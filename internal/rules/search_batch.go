package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/iampolo87/claude-policy/internal/config"
	"github.com/iampolo87/claude-policy/internal/hook"
	"github.com/iampolo87/claude-policy/internal/shell"
	"github.com/iampolo87/claude-policy/internal/state"
)

// searchBatch nudges (context only, never a deny or rewrite) an agent that
// sends read-only lookups one per message: each message re-reads the whole
// context, so lookups sent together cost one round trip instead of several.
// The streak is per agent and counts messages that carry exactly one
// single-lookup call; any other work, a batched message or a new user prompt
// resets it, and the nudge repeats every Threshold.
//
// A hook sees calls, not messages, so calls are grouped by timing: a Pre
// belongs to the running message when the previous event was a Pre (parallel
// calls) or ended under sbGap ago (the next serial call; an API round trip
// takes longer). ponytail: a serial batch's first call still counts until its
// second call shows up, so a batch sent right at Threshold-1 gets one stray
// nudge; a denied call (no Post) merges the next message into its own.
type searchBatch struct{}

func init() { Registry = append(Registry, searchBatch{}) }

func (searchBatch) Name() string { return "search_batch" }
func (searchBatch) Events() []string {
	return []string{"UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolUseFailure"}
}

const (
	sbSuffix = ".searchbatch"
	// sbGap: live metrics put same-message calls under 0.25 s apart and
	// separate messages over 1 s (under 1 % fell between).
	sbGap = 1.0
)

// What one finished call was, for the streak.
const (
	sbOther = iota // not a read-only lookup
	sbSolo1        // one lookup
	sbBatch        // one Bash command holding several lookups
)

var sbNow = func() float64 { return float64(time.Now().UnixNano()) / 1e9 }

type sbState struct {
	Streak int     `json:"streak"`
	Calls  int     `json:"calls"` // calls seen in the running message
	Last   float64 `json:"last"`  // time of the agent's last tool event
	Pre    bool    `json:"pre"`   // that event was a PreToolUse
}

func (searchBatch) Apply(ctx context.Context, in *hook.Input, cfg *config.Config, st *state.Store) *hook.Decision {
	if ctx.Err() != nil {
		return nil
	}
	if in.HookEventName == "UserPromptSubmit" {
		if in.AgentID == "" && !promptInjected(in.Prompt) {
			st.Write(st.Agent+sbSuffix, nil)
		}
		return nil
	}
	pre := in.HookEventName == "PreToolUse"
	kind := sbOther
	if !pre && !in.IsInterrupt {
		kind = sbKind(in)
	}
	n, now, fire := cfg.Rules.SearchBatch.Threshold, sbNow(), false
	st.Update(st.Agent+sbSuffix, func(old []byte) []byte {
		s := lgLoad[sbState](old)
		switch {
		case pre:
			if !s.Pre && now-s.Last > sbGap {
				s.Calls = 0
			}
			if s.Calls++; s.Calls > 1 {
				s.Streak = 0
			}
		case s.Calls > 1 || kind != sbSolo1:
			s.Streak = 0
		default:
			if s.Streak++; s.Streak >= n {
				s.Streak, fire = 0, true
			}
		}
		s.Pre, s.Last = pre, now
		out, _ := json.Marshal(s)
		return out
	})
	if !fire {
		return nil
	}
	return &hook.Decision{AdditionalContext: fmt.Sprintf("search_batch: %d read-only lookups in a row, one per message, "+
		"and each message re-reads the whole context. Send the next independent lookups together: several tool calls "+
		"in one message, or one Bash command with `;` between them.", n)}
}

var (
	// sbNeutral commands are read-only but look nothing up.
	sbNeutral = setOf("cd", "echo", "printf", "true", "test", "[", "pwd")
	// ponytail: awk and sort can write a file (`print > f`, `-o f`); not modelled.
	sbReadOnly = setOf("grep", "egrep", "fgrep", "rg", "ugrep", "ag", "cat", "head", "tail", "ls", "wc", "cut", "sort",
		"uniq", "tr", "nl", "column", "jq", "tree", "stat", "file", "du", "diff", "less", "bat", "fd", "awk",
		"read", // rtk read
		"cd", "echo", "printf", "true", "test", "[", "pwd")
	sbGit = setOf("log", "show", "diff", "status", "blame", "grep", "ls-files", "ls-tree", "cat-file", "rev-parse",
		"describe", "shortlog", "merge-base", "rev-list")
	sbGitValue = setOf("-C", "-c", "--git-dir", "--work-tree")
	sbFindRun  = setOf("-exec", "-execdir", "-ok", "-okdir")
	sbFindOut  = setOf("-delete", "-fprint", "-fprint0", "-fprintf", "-fls")
)

// sbKind classifies a finished call. Anything it cannot read as a plain
// read-only command is sbOther, which only ever silences the nudge.
func sbKind(in *hook.Input) int {
	switch in.ToolName {
	case "Read", "Grep", "Glob":
		return sbSolo1
	case "Bash":
	default:
		return sbOther
	}
	cmd := lgCommand(in)
	if shell.Opaque(cmd) || strings.Contains(cmd, "`") || strings.Contains(cmd, "$(") ||
		strings.Contains(cmd, "<(") || strings.Contains(cmd, ">(") {
		return sbOther
	}
	lookups, stage := 0, 0 // stage: position in the running pipeline
	for _, s := range shell.Segments(cmd) {
		first := stage == 0
		if s.Separator == "|" || s.Separator == "|&" {
			stage++
		} else {
			stage = 0
		}
		if len(s.Tokens) == 0 {
			continue
		}
		name, args := s.Name(), s.Args()
		if name == "rtk" && len(args) > 0 {
			name, args = args[0], args[1:]
		}
		if sbWrites(s.Tokens) || !sbReads(name, args) {
			return sbOther
		}
		if first && !sbNeutral[name] {
			lookups++
		}
	}
	switch lookups {
	case 0:
		return sbOther
	case 1:
		return sbSolo1
	}
	return sbBatch
}

// sbWrites reports an output redirection to anything but /dev/null or an fd.
func sbWrites(toks []shell.Token) bool {
	for i, t := range toks {
		if !t.Redirect || !strings.Contains(t.Value, ">") {
			continue
		}
		target := ""
		if i+1 < len(toks) {
			target = toks[i+1].Value
		}
		fd := target != "" && strings.Trim(target, "0123456789-") == ""
		if target != "/dev/null" && !(strings.HasSuffix(t.Value, ">&") && fd) {
			return true
		}
	}
	return false
}

func sbReads(name string, args []string) bool {
	switch name {
	case "git":
		i := 0
		for i < len(args) && strings.HasPrefix(args[i], "-") {
			if sbGitValue[args[i]] {
				i++
			}
			i++
		}
		return i < len(args) && sbGit[args[i]]
	case "sed":
		for _, a := range args {
			if strings.HasPrefix(a, "--in-place") || strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.Contains(a, "i") {
				return false
			}
		}
		return true
	case "find":
		for i, a := range args {
			if sbFindOut[a] {
				return false
			}
			if sbFindRun[a] && (i+1 >= len(args) || !sbReadOnly[shell.Executable(args[i+1])] || sbNeutral[shell.Executable(args[i+1])]) {
				return false
			}
		}
		return true
	}
	return sbReadOnly[name]
}
