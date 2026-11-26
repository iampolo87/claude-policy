package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/iampolo87/claude-policy/internal/config"
	"github.com/iampolo87/claude-policy/internal/hook"
	"github.com/iampolo87/claude-policy/internal/state"
)

// riskLine records files edited this turn (PostToolUse, any agent) and
// reminds the main agent once per turn: at its first edit, or when a worker
// hands back delegated edits (Agent/Task result or task notification). A Stop
// without a `Risk:` line is only logged (reason-only decision, emits {}), so
// formatting never costs another call. The set is session-wide and cleared on
// every main Stop and genuine new prompt. ponytail: edits made through Bash
// (sed -i, redirects) are not tracked; a background worker's edits made
// before a new user prompt are dropped from its later handback.
type riskLine struct{}

func init() { Registry = append(Registry, riskLine{}) }

const (
	rlFile     = "risk_line.edits"
	rlReminded = "risk_line.reminded"
)

func (riskLine) Name() string     { return "risk_line" }
func (riskLine) Events() []string { return []string{"UserPromptSubmit", "PostToolUse", "Stop"} }

// No Tools(): the runner would filter Stop (empty tool_name) out too.
var rlTools = []string{"Edit", "Write", "MultiEdit", "NotebookEdit"}

func rlUnder(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, dir+string(filepath.Separator))
}

func rlMatch(globs []string, p string) bool {
	return slices.ContainsFunc(globs, func(g string) bool {
		ok, _ := doublestar.Match(g, p)
		return ok
	})
}

func (riskLine) Apply(ctx context.Context, in *hook.Input, cfg *config.Config, st *state.Store) *hook.Decision {
	if ctx.Err() != nil {
		return nil
	}
	rc := cfg.Rules.RiskLine
	if in.HookEventName == "UserPromptSubmit" {
		// An interrupted turn has no Stop; reset here so it cannot leak.
		if !promptInjected(in.Prompt) {
			rlReset(st)
			return nil
		}
		return rlHandback(st, rc.Reminder)
	}
	if in.HookEventName == "PostToolUse" {
		if in.ToolName == "Agent" || in.ToolName == "Task" {
			if in.AgentID != "" {
				return nil
			}
			return rlHandback(st, rc.Reminder)
		}
		if !slices.Contains(rlTools, in.ToolName) {
			return nil
		}
		var ti struct {
			FilePath     string `json:"file_path"`
			NotebookPath string `json:"notebook_path"`
		}
		if json.Unmarshal(in.ToolInput, &ti) != nil {
			return nil
		}
		p := ti.FilePath
		if p == "" {
			p = ti.NotebookPath
		}
		if p == "" {
			return nil
		}
		if !filepath.IsAbs(p) {
			p = filepath.Join(in.Cwd, p)
		}
		p = filepath.Clean(p)
		home, _ := os.UserHomeDir()
		for _, s := range rc.Skip {
			switch {
			case strings.HasPrefix(s, "$scratchpad_dir"):
				if in.ScratchpadDir == "" {
					continue
				}
				s = in.ScratchpadDir + strings.TrimPrefix(s, "$scratchpad_dir")
			case s == "~" || strings.HasPrefix(s, "~/"):
				if home == "" {
					continue
				}
				s = home + s[1:]
			}
			if rlUnder(p, filepath.Clean(s)) {
				return nil
			}
		}
		if rlMatch(rc.Docs, p) && !rlMatch(rc.DocsExcept, p) {
			return nil
		}
		st.Update(rlFile, func(old []byte) []byte {
			if slices.Contains(strings.Split(string(old), "\n"), p) {
				return old
			}
			return append(old, p+"\n"...)
		})
		if in.AgentID != "" {
			return nil
		}
		return rlRemind(st, rc.Reminder)
	}

	// Stop: main agent only; always consume the set and re-arm the reminder.
	if in.AgentID != "" {
		return nil
	}
	files := rlReset(st)
	if len(files) == 1 && files[0] == "" {
		files = nil
	}
	if in.StopHookActive || len(files) == 0 || in.LastAssistantMessage == "" {
		return nil
	}
	re, err := regexp.Compile(rc.Pattern)
	if err != nil || re.MatchString(in.LastAssistantMessage) {
		return nil
	}
	list := strings.Join(files[:min(5, len(files))], ", ")
	if len(files) > 5 {
		list += ", …"
	}
	return &hook.Decision{Reason: fmt.Sprintf("risk_line: this turn edited %d file(s) (%s) but the final message has no Risk line.", len(files), list)}
}

// rlHandback reminds the main agent when a worker returns with edits recorded.
func rlHandback(st *state.Store, reminder string) *hook.Decision {
	if b, _ := st.Read(rlFile); len(b) == 0 {
		return nil
	}
	return rlRemind(st, reminder)
}

// rlRemind returns the reminder the first time it is called in a turn.
func rlRemind(st *state.Store, reminder string) *hook.Decision {
	if reminder == "" {
		return nil
	}
	first := false
	st.Update(rlReminded, func(old []byte) []byte {
		first = len(old) == 0
		return []byte("1")
	})
	if !first {
		return nil
	}
	return &hook.Decision{AdditionalContext: reminder}
}

// rlReset clears the turn's state and returns the edited files it held.
func rlReset(st *state.Store) []string {
	st.Write(rlReminded, nil)
	var files []string
	st.Update(rlFile, func(old []byte) []byte {
		files = strings.Split(strings.TrimSpace(string(old)), "\n")
		return []byte{}
	})
	return files
}
