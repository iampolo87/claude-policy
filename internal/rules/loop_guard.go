package rules

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/iampolo87/claude-policy/internal/config"
	"github.com/iampolo87/claude-policy/internal/hook"
	"github.com/iampolo87/claude-policy/internal/state"
)

// Session-wide state files (shared across agents in one cwd on purpose); the streak is
// per agent: st.Agent+lgStreakSuffix.
const (
	lgFails        = "loopguard.fails"
	lgPending      = "loopguard.pending"
	lgStreakSuffix = ".loopstreak"
)

var lgEditTools = []string{"Edit", "Write", "NotebookEdit"}

var (
	lgRtk = regexp.MustCompile(`^rtk\s+`)
	lgWS  = regexp.MustCompile(`\s+`)
)

type lgRec struct {
	H  string  `json:"h"`
	TS float64 `json:"ts"`
}

type loopGuard struct{}

func init() { Registry = append(Registry, loopGuard{}) }

func (loopGuard) Name() string { return "loop_guard" }
func (loopGuard) Events() []string {
	return []string{"PreToolUse", "PostToolUse", "PostToolUseFailure"}
}

// Timeout covers three Updates that may each wait 100 ms for a lock.
func (loopGuard) Timeout() time.Duration { return 500 * time.Millisecond }

func lgNorm(cmd string) string {
	return lgWS.ReplaceAllString(lgRtk.ReplaceAllString(strings.TrimSpace(cmd), ""), " ")
}

// lgHash keys a command by the hook's current cwd too, so one directory's
// failures never deny another's; an absent cwd is just "". ponytail: a `cd`
// inside the session moves the key, so a retry after cd gets fresh attempts.
func lgHash(cwd, cmd string) string {
	if cwd != "" {
		cwd = filepath.Clean(cwd)
	}
	s := sha1.Sum([]byte(cwd + "\x00" + lgNorm(cmd)))
	return hex.EncodeToString(s[:])[:12]
}

func lgCommand(in *hook.Input) string {
	var ti struct {
		Command string `json:"command"`
	}
	json.Unmarshal(in.ToolInput, &ti)
	return ti.Command
}

// lgIsFail ports the old is_fail: only a JSON object can say failure.
func lgIsFail(raw json.RawMessage) bool {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	if m["isError"] == true || m["success"] == false {
		return true
	}
	if ec, ok := m["exit_code"].(float64); ok && ec != 0 {
		return true
	}
	switch e := m["error"].(type) {
	case nil:
		return false
	case bool:
		return e
	case string:
		return e != ""
	case float64:
		return e != 0
	case []any:
		return len(e) > 0
	case map[string]any:
		return len(e) > 0
	}
	return true
}

func lgLoad[T any](b []byte) T {
	var v T
	json.Unmarshal(b, &v)
	return v
}

func (loopGuard) Apply(ctx context.Context, in *hook.Input, cfg *config.Config, st *state.Store) *hook.Decision {
	c := cfg.Rules.LoopGuard
	ttl := float64(c.TTLSeconds)
	now := float64(time.Now().UnixNano()) / 1e9
	if ctx.Err() != nil {
		return nil
	}
	switch in.HookEventName {
	case "PreToolUse":
		return lgPre(in, c, ttl, now, st)
	case "PostToolUse", "PostToolUseFailure":
	default:
		return nil
	}
	if in.HookEventName == "PostToolUseFailure" && in.IsInterrupt {
		return nil // a user interrupt is not a tool failure
	}
	failed := in.HookEventName == "PostToolUseFailure" || lgIsFail(in.ToolResponse)
	switch {
	case in.ToolName == "Bash":
		lgRecord(in, failed, ttl, now, st)
	case !failed && slices.Contains(lgEditTools, in.ToolName):
		// A file changed, so rerunning a failed command is the red-green loop,
		// not a verbatim retry. ponytail: clears every command's failures, and
		// an edit made through Bash (sed -i, a heredoc) clears nothing.
		st.Update(lgFails, func([]byte) []byte { return []byte("[]") })
	}
	var streak int
	st.Update(st.Agent+lgStreakSuffix, func(old []byte) []byte {
		streak, _ = strconv.Atoi(strings.TrimSpace(string(old)))
		if failed {
			streak++
		} else {
			streak = 0
		}
		if failed && streak >= c.StreakThreshold {
			return []byte("0") // nag every StreakThreshold, not every call after
		}
		return []byte(strconv.Itoa(streak))
	})
	if !failed || streak < c.StreakThreshold {
		return nil
	}
	return &hook.Decision{AdditionalContext: fmt.Sprintf(
		"⚠ CIRCUIT BREAKER: %d tool calls failed in a row. This pattern is an "+
			"environment/dependency problem, not something to brute-force. STOP retrying. Check: "+
			"service down (ES/DB/web)? wrong cwd/env? missing dep/build? auth expired? Verify "+
			"upstream health BEFORE the next attempt, and state WHY these failed before acting.", streak)}
}

func lgPre(in *hook.Input, c config.LoopGuard, ttl, now float64, st *state.Store) *hook.Decision {
	if in.ToolName != "Bash" {
		return nil
	}
	cmd := lgCommand(in)
	if cmd == "" {
		return nil
	}
	h := lgHash(in.Cwd, cmd)
	b, err := st.Read(lgFails)
	if err != nil {
		return nil
	}
	n := 0
	for _, r := range lgLoad[[]lgRec](b) {
		if r.H == h && r.TS >= now-ttl {
			n++
		}
	}
	if n >= c.FailThreshold {
		return &hook.Decision{Permission: "deny", Reason: fmt.Sprintf(
			"BLOCKED by loop-guard: this command already FAILED %dx this session "+
				"(normalized match). Re-running it verbatim wastes a turn. STOP and diagnose "+
				"ROOT CAUSE first: is a service down (ES/DB/web)? wrong cwd/env? missing build/dep? "+
				"auth expired? Then change the command or the approach. If you have genuinely "+
				"reassessed and must run it again, alter it (e.g. append ` # retry-after-fix`).", n)}
	}
	if in.ToolUseID != "" {
		st.Update(lgPending, func(old []byte) []byte {
			m := lgLoad[map[string]lgRec](old)
			if m == nil {
				m = map[string]lgRec{}
			}
			for k, r := range m {
				if r.TS < now-ttl {
					delete(m, k)
				}
			}
			m[in.ToolUseID] = lgRec{h, now}
			out, _ := json.Marshal(m)
			return out
		})
	}
	return nil
}

// lgRecord resolves the Bash command's hash (tool_use_id first: the Post
// command may be rtk-rewritten) and records a failure or clears its failures.
func lgRecord(in *hook.Input, failed bool, ttl, now float64, st *state.Store) {
	h := ""
	if in.ToolUseID != "" {
		st.Update(lgPending, func(old []byte) []byte {
			m := lgLoad[map[string]lgRec](old)
			r, ok := m[in.ToolUseID]
			if !ok {
				return nil
			}
			h = r.H
			delete(m, in.ToolUseID)
			out, _ := json.Marshal(m)
			return out
		})
	}
	if h == "" {
		cmd := lgCommand(in)
		if cmd == "" {
			return
		}
		h = lgHash(in.Cwd, cmd)
	}
	st.Update(lgFails, func(old []byte) []byte {
		fs := slices.DeleteFunc(lgLoad[[]lgRec](old), func(r lgRec) bool {
			return r.TS < now-ttl || (!failed && r.H == h)
		})
		if failed {
			fs = append(fs, lgRec{h, now})
		}
		out, _ := json.Marshal(fs)
		return out
	})
}
