package rules

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/iampolo87/claude-policy/internal/hook"
	"github.com/iampolo87/claude-policy/internal/state"
)

func rlEdit(tool, path, agent string) *hook.Input {
	ti, _ := json.Marshal(map[string]string{"file_path": path})
	return &hook.Input{HookEventName: "PostToolUse", ToolName: tool, ToolInput: ti, SessionID: "s", AgentID: agent,
		Cwd: "/proj", ScratchpadDir: "/tmp/scratch"}
}

func rlStop(msg string, active bool, agent string) *hook.Input {
	return &hook.Input{HookEventName: "Stop", SessionID: "s", AgentID: agent, LastAssistantMessage: msg, StopHookActive: active}
}

func rlApply(in *hook.Input, st *state.Store) *hook.Decision {
	return riskLine{}.Apply(context.Background(), in, suiteCfg(), st)
}

// rlFlagged: advisory miss, logged with a reason, never a block.
func rlFlagged(d *hook.Decision) bool { return d != nil && !d.Block && d.Reason != "" }

func TestRiskLineFlagsOnceThenPasses(t *testing.T) {
	st := state.New(t.TempDir(), "s", "")
	rlApply(rlEdit("Edit", "/proj/a.go", ""), st)
	rlApply(rlEdit("Write", "b.go", ""), st) // relative -> cwd
	rlApply(rlEdit("Edit", "/proj/a.go", ""), st)
	d := rlApply(rlStop("Done. Risk: none", false, ""), st) // not at line start
	if !rlFlagged(d) || !strings.Contains(d.Reason, "2 file(s)") || !strings.Contains(d.Reason, "/proj/a.go") || !strings.Contains(d.Reason, "/proj/b.go") {
		t.Fatalf("want reason-only decision naming files, got %+v", d)
	}
	if d := rlApply(rlStop("again", true, ""), st); d != nil {
		t.Fatalf("stop_hook_active must pass: %+v", d)
	}
	if d := rlApply(rlStop("no edits since", false, ""), st); d != nil {
		t.Fatalf("set must be consumed: %+v", d)
	}
}

func TestRiskLineRiskPresentClearsSet(t *testing.T) {
	st := state.New(t.TempDir(), "s", "")
	rlApply(rlEdit("MultiEdit", "/proj/a.go", ""), st)
	if d := rlApply(rlStop("ok\nRisk: item 3 (x)", false, ""), st); d != nil {
		t.Fatalf("got %+v", d)
	}
	if b, _ := st.Read(rlFile); len(b) != 0 {
		t.Fatalf("set not cleared: %q", b)
	}
	rlApply(rlEdit("Edit", "/proj/a.go", ""), st)
	if d := rlApply(rlStop("", false, ""), st); d != nil { // empty message fails open
		t.Fatalf("got %+v", d)
	}
}

// The first main-agent code edit of a turn reminds once, so the Risk line is
// written with the summary instead of after a Stop block.
func TestRiskLineRemindsOncePerTurn(t *testing.T) {
	st := state.New(t.TempDir(), "s", "")
	if d := rlApply(rlEdit("Edit", "/proj/sub.go", "agent1"), st); d != nil {
		t.Fatalf("subagent edit must not remind: %+v", d)
	}
	if d := rlApply(rlEdit("Edit", "/tmp/scratch/x.md", ""), st); d != nil {
		t.Fatalf("skipped path must not remind: %+v", d)
	}
	d := rlApply(rlEdit("Edit", "/proj/a.go", ""), st)
	if d == nil || d.Block || !strings.Contains(d.AdditionalContext, "Risk: none") {
		t.Fatalf("first main edit must remind: %+v", d)
	}
	if d := rlApply(rlEdit("Write", "/proj/b.go", ""), st); d != nil {
		t.Fatalf("second edit must not remind: %+v", d)
	}
	rlApply(rlStop("ok\nRisk: none", false, ""), st)
	if d := rlApply(rlEdit("Edit", "/proj/a.go", ""), st); d == nil || d.AdditionalContext == "" {
		t.Fatalf("Stop must re-arm the reminder: %+v", d)
	}
}

func rlPrompt(p string) *hook.Input {
	return &hook.Input{HookEventName: "UserPromptSubmit", SessionID: "s", Prompt: p}
}

// An interrupted turn has no Stop: a genuine new prompt resets edits and
// reminder; injected reports do not.
func TestRiskLineNewPromptResetsTurn(t *testing.T) {
	st := state.New(t.TempDir(), "s", "")
	rlApply(rlEdit("Edit", "/proj/a.go", ""), st) // reminded, then interrupted
	for _, p := range []string{"<task-notification>\n<task-id>x</task-id>", "  <agent-message from=\"w\">done"} {
		rlApply(rlPrompt(p), st)
		if d := rlApply(rlEdit("Edit", "/proj/b.go", ""), st); d != nil {
			t.Fatalf("injected prompt %q must not reset: %+v", p, d)
		}
	}
	rlApply(rlPrompt("next task"), st)
	if b, _ := st.Read(rlFile); len(b) != 0 {
		t.Fatalf("edits not cleared: %q", b)
	}
	if d := rlApply(rlStop("answer", false, ""), st); d != nil {
		t.Fatalf("new turn must inherit no edits: %+v", d)
	}
	if d := rlApply(rlEdit("Edit", "/proj/c.go", ""), st); d == nil || d.AdditionalContext == "" {
		t.Fatalf("new prompt must re-arm the reminder: %+v", d)
	}
}

// Delegated-only edits remind the main agent once, when the worker hands back.
func TestRiskLineDelegatedReminder(t *testing.T) {
	st := state.New(t.TempDir(), "s", "")
	done := &hook.Input{HookEventName: "PostToolUse", ToolName: "Agent", SessionID: "s"}
	if d := rlApply(done, st); d != nil {
		t.Fatalf("no edits, no reminder: %+v", d)
	}
	rlApply(rlEdit("Edit", "/proj/sub.go", "agent1"), st)
	if d := rlApply(&hook.Input{HookEventName: "PostToolUse", ToolName: "Agent", SessionID: "s", AgentID: "agent1"}, st); d != nil {
		t.Fatalf("nested completion inside a worker must not remind: %+v", d)
	}
	if d := rlApply(&hook.Input{HookEventName: "PostToolUse", ToolName: "Bash", SessionID: "s"}, st); d != nil {
		t.Fatalf("unrelated tool must not remind: %+v", d)
	}
	if d := rlApply(done, st); d == nil || !strings.Contains(d.AdditionalContext, "Risk: none") {
		t.Fatalf("handback must remind: %+v", d)
	}
	if d := rlApply(&hook.Input{HookEventName: "PostToolUse", ToolName: "Task", SessionID: "s"}, st); d != nil {
		t.Fatalf("second handback must not remind: %+v", d)
	}

	// Background workers hand back through a task notification instead.
	st = state.New(t.TempDir(), "s", "")
	note := rlPrompt("<task-notification>\n<status>completed</status>")
	if d := rlApply(note, st); d != nil {
		t.Fatalf("notification without edits must not remind: %+v", d)
	}
	rlApply(rlEdit("Edit", "/proj/sub.go", "agent1"), st)
	if d := rlApply(note, st); d == nil || !strings.Contains(d.AdditionalContext, "Risk: none") {
		t.Fatalf("notification after delegated edits must remind: %+v", d)
	}
	if d := rlApply(note, st); d != nil {
		t.Fatalf("second notification must not remind: %+v", d)
	}
}

// Enforce mode: the miss reaches the audit log but the hook emits {}, so
// Stop never forces another assistant call.
func TestRiskLineEnforceIsAdvisory(t *testing.T) {
	cfg := suiteCfg()
	cfg.Rules.RiskLine.Mode = "enforce"
	st := state.New(t.TempDir(), "s", "")
	rs := []Rule{riskLine{}}
	ctx := context.Background()
	if got := out(t, Run(ctx, rs, cfg, rlEdit("Edit", "/proj/a.go", ""), st)); !strings.Contains(got, "Risk: none") {
		t.Fatalf("enforce must emit the reminder: %s", got)
	}
	if got := out(t, Run(ctx, rs, cfg, rlStop("x", false, ""), st)); got != "{}" {
		t.Fatalf("Stop must emit {}: %s", got)
	}
	if ls := logLines(t, st); len(ls) != 2 || ls[1]["event"] != "Stop" || ls[1]["mode"] != "enforce" {
		t.Fatalf("jsonl %v", ls)
	}
}

func TestRiskLineSkipsAndAgents(t *testing.T) {
	st := state.New(t.TempDir(), "s", "")
	rlApply(rlEdit("Edit", "/tmp/scratch/x.md", ""), st)
	rlApply(rlEdit("Read", "/proj/r.go", ""), st)
	if d := rlApply(rlStop("x", false, ""), st); d != nil {
		t.Fatalf("scratchpad/non-edit tools must not count: %+v", d)
	}

	rlApply(rlEdit("Edit", "/proj/sub.go", "agent1"), st) // delegated edit counts
	if d := rlApply(rlStop("x", false, "agent1"), st); d != nil {
		t.Fatalf("subagent Stop ignored: %+v", d)
	}
	if d := rlApply(rlStop("x", false, ""), st); !rlFlagged(d) || !strings.Contains(d.Reason, "/proj/sub.go") {
		t.Fatalf("subagent edit must count for main Stop: %+v", d)
	}
}

func TestRiskLineLogMode(t *testing.T) {
	cfg := suiteCfg() // risk_line defaults to log
	st := state.New(t.TempDir(), "s", "")
	rs := []Rule{riskLine{}}
	ctx := context.Background()
	if got := out(t, Run(ctx, rs, cfg, rlEdit("Edit", "/proj/a.go", ""), st)); got != "{}" {
		t.Fatalf("log mode must not emit the reminder: %s", got)
	}
	if got := out(t, Run(ctx, rs, cfg, rlStop("x", false, ""), st)); got != "{}" {
		t.Fatalf("log mode must emit {}: %s", got)
	}
	if ls := logLines(t, st); len(ls) != 2 || ls[1]["rule"] != "risk_line" || ls[1]["mode"] != "log" || ls[1]["event"] != "Stop" {
		t.Fatalf("jsonl %v", ls)
	}
	Run(ctx, rs, cfg, rlStop("x", false, ""), st)
	if ls := logLines(t, st); len(ls) != 2 {
		t.Fatalf("second Stop must not log: %v", ls)
	}
}

// The Risk line is for code changes: a docs-only turn passes,
// a turn mixing docs and code is still flagged.
func TestRiskLineDocsOnly(t *testing.T) {
	st := state.New(t.TempDir(), "s", "")
	rlApply(rlEdit("Write", "/proj/PLAN.md", ""), st)
	rlApply(rlEdit("Edit", "/proj/docs/briefs/b.txt", ""), st)
	if d := rlApply(rlStop("x", false, ""), st); d != nil {
		t.Fatalf("docs-only turn must pass: %+v", d)
	}
	rlApply(rlEdit("Edit", "/proj/README.md", ""), st)
	rlApply(rlEdit("Edit", "/proj/a.vcl", ""), st)
	if d := rlApply(rlStop("x", false, ""), st); d == nil || !strings.Contains(d.Reason, "1 file(s) (/proj/a.vcl)") {
		t.Fatalf("code edit must be flagged and list only code files: %+v", d)
	}
}

// Agent instructions and build/crawler config are .md/.txt but no prose:
// they still need a Risk line.
func TestRiskLineDocsExcept(t *testing.T) {
	for _, p := range []string{"/proj/CLAUDE.md", "/proj/sub/AGENTS.md", "/h/.claude/skills/x/SKILL.md", "/h/.claude/rules/core.md",
		"/h/.claude/agents/reviewer.md", "/proj/requirements-dev.txt", "/proj/CMakeLists.txt", "/proj/pub/robots.txt",
		"/proj/CLAUDE.local.md", "/proj/requirements/base.txt", "/h/.claude/output-styles/x.md", "/proj/.github/copilot-instructions.md",
		"/proj/.github/instructions/go.instructions.md", "/proj/GEMINI.md", "/proj/.cursor/rules/x.md"} {
		st := state.New(t.TempDir(), "s", "")
		rlApply(rlEdit("Edit", p, ""), st)
		if d := rlApply(rlStop("x", false, ""), st); !rlFlagged(d) {
			t.Errorf("%s must still need a Risk line: %+v", p, d)
		}
	}
}
