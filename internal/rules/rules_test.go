package rules

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iampolo87/claude-policy/internal/config"
	"github.com/iampolo87/claude-policy/internal/hook"
	"github.com/iampolo87/claude-policy/internal/state"
)

type fake struct {
	name    string
	events  []string
	tools   []string
	d       *hook.Decision
	panics  bool
	sleep   time.Duration
	timeout time.Duration
	called  *bool
}

func (f fake) Name() string           { return f.name }
func (f fake) Events() []string       { return f.events }
func (f fake) Tools() []string        { return f.tools }
func (f fake) Timeout() time.Duration { return f.timeout }
func (f fake) Apply(context.Context, *hook.Input, *config.Config, *state.Store) *hook.Decision {
	if f.called != nil {
		*f.called = true
	}
	if f.panics {
		panic("boom")
	}
	time.Sleep(f.sleep)
	return f.d
}

var pre = []string{"PreToolUse"}

func setup(t *testing.T, mode string) (*config.Config, *hook.Input, *state.Store) {
	t.Helper()
	cfg := suiteCfg()
	cfg.Global.Mode = mode
	in := &hook.Input{HookEventName: "PreToolUse", ToolName: "Agent", SessionID: "s"}
	return cfg, in, state.New(t.TempDir(), "s", "")
}

func out(t *testing.T, o hook.Output) string {
	t.Helper()
	b, _ := json.Marshal(o)
	return string(b)
}

func logLines(t *testing.T, st *state.Store) []map[string]any {
	t.Helper()
	b, _ := os.ReadFile(filepath.Join(st.Root, "decisions.jsonl"))
	var ls []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatal(err)
		}
		ls = append(ls, m)
	}
	return ls
}

const askJSON = `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"r"}}`

// Every registered rule needs a unique name with its own [rules.<name>] mode,
// else cfg.Mode silently falls back to [global].
func TestRegistryNames(t *testing.T) {
	cfg := suiteCfg()
	cfg.Global.Mode = "unset"
	seen := map[string]bool{}
	for _, r := range Registry {
		if seen[r.Name()] || cfg.Mode(r.Name()) == "unset" {
			t.Errorf("rule %q: duplicate or missing from config", r.Name())
		}
		seen[r.Name()] = true
	}
}

func TestFilterByEventAndTool(t *testing.T) {
	cfg, in, st := setup(t, "enforce")
	var stopCalled, bashCalled bool
	rs := []Rule{
		fake{name: "x", events: []string{"Stop"}, called: &stopCalled},
		fake{name: "y", events: pre, tools: []string{"Bash"}, called: &bashCalled},
		fake{name: "z", events: pre, tools: []string{"Agent", "Task"}, d: &hook.Decision{Permission: "ask", Reason: "r"}},
	}
	if got := out(t, Run(context.Background(), rs, cfg, in, st)); got != askJSON {
		t.Fatalf("got %s", got)
	}
	if stopCalled || bashCalled {
		t.Fatal("rules for other events/tools must not run")
	}
}

func TestModes(t *testing.T) {
	d := &hook.Decision{Permission: "ask", Reason: "r"}

	cfg, in, st := setup(t, "off")
	var called bool
	if got := out(t, Run(context.Background(), []Rule{fake{name: "x", events: pre, d: d, called: &called}}, cfg, in, st)); got != "{}" || called {
		t.Fatalf("off: got %s called=%v", got, called)
	}

	cfg, in, st = setup(t, "log")
	if got := out(t, Run(context.Background(), []Rule{fake{name: "x", events: pre, d: d}}, cfg, in, st)); got != "{}" {
		t.Fatalf("log: got %s", got)
	}
	ls := logLines(t, st)
	if len(ls) != 1 || ls[0]["rule"] != "x" || ls[0]["mode"] != "log" || ls[0]["event"] != "PreToolUse" || ls[0]["decision"].(map[string]any)["permission"] != "ask" {
		t.Fatalf("log: jsonl %v", ls)
	}

	cfg, in, st = setup(t, "log")
	hard := &hook.Decision{Permission: "deny", Reason: "hard", Hard: true}
	if got := out(t, Run(context.Background(), []Rule{fake{name: "x", events: pre, d: hard}}, cfg, in, st)); !strings.Contains(got, `"permissionDecision":"deny"`) {
		t.Fatalf("hard decision must apply in log mode: %s", got)
	}

	cfg, in, st = setup(t, "log")
	cfg.Rules.LoopGuard.Mode = "enforce" // per-rule mode beats [global]
	if got := out(t, Run(context.Background(), []Rule{fake{name: "loop_guard", events: pre, d: d}}, cfg, in, st)); got != askJSON {
		t.Fatalf("enforce: got %s", got)
	}
	if ls := logLines(t, st); len(ls) != 1 || ls[0]["mode"] != "enforce" {
		t.Fatalf("enforce: jsonl %v", ls)
	}
}

func TestPanicAndSlowRulesFailOpen(t *testing.T) {
	cfg, in, st := setup(t, "enforce")
	rs := []Rule{
		fake{name: "panics", events: pre, panics: true, d: &hook.Decision{Permission: "deny"}},
		fake{name: "slow", events: pre, sleep: 2 * time.Second, d: &hook.Decision{Permission: "deny"}},
		fake{name: "slow_custom", events: pre, sleep: time.Second, timeout: 20 * time.Millisecond, d: &hook.Decision{Permission: "deny"}},
		fake{name: "ok", events: pre, d: &hook.Decision{Permission: "ask", Reason: "r"}},
	}
	start := time.Now()
	got := out(t, Run(context.Background(), rs, cfg, in, st))
	el := time.Since(start)
	if got != askJSON {
		t.Fatalf("failing rules must be no opinion: %s", got)
	}
	if el < DefaultTimeout || el > DefaultTimeout+300*time.Millisecond {
		t.Fatalf("took %v, want ~%v", el, DefaultTimeout+20*time.Millisecond)
	}
	errs := map[string]bool{}
	for _, l := range logLines(t, st) {
		if e, _ := l["error"].(string); e != "" {
			errs[l["rule"].(string)] = true
		}
	}
	if !errs["panics"] || !errs["slow"] || !errs["slow_custom"] || len(errs) != 3 {
		t.Fatalf("errors must be logged per failing rule: %v", errs)
	}
}

// every runner line carries ms, the wall time of that rule's Apply.
func TestRunLogsMS(t *testing.T) {
	cfg, in, st := setup(t, "log")
	rs := []Rule{
		fake{name: "slow", events: pre, d: &hook.Decision{Permission: "ask", Reason: "r"}, sleep: 30 * time.Millisecond},
		fake{name: "fast", events: pre, d: &hook.Decision{Permission: "ask", Reason: "r"}},
		fake{name: "late", events: pre, sleep: time.Second, timeout: 20 * time.Millisecond},
	}
	Run(context.Background(), rs, cfg, in, st)
	ls := logLines(t, st)
	if len(ls) != 3 {
		t.Fatalf("lines %v", ls)
	}
	for i, min := range []float64{30, 0, 20} {
		ms, ok := ls[i]["ms"].(float64)
		if !ok || ms < min || ms > min+500 {
			t.Fatalf("%v: ms=%v, want >=%v", ls[i]["rule"], ls[i]["ms"], min)
		}
		if us, ok := ls[i]["us"].(float64); !ok || us < ms*1000 || us >= (ms+1)*1000 {
			t.Fatalf("%v: us=%v vs ms=%v", ls[i]["rule"], ls[i]["us"], ms)
		}
	}
}

func TestRunStats(t *testing.T) {
	cfg, in, st := setup(t, "enforce")
	cfg.Rules.Lint.Mode = "log" // modes are per rule name
	cfg.Rules.LoopGuard.Mode = "off"
	d := func(x hook.Decision) *hook.Decision { return &x }
	raw := json.RawMessage(`"x"`)
	cases := []struct {
		name string
		f    fake
		want string
	}{
		{"nil", fake{d: nil}, "none"},
		{"deny", fake{d: d(hook.Decision{Permission: "deny"})}, "deny"},
		{"ask", fake{d: d(hook.Decision{Permission: "ask", AdditionalContext: "c"})}, "ask"},
		{"block", fake{d: d(hook.Decision{Block: true, AdditionalContext: "c"})}, "block"},
		{"output", fake{d: d(hook.Decision{UpdatedToolOutput: raw, AdditionalContext: "c"})}, "output"},
		{"input", fake{d: d(hook.Decision{UpdatedInput: raw, AdditionalContext: "c"})}, "input"},
		{"context", fake{d: d(hook.Decision{AdditionalContext: "c"})}, "context"},
		{"bare", fake{d: d(hook.Decision{Reason: "r"})}, "decision"},
		{"panic", fake{panics: true}, "error"},
		{"deadline", fake{sleep: 100 * time.Millisecond, timeout: 5 * time.Millisecond}, "error"},
	}
	var rs []Rule
	for _, c := range cases {
		c.f.name, c.f.events = c.name, pre
		rs = append(rs, c.f)
	}
	// log-mode rule (lint) reports its verdict; off rule (loop_guard) is absent; wrong event is absent
	rs = append(rs, fake{name: "lint", events: pre, d: d(hook.Decision{Permission: "deny"})},
		fake{name: "loop_guard", events: pre}, fake{name: "stopper", events: []string{"Stop"}})
	cfg.Rules.Lint.Mode = "log"
	_, stats := RunStats(context.Background(), rs, cfg, in, st)
	if len(stats) != len(cases)+1 {
		t.Fatalf("stats: %+v", stats)
	}
	for i, c := range cases {
		if stats[i].Name != c.name || stats[i].Verdict != c.want {
			t.Errorf("%s: got %+v", c.name, stats[i])
		}
	}
	if l := stats[len(cases)]; l.Name != "lint" || l.Verdict != "deny" || l.Mode != "log" || stats[0].Mode != "enforce" {
		t.Errorf("log-mode: %+v", l)
	}
	if s := stats[len(cases)-1]; s.MS < 4 || s.US < 4000 {
		t.Errorf("deadline ms: %+v", stats[len(cases)-1])
	}
	if _, s := RunStats(context.Background(), nil, cfg, in, st); s == nil || len(s) != 0 {
		t.Errorf("no rules ran must be empty non-nil slice, got %#v", s)
	}
}

// In-rule lines (edit_surfaces fail-open) carry no timing: zeros would skew the stats.
func TestInRuleLineHasNoTiming(t *testing.T) {
	cfg, in, st := setup(t, "log")
	in.AgentID, in.ToolName, in.ToolInput, in.AgentTranscriptPath = "a1", "Write", json.RawMessage(`{"file_path":"/x/y.go"}`), "/nonexistent/brief.jsonl"
	Run(context.Background(), []Rule{editSurfaces{}}, cfg, in, st)
	ls := logLines(t, st)
	if len(ls) == 0 {
		t.Fatal("no line")
	}
	for _, l := range ls {
		if _, ok := l["ms"]; ok && l["error"] != nil {
			t.Fatalf("in-rule line has timing: %v", l)
		}
	}
}
