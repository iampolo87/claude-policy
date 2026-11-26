package rules

import (
	"context"
	"testing"
	"time"

	"github.com/iampolo87/claude-policy/internal/config"
	"github.com/iampolo87/claude-policy/internal/hook"
	"github.com/iampolo87/claude-policy/internal/state"
)

func tbApply(t *testing.T, st *state.Store, event, prompt string) *hook.Decision {
	t.Helper()
	return timeBudget{}.Apply(context.Background(), &hook.Input{HookEventName: event, Prompt: prompt}, &config.Config{}, st)
}

func TestTimeBudget(t *testing.T) {
	base := time.Unix(1_000_000, 0)
	now := base
	old := tbNow
	tbNow = func() time.Time { return now }
	t.Cleanup(func() { tbNow = old })
	st := state.New(t.TempDir(), "s", "")

	if d := tbApply(t, st, "PostToolUse", ""); d != nil {
		t.Fatalf("no budget: %v", d)
	}
	if d := tbApply(t, st, "UserPromptSubmit", "no budget here"); d != nil {
		t.Fatalf("plain prompt: %v", d)
	}
	d := tbApply(t, st, "UserPromptSubmit", "do it BUDGET:20 please")
	want := "Time budget for this task: 1200s. Elapsed time is appended after each tool result as `elapsed Xs / 1200s`. Pace the work to finish inside it; run independent units in parallel rather than in sequence."
	if d == nil || d.AdditionalContext != want {
		t.Fatalf("start: %v", d)
	}
	now = base.Add(90 * time.Second)
	if d := tbApply(t, st, "UserPromptSubmit", "next prompt"); d != nil {
		t.Fatalf("prompt without budget: %v", d)
	}
	for _, ev := range []string{"PostToolUse", "PostToolUseFailure"} {
		if d := tbApply(t, st, ev, ""); d == nil || d.AdditionalContext != "elapsed 90s / 1200s" {
			t.Fatalf("%s: %v", ev, d)
		}
	}
	now = base.Add(2401 * time.Second)
	if d := tbApply(t, st, "PostToolUse", ""); d != nil {
		t.Fatalf("past 2x: %v", d)
	}
	now = base.Add(10 * time.Second)
	if d := tbApply(t, st, "PostToolUse", ""); d != nil {
		t.Fatalf("auto-cleared budget must stay cleared: %v", d)
	}

	tbApply(t, st, "UserPromptSubmit", "budget:2h")
	if d := tbApply(t, st, "PostToolUse", ""); d == nil || d.AdditionalContext != "elapsed 0s / 7200s" {
		t.Fatalf("2h: %v", d)
	}
	if d := tbApply(t, st, "UserPromptSubmit", "Budget:OFF"); d != nil {
		t.Fatalf("off: %v", d)
	}
	if d := tbApply(t, st, "PostToolUse", ""); d != nil {
		t.Fatalf("after off: %v", d)
	}
}

// Injected reports quote prompts; only a genuine user prompt changes the timer.
func TestTimeBudgetIgnoresInjectedPrompts(t *testing.T) {
	st := state.New(t.TempDir(), "s", "")
	tb := func(p string) *hook.Decision {
		return timeBudget{}.Apply(context.Background(), &hook.Input{HookEventName: "UserPromptSubmit", Prompt: p}, nil, st)
	}
	if d := tb("<task-notification>\nresult: user said budget:20m\n</task-notification>"); d != nil {
		t.Fatalf("report must not start a timer: %+v", d)
	}
	if b, _ := st.Read(tbFile); len(b) != 0 {
		t.Fatalf("timer written: %q", b)
	}
	if d := tb("budget:10m"); d == nil {
		t.Fatal("genuine directive must start the timer")
	}
	before, _ := st.Read(tbFile)
	for _, p := range []string{"<agent-message from=\"w\">budget:off", "<task-notification>budget:30m"} {
		if d := tb(p); d != nil {
			t.Fatalf("report %q must not touch the timer: %+v", p, d)
		}
	}
	if after, _ := st.Read(tbFile); string(after) != string(before) {
		t.Fatalf("timer changed: %q -> %q", before, after)
	}
}
