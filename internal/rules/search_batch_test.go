package rules

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/iampolo87/claude-policy/internal/hook"
	"github.com/iampolo87/claude-policy/internal/state"
)

// sbClock replaces the rule's clock for one test and returns the handle that
// moves it.
func sbClock(t *testing.T) *float64 {
	t.Helper()
	now := 1000.0
	old := sbNow
	sbNow = func() float64 { return now }
	t.Cleanup(func() { sbNow = old })
	return &now
}

func sbIn(event, tool, cmd string) *hook.Input {
	ti, _ := json.Marshal(map[string]string{"command": cmd})
	return &hook.Input{HookEventName: event, ToolName: tool, ToolInput: ti}
}

func sbApply(st *state.Store, in *hook.Input) *hook.Decision {
	return searchBatch{}.Apply(context.Background(), in, suiteCfg(), st)
}

// sbCall is one message carrying one tool call: an API round trip, then the
// call's Pre and Post. It returns what the Post decided.
func sbCall(st *state.Store, now *float64, tool, cmd string) *hook.Decision {
	*now += 3
	if d := sbApply(st, sbIn("PreToolUse", tool, cmd)); d != nil {
		return d
	}
	*now += 0.2
	return sbApply(st, sbIn("PostToolUse", tool, cmd))
}

func sbSolo(t *testing.T, st *state.Store, now *float64, n int) {
	t.Helper()
	for i := range n {
		if d := sbCall(st, now, "Bash", "grep -rn foo src"); d != nil {
			t.Fatalf("solo lookup %d: unexpected %+v", i+1, d)
		}
	}
}

func sbWantNudge(t *testing.T, d *hook.Decision) {
	t.Helper()
	if d == nil || !strings.Contains(d.AdditionalContext, "search_batch: 4 read-only lookups in a row") {
		t.Fatalf("want the nudge, got %+v", d)
	}
	if d.Permission != "" || d.Block || d.Reason != "" || d.UpdatedInput != nil || d.UpdatedToolOutput != nil {
		t.Fatalf("the nudge must be context only, got %+v", d)
	}
}

func TestSearchBatchNudgesOnFourthSoloLookup(t *testing.T) {
	now := sbClock(t)
	st := state.New(t.TempDir(), "s", "")
	sbSolo(t, st, now, 3)
	sbWantNudge(t, sbCall(st, now, "Read", ""))
}

func TestSearchBatchRepeatsEveryThreshold(t *testing.T) {
	now := sbClock(t)
	st := state.New(t.TempDir(), "s", "")
	for round := range 2 {
		sbSolo(t, st, now, 3)
		if d := sbCall(st, now, "Bash", "cat a.go"); d == nil {
			t.Fatalf("round %d: want the nudge on the 4th lookup", round)
		}
	}
}

func TestSearchBatchParallelCallsReset(t *testing.T) {
	now := sbClock(t)
	st := state.New(t.TempDir(), "s", "")
	sbSolo(t, st, now, 3)
	*now += 3
	sbApply(st, sbIn("PreToolUse", "Bash", "grep a f"))
	*now += 0.4 // the second call's hooks run behind the first's
	sbApply(st, sbIn("PreToolUse", "Read", ""))
	*now += 2 // a slow tool does not end the message
	if d := sbApply(st, sbIn("PostToolUse", "Bash", "grep a f")); d != nil {
		t.Fatalf("first of two parallel calls: %+v", d)
	}
	if d := sbApply(st, sbIn("PostToolUse", "Read", "")); d != nil {
		t.Fatalf("second of two parallel calls: %+v", d)
	}
	sbSolo(t, st, now, 3)
	sbWantNudge(t, sbCall(st, now, "Bash", "grep -rn foo src"))
}

func TestSearchBatchSerialCallsOfOneMessageReset(t *testing.T) {
	now := sbClock(t)
	st := state.New(t.TempDir(), "s", "")
	sbSolo(t, st, now, 2)
	*now += 3
	sbApply(st, sbIn("PreToolUse", "Bash", "grep a f"))
	sbApply(st, sbIn("PostToolUse", "Bash", "grep a f"))
	*now += 0.05 // no API round trip: the same message's next call
	sbApply(st, sbIn("PreToolUse", "Bash", "grep b f"))
	if d := sbApply(st, sbIn("PostToolUse", "Bash", "grep b f")); d != nil {
		t.Fatalf("second serial call: %+v", d)
	}
	sbSolo(t, st, now, 3)
	sbWantNudge(t, sbCall(st, now, "Bash", "grep -rn foo src"))
}

func TestSearchBatchOtherWorkResets(t *testing.T) {
	for _, c := range []struct{ tool, cmd string }{
		{"Edit", ""},
		{"Bash", "go test ./..."},
		{"Bash", "grep -n a f; grep -n b g"}, // already batched in one command
		{"mcp__srv__lookup", ""},
		{"Agent", ""},
	} {
		now := sbClock(t)
		st := state.New(t.TempDir(), "s", "")
		sbSolo(t, st, now, 3)
		if d := sbCall(st, now, c.tool, c.cmd); d != nil {
			t.Fatalf("%s %q: %+v", c.tool, c.cmd, d)
		}
		sbSolo(t, st, now, 3)
	}
}

func TestSearchBatchPromptResetsMainStreak(t *testing.T) {
	now := sbClock(t)
	st := state.New(t.TempDir(), "s", "")
	sbSolo(t, st, now, 3)
	sbApply(st, &hook.Input{HookEventName: "UserPromptSubmit", Prompt: "and where is it called?"})
	sbSolo(t, st, now, 3)
	// A task notification is not a new user turn.
	sbApply(st, &hook.Input{HookEventName: "UserPromptSubmit", Prompt: "<task-notification>done</task-notification>"})
	sbWantNudge(t, sbCall(st, now, "Bash", "grep -rn foo src"))
}

func TestSearchBatchStreakIsPerAgent(t *testing.T) {
	now := sbClock(t)
	root := t.TempDir()
	sbSolo(t, state.New(root, "s", ""), now, 3)
	sbSolo(t, state.New(root, "s", "agent1"), now, 3)
	sbWantNudge(t, sbCall(state.New(root, "s", "agent1"), now, "Bash", "grep -rn foo src"))
}

func TestSearchBatchFailedLookupCountsInterruptResets(t *testing.T) {
	now := sbClock(t)
	st := state.New(t.TempDir(), "s", "")
	sbSolo(t, st, now, 3)
	*now += 3
	sbApply(st, sbIn("PreToolUse", "Bash", "grep -rn nomatch src"))
	sbWantNudge(t, sbApply(st, sbIn("PostToolUseFailure", "Bash", "grep -rn nomatch src"))) // exit 1: no match

	sbSolo(t, st, now, 3)
	*now += 3
	sbApply(st, sbIn("PreToolUse", "Bash", "grep -rn foo /"))
	stop := sbIn("PostToolUseFailure", "Bash", "grep -rn foo /")
	stop.IsInterrupt = true
	if d := sbApply(st, stop); d != nil {
		t.Fatalf("interrupt: %+v", d)
	}
	sbSolo(t, st, now, 3)
}

func TestSearchBatchKind(t *testing.T) {
	for _, c := range []struct {
		tool, cmd string
		want      int
	}{
		{"Read", "", sbSolo1},
		{"Grep", "", sbSolo1},
		{"Glob", "", sbSolo1},
		{"Edit", "", sbOther},
		{"mcp__srv__query", "", sbOther},
		{"Bash", "grep -rn foo src | head -20", sbSolo1},
		{"Bash", "cd app && grep -rn foo . 2>/dev/null | head", sbSolo1},
		{"Bash", "rtk grep foo src", sbSolo1},
		{"Bash", "rtk read a.go", sbSolo1},
		{"Bash", "command grep -n x f", sbSolo1},
		{"Bash", "git log --oneline -5", sbSolo1},
		{"Bash", "git -C /x show HEAD:f | sed -n 1,40p", sbSolo1},
		{"Bash", "sed -n 1,40p f.go", sbSolo1},
		{"Bash", "wc -l f 2>&1", sbSolo1},
		{"Bash", "find . -name '*.go' | xargs grep -n foo", sbSolo1},
		{"Bash", "ls -la src; echo ---", sbSolo1},
		{"Bash", "cat a; cat b", sbBatch},
		{"Bash", "grep a f && grep b g", sbBatch},
		{"Bash", "grep a f\ngrep b g", sbBatch},
		{"Bash", "sed -i s/a/b/ f.go", sbOther},
		{"Bash", "sed --in-place s/a/b/ f.go", sbOther},
		{"Bash", "grep foo a > out.txt", sbOther},
		{"Bash", "cat <<'EOF' > f\nx\nEOF", sbOther},
		{"Bash", "git commit -m x", sbOther},
		{"Bash", "git branch topic", sbOther},
		{"Bash", "go test ./...", sbOther},
		{"Bash", "rm -rf x", sbOther},
		{"Bash", "find . -name x -delete", sbOther},
		{"Bash", "find . -name x -exec rm {} +", sbOther},
		{"Bash", "grep foo $(make list)", sbOther},
		{"Bash", "echo hi", sbOther},
		{"Bash", "", sbOther},
	} {
		if got := sbKind(sbIn("PostToolUse", c.tool, c.cmd)); got != c.want {
			t.Errorf("%s %q: got %d, want %d", c.tool, c.cmd, got, c.want)
		}
	}
}

func TestSearchBatchRegisteredAndConfigured(t *testing.T) {
	found := false
	for _, r := range Registry {
		found = found || r.Name() == "search_batch"
	}
	if !found {
		t.Fatal("search_batch is not in Registry")
	}
	if m := suiteCfg().Mode("search_batch"); m != "enforce" {
		t.Fatalf("default mode %q", m)
	}
}
