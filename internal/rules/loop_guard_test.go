package rules

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iampolo87/claude-policy/internal/config"
	"github.com/iampolo87/claude-policy/internal/hook"
	"github.com/iampolo87/claude-policy/internal/state"
)

func lgCfg() *config.Config {
	return suiteCfg()
}

func lgIn(event, tool, id, cmd string) *hook.Input {
	ti, _ := json.Marshal(map[string]string{"command": cmd})
	return &hook.Input{HookEventName: event, ToolName: tool, ToolUseID: id, ToolInput: ti}
}

func lgApply(st *state.Store, in *hook.Input) *hook.Decision {
	return loopGuard{}.Apply(context.Background(), in, lgCfg(), st)
}

// lgFail runs a Pre then a failing Post for one Bash call; failed is the
// (possibly rtk-rewritten) command the failure event carries.
func lgFail(st *state.Store, id, orig, failed string) *hook.Decision {
	if d := lgApply(st, lgIn("PreToolUse", "Bash", id, orig)); d != nil {
		return d
	}
	f := lgIn("PostToolUseFailure", "Bash", id, failed)
	f.Error = "Exit code 1"
	return lgApply(st, f)
}

func TestLoopGuardThirdIdenticalDenied(t *testing.T) {
	st := state.New(t.TempDir(), "s", "")
	for i, id := range []string{"a", "b"} {
		if d := lgFail(st, id, "ls   x", "rtk ls x"); d != nil {
			t.Fatalf("attempt %d: %+v", i, d)
		}
	}
	d := lgApply(st, lgIn("PreToolUse", "Bash", "c", "rtk ls x"))
	if d == nil || d.Permission != "deny" || !strings.Contains(d.Reason, "BLOCKED by loop-guard: this command already FAILED 2x") {
		t.Fatalf("got %+v", d)
	}
}

func TestLoopGuardRewrittenFailureStillCounts(t *testing.T) {
	st := state.New(t.TempDir(), "s", "")
	lgFail(st, "a", "cd a && cat x", "cd a && rtk read x")
	lgFail(st, "b", "cd a && cat x", "cd a && rtk read x")
	if d := lgApply(st, lgIn("PreToolUse", "Bash", "c", "cd a && cat x")); d == nil || d.Permission != "deny" {
		t.Fatalf("got %+v", d)
	}
}

func TestLoopGuardFallbackWithoutPending(t *testing.T) {
	st := state.New(t.TempDir(), "s", "")
	for _, id := range []string{"a", "b"} {
		f := lgIn("PostToolUseFailure", "Bash", id, "make")
		lgApply(st, f)
	}
	if d := lgApply(st, lgIn("PreToolUse", "Bash", "c", "make")); d == nil {
		t.Fatal("want deny")
	}
}

func TestLoopGuardSuccessClearsFailures(t *testing.T) {
	st := state.New(t.TempDir(), "s", "")
	lgFail(st, "a", "make", "make")
	lgFail(st, "b", "make", "make")
	lgApply(st, lgIn("PostToolUse", "Bash", "zz", "make"))
	if d := lgApply(st, lgIn("PreToolUse", "Bash", "e", "make")); d != nil {
		t.Fatalf("got %+v", d)
	}
}

func TestLoopGuardPendingConsumedAndExpired(t *testing.T) {
	st := state.New(t.TempDir(), "s", "")
	lgApply(st, lgIn("PreToolUse", "Bash", "a", "make"))
	lgApply(st, lgIn("PostToolUse", "Bash", "a", "make"))
	if b, _ := st.Read(lgPending); strings.Contains(string(b), `"a"`) {
		t.Fatalf("pending not consumed: %s", b)
	}
	lgApply(st, lgIn("PreToolUse", "Bash", "old", "make"))
	cfg := lgCfg()
	cfg.Rules.LoopGuard.TTLSeconds = 1
	time.Sleep(1100 * time.Millisecond)
	loopGuard{}.Apply(context.Background(), lgIn("PreToolUse", "Bash", "new", "ls"), cfg, st)
	if b, _ := st.Read(lgPending); strings.Contains(string(b), `"old"`) {
		t.Fatalf("pending not expired: %s", b)
	}
}

func TestLoopGuardTTL(t *testing.T) {
	st := state.New(t.TempDir(), "s", "")
	lgFail(st, "a", "make", "make")
	lgFail(st, "b", "make", "make")
	cfg := lgCfg()
	cfg.Rules.LoopGuard.TTLSeconds = 1
	time.Sleep(1100 * time.Millisecond)
	if d := (loopGuard{}).Apply(context.Background(), lgIn("PreToolUse", "Bash", "c", "make"), cfg, st); d != nil {
		t.Fatalf("expired failures must not deny: %+v", d)
	}
}

func lgStreak(st *state.Store, n int, tool string) (last *hook.Decision) {
	for i := 0; i < n; i++ {
		in := lgIn("PostToolUseFailure", tool, "", "x")
		in.Error = "boom"
		last = lgApply(st, in)
	}
	return last
}

func TestLoopGuardStreakPerAgent(t *testing.T) {
	root := t.TempDir()
	main, sub := state.New(root, "s", ""), state.New(root, "s", "ag1")
	lgStreak(main, 3, "Read")
	lgStreak(sub, 3, "Read")
	if d := lgStreak(main, 1, "Read"); d == nil || !strings.Contains(d.AdditionalContext, "CIRCUIT BREAKER: 4 tool calls") {
		t.Fatalf("main: %+v", d)
	}
	if d := lgStreak(sub, 1, "mcp__x__y"); d == nil || d.AdditionalContext == "" {
		t.Fatalf("sub: %+v", d)
	}
	if d := lgStreak(main, 3, "Read"); d != nil { // reset after nag
		t.Fatalf("main after reset: %+v", d)
	}
}

func TestLoopGuardSuccessResetsStreak(t *testing.T) {
	st := state.New(t.TempDir(), "s", "")
	lgStreak(st, 3, "Read")
	lgApply(st, lgIn("PostToolUse", "Read", "", ""))
	if d := lgStreak(st, 3, "Read"); d != nil {
		t.Fatalf("got %+v", d)
	}
}

func TestLoopGuardPostToolUseErrorIsFailure(t *testing.T) {
	st := state.New(t.TempDir(), "s", "")
	var d *hook.Decision
	for i := 0; i < 4; i++ {
		in := lgIn("PostToolUse", "mcp__a__b", "", "")
		in.ToolResponse = json.RawMessage(`{"isError":true}`)
		d = lgApply(st, in)
	}
	if d == nil {
		t.Fatal("want breaker")
	}
	in := lgIn("PostToolUse", "Bash", "", "")
	in.ToolResponse = json.RawMessage(`"plain string"`)
	if lgApply(st, in) != nil {
		t.Fatal("string response is success")
	}
}

func TestLoopGuardConcurrent(t *testing.T) {
	root := t.TempDir()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lgFail(state.New(root, "s", ""), string(rune('a'+i)), "make", "make")
		}()
	}
	wg.Wait()
	b, _ := state.New(root, "s", "").Read(lgFails)
	var fs []lgRec
	if err := json.Unmarshal(b, &fs); err != nil || len(fs) < 6 { // state.Update fails open on lock timeout, so a rare lost update is allowed; corruption is not
		t.Fatalf("err=%v n=%d", err, len(fs))
	}
}

func TestLoopGuardTimeout(t *testing.T) {
	if d := (loopGuard{}).Timeout(); d != 500*time.Millisecond {
		t.Fatalf("got %v", d)
	}
}

func TestLoopGuardFalsyErrorIsNotFailure(t *testing.T) {
	for _, e := range []string{`""`, `[]`, `{}`, `null`, `false`, `0`} {
		st := state.New(t.TempDir(), "s", "")
		var d *hook.Decision
		for i := 0; i < 4; i++ {
			in := lgIn("PostToolUse", "mcp__a__b", "", "")
			in.ToolResponse = json.RawMessage(`{"error":` + e + `}`)
			d = lgApply(st, in)
		}
		if d != nil {
			t.Errorf("error=%s counted as failure", e)
		}
	}
	st := state.New(t.TempDir(), "s", "")
	var d *hook.Decision
	for i := 0; i < 4; i++ {
		in := lgIn("PostToolUse", "mcp__a__b", "", "")
		in.ToolResponse = json.RawMessage(`{"error":["x"]}`)
		d = lgApply(st, in)
	}
	if d == nil {
		t.Fatal("non-empty list error must count")
	}
}

func TestLoopGuardInterruptNotCounted(t *testing.T) {
	st := state.New(t.TempDir(), "s", "")
	for i := 0; i < 6; i++ {
		in := lgIn("PostToolUseFailure", "Bash", "", "sleep 9")
		in.IsInterrupt = true
		if d := lgApply(st, in); d != nil {
			t.Fatalf("interrupt %d: %+v", i, d)
		}
	}
	if d := lgApply(st, lgIn("PreToolUse", "Bash", "", "sleep 9")); d != nil {
		t.Fatalf("interrupt recorded as failed command: %+v", d)
	}
}

// Failures count per starting directory; agents in one directory share them.
func TestLoopGuardScopedByCwd(t *testing.T) {
	st := state.New(t.TempDir(), "s", "")
	in := func(event, id, cwd string) *hook.Input {
		x := lgIn(event, "Bash", id, "make test")
		x.Cwd = cwd
		return x
	}
	fail := func(id, cwd string, pending bool) {
		if pending {
			lgApply(st, in("PreToolUse", id, cwd))
		}
		f := in("PostToolUseFailure", id, cwd)
		f.Error = "Exit code 1"
		lgApply(st, f)
	}
	fail("a", "/A", true)
	fail("b", "/A", false) // fallback recording without a pending id
	if d := lgApply(st, in("PreToolUse", "c", "/B")); d != nil {
		t.Fatalf("other directory must not be denied: %+v", d)
	}
	if d := lgApply(st, in("PreToolUse", "d", "/A")); d == nil || d.Permission != "deny" {
		t.Fatalf("same directory must be denied: %+v", d)
	}
	x := in("PreToolUse", "e", "/A")
	x.AgentID = "worker"
	if d := lgApply(st, x); d == nil || d.Permission != "deny" {
		t.Fatalf("agents in the same directory share failures: %+v", d)
	}
	lgApply(st, in("PostToolUse", "c", "/B")) // success in B leaves A alone
	if d := lgApply(st, in("PreToolUse", "f", "/A/")); d == nil || d.Permission != "deny" {
		t.Fatalf("success elsewhere must not clear A (cwd cleaned): %+v", d)
	}

	// Absent cwd is its own deterministic key.
	fail("g", "", true)
	fail("h", "", true)
	if d := lgApply(st, in("PreToolUse", "i", "")); d == nil || d.Permission != "deny" {
		t.Fatalf("absent cwd must still be guarded: %+v", d)
	}
	if d := lgApply(st, in("PreToolUse", "j", "/C")); d != nil {
		t.Fatalf("absent-cwd failures must not deny /C: %+v", d)
	}
}
