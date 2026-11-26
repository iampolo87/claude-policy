package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/iampolo87/claude-policy/internal/config"
	"github.com/iampolo87/claude-policy/internal/hook"
	"github.com/iampolo87/claude-policy/internal/state"
)

// cpWorkStateURL is the [integrations.claude_mem] work_state_url cpCfg sets.
var cpWorkStateURL string

func cpCfg(mode string) *config.Config {
	cfg := suiteCfg()
	cfg.Rules.Checkpoint.Mode = mode
	cfg.Integrations.ClaudeMem.WorkStateURL = cpWorkStateURL
	return cfg
}

func cpStore(t *testing.T) *state.Store {
	t.Helper()
	cpWorkStateURL = "http://127.0.0.1:1/none" // never reach a real worker
	return state.New(t.TempDir(), "s1", "")
}

func cpApply(t *testing.T, st *state.Store, payload string) *hook.Decision {
	t.Helper()
	return cpApplyMode(t, st, "log", payload)
}

func cpApplyMode(t *testing.T, st *state.Store, mode, payload string) *hook.Decision {
	t.Helper()
	cfg := cpCfg(mode)
	in, err := hook.Parse([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return checkpoint{}.Apply(ctx, in, cfg, st)
}

func jstr(s string) string { b, _ := json.Marshal(s); return string(b) }

func cpEdit(t *testing.T, st *state.Store, path, agent string) {
	t.Helper()
	cpApply(t, st, fmt.Sprintf(`{"hook_event_name":"PostToolUse","tool_name":"Edit","cwd":"/w","agent_id":%s,"tool_input":{"file_path":%s}}`, jstr(agent), jstr(path)))
}

func cpOnlyFile(t *testing.T, st *state.Store) string {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(st.Dir, "checkpoint-*.md"))
	if len(m) != 1 {
		t.Fatalf("want one checkpoint file, got %v", m)
	}
	b, _ := os.ReadFile(m[0])
	return string(b)
}

func TestCheckpointEditsDedupeAndCap(t *testing.T) {
	st := cpStore(t)
	for i := 0; i < 210; i++ {
		cpEdit(t, st, fmt.Sprintf("f%d.go", i), "")
	}
	cpEdit(t, st, "/w/f209.go", "") // dup of relative, moves to end, no growth
	cpEdit(t, st, "/w/sub/../f150.go", "")
	ls := cpLines(st, cpEdits)
	if len(ls) != 200 || ls[len(ls)-1] != "/w/f150.go" || ls[0] != "/w/f10.go" && ls[0] != "/w/f11.go" {
		t.Fatalf("len=%d first=%s last=%s", len(ls), ls[0], ls[len(ls)-1])
	}
	seen := map[string]bool{}
	for _, l := range ls {
		if seen[l] {
			t.Fatalf("dup %s", l)
		}
		seen[l] = true
	}
}

func TestCheckpointSubagentOnlyEdits(t *testing.T) {
	st := cpStore(t)
	cpEdit(t, st, "/w/a.go", "ag1")
	cpApply(t, st, `{"hook_event_name":"PostToolUse","tool_name":"Bash","agent_id":"ag1","tool_input":{"command":"ls"}}`)
	cpApply(t, st, `{"hook_event_name":"UserPromptSubmit","agent_id":"ag1","prompt":"hi"}`)
	cpApply(t, st, `{"hook_event_name":"Stop","agent_id":"ag1","last_assistant_message":"Risk: none"}`)
	cpApply(t, st, `{"hook_event_name":"PreCompact","agent_id":"ag1","trigger":"auto"}`)
	if d := cpApply(t, st, `{"hook_event_name":"SessionStart","source":"compact","agent_id":"ag1"}`); d != nil {
		t.Fatalf("subagent SessionStart got %+v", d)
	}
	if got := cpLines(st, cpEdits); len(got) != 1 {
		t.Fatalf("edits %v", got)
	}
	for _, n := range []string{cpCommands, cpPrompts, cpRisk} {
		if b, _ := st.Read(n); len(b) != 0 {
			t.Errorf("%s recorded for subagent", n)
		}
	}
	if m, _ := filepath.Glob(filepath.Join(st.Dir, "checkpoint-*.md")); len(m) != 0 {
		t.Fatalf("subagent PreCompact wrote %v", m)
	}
}

func TestCheckpointPromptsAndCommands(t *testing.T) {
	st := cpStore(t)
	for _, p := range []string{"one", "<task-notification>x", "  <agent-message from=a>", "two", "three", "four"} {
		cpApply(t, st, fmt.Sprintf(`{"hook_event_name":"UserPromptSubmit","prompt":%s}`, jstr(p)))
	}
	cpApply(t, st, fmt.Sprintf(`{"hook_event_name":"UserPromptSubmit","prompt":%s}`, jstr(strings.Repeat("é", 1500))))
	var ps []string
	for _, l := range cpLines(st, cpPrompts) {
		var p string
		json.Unmarshal([]byte(l), &p)
		ps = append(ps, p)
	}
	if len(ps) != 3 || ps[0] != "three" || ps[1] != "four" || utf8.RuneCountInString(ps[2]) != 1000 {
		t.Fatalf("prompts %q", ps)
	}

	st = cpStore(t)
	cpApply(t, st, `{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"rtk  ls\n  -la"}}`)
	cpApply(t, st, `{"hook_event_name":"PostToolUseFailure","tool_name":"Bash","error":"Exit code 127\nnope","tool_input":{"command":"a"}}`)
	cpApply(t, st, `{"hook_event_name":"PostToolUseFailure","tool_name":"Bash","is_interrupt":true,"error":"x","tool_input":{"command":"b"}}`)
	cpApply(t, st, `{"hook_event_name":"PostToolUseFailure","tool_name":"Bash","error":"boom","tool_input":{"command":"c"}}`)
	cpApply(t, st, fmt.Sprintf(`{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":%s}}`, jstr(strings.Repeat("x", 300))))
	var got []cpCommand
	for _, l := range cpLines(st, cpCommands) {
		var c cpCommand
		json.Unmarshal([]byte(l), &c)
		got = append(got, c)
	}
	if len(got) != 5 || got[0] != (cpCommand{"rtk ls -la", "0"}) || got[1].Exit != "127" || got[2].Exit != "interrupted" || got[3].Exit != "error" || len(got[4].Cmd) != 200 {
		t.Fatalf("%+v", got)
	}
	for i := 0; i < 12; i++ {
		cpApply(t, st, fmt.Sprintf(`{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"c%d"}}`, i))
	}
	if n := len(cpLines(st, cpCommands)); n != 10 {
		t.Fatalf("commands kept %d", n)
	}
}

func TestCheckpointRisk(t *testing.T) {
	st := cpStore(t)
	cpApply(t, st, `{"hook_event_name":"Stop","last_assistant_message":"done\nRisk: item 2 (x)\n"}`)
	cpApply(t, st, `{"hook_event_name":"Stop","last_assistant_message":"no risk line here"}`)
	if b, _ := st.Read(cpRisk); string(b) != "Risk: item 2 (x)" {
		t.Fatalf("risk %q", b)
	}
}

func TestCheckpointPreCompactSizeCap(t *testing.T) {
	st := cpStore(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("世", 5000))
	}))
	defer srv.Close()
	cpWorkStateURL = srv.URL
	for i := 0; i < 30; i++ {
		cpEdit(t, st, "/w/"+strings.Repeat("é", 100)+fmt.Sprint(i), "")
	}
	for i := 0; i < 3; i++ {
		cpApply(t, st, fmt.Sprintf(`{"hook_event_name":"UserPromptSubmit","prompt":%s}`, jstr(strings.Repeat("世", 2000))))
	}
	cpApply(t, st, `{"hook_event_name":"PreCompact","trigger":"manual","cwd":"/nonexistent"}`)
	out := cpOnlyFile(t, st)
	if len(out) > 8000 || !utf8.ValidString(out) || !strings.HasSuffix(out, "… (truncated)\n") {
		t.Fatalf("len=%d valid=%v", len(out), utf8.ValidString(out))
	}
	fi, _ := os.Stat(filepath.Join(st.Dir, mustGlob(t, st)))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
}

func mustGlob(t *testing.T, st *state.Store) string {
	m, _ := filepath.Glob(filepath.Join(st.Dir, "checkpoint-*.md"))
	if len(m) != 1 {
		t.Fatal(m)
	}
	return filepath.Base(m[0])
}

func TestCheckpointGitAndWorkState(t *testing.T) {
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	repo := t.TempDir()
	if out, err := exec.Command("git", "-C", repo, "init", "-q", "-b", "main").CombinedOutput(); err != nil {
		t.Skipf("git init: %v %s", err, out)
	}
	os.WriteFile(filepath.Join(repo, "dirty.txt"), []byte("x"), 0o644)

	var gotCwd string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCwd = r.URL.Query().Get("cwd")
		fmt.Fprint(w, "- task A doing")
	}))
	defer srv.Close()
	st := cpStore(t)
	cpWorkStateURL = srv.URL
	cpEdit(t, st, filepath.Join(repo, "dirty.txt"), "")
	cpApply(t, st, fmt.Sprintf(`{"hook_event_name":"PreCompact","trigger":"auto","cwd":%s}`, jstr(os.TempDir()+"/a b")))
	out := cpOnlyFile(t, st)
	for _, s := range []string{"?? dirty.txt", "- task A doing", "### " + repo, "- trigger: auto"} {
		if !strings.Contains(out, s) {
			t.Errorf("missing %q in\n%s", s, out)
		}
	}
	if gotCwd != os.TempDir()+"/a b" {
		t.Errorf("cwd query %q", gotCwd)
	}
	// section order
	last := -1
	for _, h := range []string{"## Edited files", "## Last user prompts", "## Last commands", "## Last Risk line", "## Git", "## Work state"} {
		i := strings.Index(out, h)
		if i <= last {
			t.Fatalf("section %s out of order", h)
		}
		last = i
	}
}

func TestCheckpointWorkStateSlowAndNon200(t *testing.T) {
	st := cpStore(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(1500 * time.Millisecond):
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	cpWorkStateURL = srv.URL
	start := time.Now()
	in, _ := hook.Parse([]byte(`{"hook_event_name":"PreCompact","trigger":"auto","cwd":"/nonexistent"}`))
	d, err := apply(context.Background(), checkpoint{}, in, cpCfg("log"), st)
	if d != nil || err != nil || time.Since(start) > 900*time.Millisecond {
		t.Fatalf("d=%v err=%v took %v", d, err, time.Since(start))
	}
	if out := cpOnlyFile(t, st); !strings.Contains(out, "## Work state\n(unavailable)") {
		t.Fatalf("slow: %s", out)
	}

	// integration off: no request, no section
	st = cpStore(t)
	cpWorkStateURL = ""
	cpApply(t, st, `{"hook_event_name":"PreCompact","cwd":"/nonexistent"}`)
	if out := cpOnlyFile(t, st); strings.Contains(out, "Work state") {
		t.Fatalf("off: %s", out)
	}

	st = cpStore(t)
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "x", 500) }))
	defer bad.Close()
	cpWorkStateURL = bad.URL
	cpApply(t, st, `{"hook_event_name":"PreCompact","cwd":"/nonexistent"}`)
	if out := cpOnlyFile(t, st); !strings.Contains(out, "(unavailable)") {
		t.Fatalf("500: %s", out)
	}
}

func TestCheckpointSessionStartInjectsThenConsumes(t *testing.T) {
	st := cpStore(t)
	cpEdit(t, st, "/w/alpha.go", "")
	cpApply(t, st, `{"hook_event_name":"PreCompact","trigger":"auto","cwd":"/nonexistent"}`)
	time.Sleep(2 * time.Millisecond)
	cpEdit(t, st, "/w/beta.go", "")
	cpApply(t, st, `{"hook_event_name":"PreCompact","trigger":"auto","cwd":"/nonexistent"}`)

	d := cpApplyMode(t, st, "enforce", `{"hook_event_name":"SessionStart","source":"compact"}`)
	if d == nil || !strings.HasPrefix(d.AdditionalContext, "[CHECKPOINT] Pre-compaction state from ") || !strings.Contains(d.AdditionalContext, "/w/beta.go") {
		t.Fatalf("first: %+v", d)
	}
	// the work-state hint follows the integration (cpStore turns it on)
	if !strings.Contains(d.AdditionalContext, "checks, recover the work-state list, then restate") {
		t.Fatalf("work-state hint missing: %.300s", d.AdditionalContext)
	}
	cpWorkStateURL = ""
	st2 := cpStore(t)
	cpWorkStateURL = ""
	cpEdit(t, st2, "/w/gamma.go", "")
	cpApply(t, st2, `{"hook_event_name":"PreCompact","trigger":"auto","cwd":"/nonexistent"}`)
	if d2 := cpApplyMode(t, st2, "enforce", `{"hook_event_name":"SessionStart","source":"compact"}`); d2 == nil || strings.Contains(d2.AdditionalContext, "work-state") {
		t.Fatalf("integration off: %+v", d2)
	}
	if m, _ := filepath.Glob(filepath.Join(st.Dir, "checkpoint-*.md")); len(m) != 0 {
		t.Fatalf("not consumed: %v", m)
	}
	if m, _ := filepath.Glob(filepath.Join(st.Dir, "checkpoint-*.md.consumed")); len(m) != 2 {
		t.Fatalf("consumed: %v", m)
	}
	d = cpApplyMode(t, st, "enforce", `{"hook_event_name":"SessionStart","source":"compact"}`)
	if d == nil || d.AdditionalContext != noticePostCompact {
		t.Fatalf("second: %+v", d)
	}
	if d := cpApply(t, st, `{"hook_event_name":"SessionStart","source":"startup"}`); d != nil {
		t.Fatalf("startup: %+v", d)
	}
}

func TestCheckpointPostCompact(t *testing.T) {
	st := cpStore(t)
	for i := 0; i < 12; i++ {
		cpEdit(t, st, fmt.Sprintf("/w/file%d.go", i), "")
	}
	cpApply(t, st, `{"hook_event_name":"PostCompact","session_id":"s1","compact_summary":"touched file0.go and file1.go"}`)
	b, err := os.ReadFile(filepath.Join(st.Root, "decisions.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var e map[string]string
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatal(err)
	}
	if e["rule"] != "checkpoint" || e["event"] != "PostCompact" || e["mode"] != "log" || e["session_id"] != "s1" ||
		!strings.HasPrefix(e["result"], "summary 29 chars sha256:") || !strings.Contains(e["result"], ", anchors 12, missing 10: file2.go, file3.go") ||
		!strings.HasSuffix(e["result"], "file11.go") {
		t.Fatalf("%v", e)
	}
	// 11 missing -> ellipsis
	cpApply(t, st, `{"hook_event_name":"PostCompact","session_id":"s1","compact_summary":"file0.go"}`)
	if b, _ := os.ReadFile(filepath.Join(st.Root, "decisions.jsonl")); !strings.Contains(string(b), `missing 11: file1.go`) || !strings.Contains(string(b), `…"`) {
		t.Fatalf("%s", b)
	}
}

func TestCheckpointLogModeKeepsCheckpoint(t *testing.T) {
	st := cpStore(t)
	cpEdit(t, st, "/w/alpha.go", "")
	cpApply(t, st, `{"hook_event_name":"PreCompact","trigger":"manual","cwd":"/nonexistent"}`)
	if d := cpApply(t, st, `{"hook_event_name":"SessionStart","source":"compact"}`); d == nil || !strings.Contains(d.AdditionalContext, "/w/alpha.go") {
		t.Fatalf("log-mode decision: %+v", d)
	}
	if m, _ := filepath.Glob(filepath.Join(st.Dir, "checkpoint-*.md")); len(m) != 1 {
		t.Fatalf("log mode consumed the checkpoint: %v", m)
	}
}

func TestCheckpointBodyNotInDecisionLog(t *testing.T) {
	st := cpStore(t)
	cpApply(t, st, `{"hook_event_name":"UserPromptSubmit","prompt":"PRIVATE-PROMPT-7731"}`)
	cpApply(t, st, `{"hook_event_name":"PreCompact","trigger":"manual","cwd":"/nonexistent"}`)
	in, _ := hook.Parse([]byte(`{"session_id":"s1","hook_event_name":"SessionStart","source":"compact"}`))
	out := Run(context.Background(), []Rule{checkpoint{}}, suiteCfg(), in, st)
	if out.HookSpecificOutput != nil {
		t.Fatalf("log mode emitted: %+v", out)
	}
	b, err := os.ReadFile(filepath.Join(st.Root, "decisions.jsonl"))
	if err != nil || strings.Contains(string(b), "PRIVATE-PROMPT-7731") || !strings.Contains(string(b), "private") {
		t.Fatalf("decisions.jsonl (%v): %s", err, b)
	}
}

func TestCheckpointRejectsNewlinePath(t *testing.T) {
	st := cpStore(t)
	cpEdit(t, st, "/w/a.go\n- /etc/passwd", "")
	if ls := cpLines(st, cpEdits); len(ls) != 0 {
		t.Fatalf("recorded %q", ls)
	}
}
