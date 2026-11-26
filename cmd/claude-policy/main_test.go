package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
)

func home(t *testing.T) string {
	t.Helper()
	h := t.TempDir()
	t.Setenv("HOME", h)
	return h
}

// suitePolicy is testdata/suite.policy.toml with a fixture's own policy
// merged over it, table by table: the fixtures were recorded against that
// profile, not against the all-log defaults.
func suitePolicy(t *testing.T, over []byte) []byte {
	t.Helper()
	var base, o map[string]any
	if _, err := toml.DecodeFile("../../testdata/suite.policy.toml", &base); err != nil {
		t.Fatal(err)
	}
	if _, err := toml.Decode(string(over), &o); err != nil {
		t.Fatal(err)
	}
	var merge func(dst, src map[string]any)
	merge = func(dst, src map[string]any) {
		for k, v := range src {
			if sm, ok := v.(map[string]any); ok {
				if dm, ok := dst[k].(map[string]any); ok {
					merge(dm, sm)
					continue
				}
			}
			dst[k] = v
		}
	}
	merge(base, o)
	var b bytes.Buffer
	if err := toml.NewEncoder(&b).Encode(base); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func writePolicy(t *testing.T, h string, pol []byte) {
	t.Helper()
	os.MkdirAll(filepath.Join(h, ".claude"), 0o700)
	if err := os.WriteFile(filepath.Join(h, ".claude", "policy.toml"), pol, 0o600); err != nil {
		t.Fatal(err)
	}
}

func call(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var o, e bytes.Buffer
	code = run(args, strings.NewReader(stdin), &o, &e)
	return code, o.String(), e.String()
}

func TestFixtures(t *testing.T) {
	ins, _ := filepath.Glob("../../testdata/*/*.in.json")
	if len(ins) == 0 {
		t.Fatal("no fixtures")
	}
	testdata, _ := filepath.Abs("../../testdata")
	for _, p := range ins {
		t.Run(p, func(t *testing.T) {
			h := home(t)
			for _, k := range []string{"HERDR_ENV", "HERDR_PANE_ID", "PONYTAIL_OFF"} {
				t.Setenv(k, "") // rules read these; fixtures must not depend on the caller's shell
			}
			base := strings.TrimSuffix(p, ".in.json")
			// optional <case>.policy.toml: what the fixture adds to the suite policy (e.g. a log-mode rule set to enforce)
			over, _ := os.ReadFile(base + ".policy.toml")
			pol := suitePolicy(t, over)
			writePolicy(t, h, pol)
			in, _ := os.ReadFile(p)
			in = bytes.ReplaceAll(in, []byte("{{TESTDATA}}"), []byte(testdata)) // for fixtures that point at files
			want, err := os.ReadFile(base + ".want.json")
			if err != nil {
				t.Fatal(err)
			}
			code, got, _ := call(t, string(in), "hook")
			var g, w any
			if code != 0 || json.Unmarshal([]byte(got), &g) != nil || json.Unmarshal(want, &w) != nil || !reflect.DeepEqual(g, w) {
				t.Fatalf("code=%d got %s want %s", code, got, want)
			}
			// the metrics sink never changes stdout
			writePolicy(t, home(t), append(pol, "\n[metrics]\nmode = \"off\"\n"...))
			if _, off, _ := call(t, string(in), "hook"); json.Unmarshal([]byte(off), &g) != nil || !reflect.DeepEqual(g, w) {
				t.Fatalf("metrics off: got %s want %s", off, want)
			}
		})
	}
}

func TestHookBadStdinIsEmptyObject(t *testing.T) {
	home(t)
	for _, in := range []string{"", "garbage", "[1]", `{"tool_name":1}`, `{"permission_mode":7,"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`, `{"hook_event_name":"PreToolUse","tool_input":` + strings.Repeat(" ", maxHookStdin) + `{}}`} {
		if code, out, _ := call(t, in, "hook"); code != 0 || out != "{}\n" {
			t.Fatalf("stdin %.20q: code=%d out=%q", in, code, out)
		}
	}
	if _, _, errs := call(t, `{"stop_hook_active":"yes"}`, "hook"); !strings.Contains(errs, "claude-policy:") {
		t.Fatalf("unparseable envelope must be reported on stderr, got %q", errs)
	}
}

type panicReader struct{}

func (panicReader) Read([]byte) (int, error) { panic("boom") }

func TestPanicExitsZero(t *testing.T) {
	home(t)
	for _, sub := range []string{"hook", "probe"} {
		var o, e bytes.Buffer
		code := run([]string{sub}, panicReader{}, &o, &e)
		if code != 0 || !strings.Contains(e.String(), "panic") {
			t.Fatalf("%s: code=%d stderr=%q", sub, code, e.String())
		}
		if sub == "hook" && o.String() != "{}\n" {
			t.Fatalf("hook panic must still print {}: %q", o.String())
		}
	}
}

func TestHookBadConfigContinues(t *testing.T) {
	h := home(t)
	os.MkdirAll(filepath.Join(h, ".claude"), 0o700)
	os.WriteFile(filepath.Join(h, ".claude", "policy.toml"), []byte("[rules.loop_guard]\nfail_treshold = 2\n"), 0o600)
	code, out, errs := call(t, `{"hook_event_name":"Stop","session_id":"s"}`, "hook")
	if code != 0 || out != "{}\n" || !strings.Contains(errs, "fail_treshold") {
		t.Fatalf("code=%d out=%q stderr=%q", code, out, errs)
	}
}

func TestConfigCheck(t *testing.T) {
	h := home(t)
	t.Chdir(h) // config check reads the cwd's project file: keep the developer's own files out
	if code, out, _ := call(t, "", "config", "check"); code != 0 || out != "ok\n" {
		t.Fatalf("defaults: code=%d out=%q", code, out)
	}
	os.MkdirAll(filepath.Join(h, ".claude"), 0o700)
	os.WriteFile(filepath.Join(h, ".claude", "policy.toml"), []byte("[rules.loop_guard]\nfail_treshold = 2\n[rules.lint]\nmode = \"on\"\n"), 0o600)
	code, out, errs := call(t, "", "config", "check")
	if code != 1 || out != "" || !strings.Contains(errs, "rules.loop_guard.fail_treshold") || !strings.Contains(errs, "rules.lint.mode") {
		t.Fatalf("typo: code=%d out=%q stderr=%q", code, out, errs)
	}
	if code, _, _ := call(t, "", "nope"); code != 1 {
		t.Fatalf("unknown subcommand: code=%d", code)
	}
}

func TestProbe(t *testing.T) {
	h := home(t)
	probe := filepath.Join(h, ".claude", "state", "policy", "probe")
	raw := `{"hook_event_name":"Stop","session_id":"t","x":[1,2]}` + "\n"
	for range 2 {
		if code, out, errs := call(t, raw, "probe"); code != 0 || out != "" || errs != "" {
			t.Fatalf("code=%d out=%q err=%q", code, out, errs)
		}
	}
	files, _ := filepath.Glob(filepath.Join(probe, "Stop", "*.json"))
	if len(files) != 2 {
		t.Fatalf("want 2 distinct captures, got %v", files)
	}
	fi, _ := os.Stat(files[0])
	di, _ := os.Stat(filepath.Join(probe, "Stop"))
	got, _ := os.ReadFile(files[0])
	if fi.Mode() != 0o600 || di.Mode() != 0o700|os.ModeDir || string(got) != raw {
		t.Fatalf("file %v dir %v content %q", fi.Mode(), di.Mode(), got)
	}

	old := time.Now().Add(-25 * time.Hour)
	os.Chtimes(files[0], old, old)
	call(t, raw, "probe")
	if _, err := os.Stat(files[0]); !os.IsNotExist(err) {
		t.Fatal("captures older than 24h must be deleted")
	}
	other := filepath.Join(probe, "SessionEnd", "old.json")
	os.MkdirAll(filepath.Dir(other), 0o700)
	os.WriteFile(other, nil, 0o600)
	os.Chtimes(other, old, old)
	call(t, raw, "probe")
	if _, err := os.Stat(other); !os.IsNotExist(err) {
		t.Fatal("retention must sweep every event dir, not only the firing one")
	}
	os.Remove(filepath.Dir(other))

	for _, in := range []string{"garbage", `{"hook_event_name":"../../x"}`, `{"hook_event_name":".x"}`} {
		if code, _, _ := call(t, in, "probe"); code != 0 {
			t.Fatalf("%q: code=%d", in, code)
		}
	}
	ents, _ := os.ReadDir(probe)
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if !reflect.DeepEqual(names, []string{"Stop", "unknown"}) {
		t.Fatalf("event dirs %v", names)
	}
	if u, _ := filepath.Glob(filepath.Join(probe, "unknown", "*.json")); len(u) != 3 {
		t.Fatalf("unknown captures %v", u)
	}
}

// json.Marshal re-escapes <>& inside the updatedToolOutput RawMessage.
func TestHookOutputNotHTMLEscaped(t *testing.T) {
	h := home(t)
	t.Setenv("BASH_MAX_OUTPUT_LENGTH", "")
	os.MkdirAll(filepath.Join(h, ".claude"), 0o700)
	os.WriteFile(filepath.Join(h, ".claude", "policy.toml"), []byte("[rules.output_cap]\nmode = \"enforce\"\n"), 0o600)
	in, _ := json.Marshal(map[string]any{
		"hook_event_name": "PostToolUse", "session_id": "s", "tool_name": "Bash", "tool_use_id": "toolu_x",
		"scratchpad_dir": t.TempDir(),
		"tool_response":  map[string]any{"stdout": strings.Repeat("<a&b>", 3000), "stderr": "", "interrupted": false, "isImage": false},
	})
	_, out, _ := call(t, string(in), "hook")
	if !strings.Contains(out, "updatedToolOutput") || strings.Contains(out, "\x5cu003c") || len(out) > 9000 {
		t.Fatalf("len %d, escaped %v", len(out), strings.Contains(out, "\x5cu003c"))
	}
}

func TestCheckpointSequence(t *testing.T) {
	h := home(t)
	t.Setenv("HERDR_ENV", "")
	os.MkdirAll(filepath.Join(h, ".claude"), 0o700)
	os.WriteFile(filepath.Join(h, ".claude", "policy.toml"), []byte("[rules.checkpoint]\nmode = \"enforce\"\n"), 0o600)
	hk := func(payload string) string {
		t.Helper()
		code, out, _ := call(t, payload, "hook")
		if code != 0 {
			t.Fatalf("code %d for %s", code, payload)
		}
		return out
	}
	const s = `"session_id":"seq","cwd":"/nonexistent"`
	hk(`{` + s + `,"hook_event_name":"UserPromptSubmit","prompt":"fix the frobnicator"}`)
	hk(`{` + s + `,"hook_event_name":"PostToolUse","tool_name":"Edit","tool_input":{"file_path":"/w/frob.go"},"tool_response":{}}`)
	hk(`{` + s + `,"hook_event_name":"PreCompact","trigger":"auto"}`)
	out := hk(`{` + s + `,"hook_event_name":"SessionStart","source":"compact"}`)
	for _, w := range []string{"[CHECKPOINT]", "/w/frob.go", "fix the frobnicator"} {
		if !strings.Contains(out, w) {
			t.Fatalf("first SessionStart lacks %q: %s", w, out)
		}
	}
	if strings.Contains(out, "[POST-COMPACT]") {
		t.Fatalf("prose duplicated: %s", out)
	}
	hk(`{` + s + `,"hook_event_name":"PostCompact","compact_summary":"nothing"}`)
	out = hk(`{` + s + `,"hook_event_name":"SessionStart","source":"compact"}`)
	if strings.Contains(out, "[CHECKPOINT]") || !strings.Contains(out, "[POST-COMPACT]") {
		t.Fatalf("second SessionStart: %s", out)
	}
}

const metricsIn = `{"hook_event_name":"PreToolUse","session_id":"sm","tool_name":"Bash","tool_input":{"command":"ls"},"cwd":"/tmp"}`

func readMetrics(t *testing.T, h string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(h, ".claude", "state", "policy", "metrics.jsonl"))
	if err != nil {
		return nil
	}
	var ls []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("bad line %q: %v", l, err)
		}
		ls = append(ls, m)
	}
	return ls
}

func TestMetricsLine(t *testing.T) {
	h := home(t)
	t.Setenv("BASH_MAX_OUTPUT_LENGTH", "")
	_, out, _ := call(t, metricsIn, "hook")
	ls := readMetrics(t, h)
	if len(ls) != 1 {
		t.Fatalf("lines: %v", ls)
	}
	m := ls[0]
	if _, err := time.Parse(time.RFC3339Nano, m["ts"].(string)); err != nil || m["session_id"] != "sm" || m["event"] != "PreToolUse" || m["tool"] != "Bash" {
		t.Fatalf("fields: %v", m)
	}
	if _, ok := m["agent_id"]; ok {
		t.Fatal("agent_id must be omitted")
	}
	if _, ok := m["total_us"].(float64); !ok {
		t.Fatalf("total_us: %v", m)
	}
	if _, ok := m["total_ms"].(float64); !ok {
		t.Fatalf("total_ms: %v", m)
	}
	rs, ok := m["rules"].([]any)
	if !ok || len(rs) == 0 {
		t.Fatalf("rules: %v", m["rules"])
	}
	for _, r := range rs {
		r := r.(map[string]any)
		if r["name"] == "" || r["verdict"] == "" || r["mode"] == "" || r["us"] == nil {
			t.Fatalf("rule: %v", r)
		}
		if _, ok := r["ms"].(float64); !ok {
			t.Fatalf("rule ms: %v", r)
		}
	}
	fi, _ := os.Stat(filepath.Join(h, ".claude", "state", "policy", "metrics.jsonl"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}

	// stdout identical with metrics off, and no file
	h2 := home(t)
	os.MkdirAll(filepath.Join(h2, ".claude"), 0o700)
	os.WriteFile(filepath.Join(h2, ".claude", "policy.toml"), []byte("[metrics]\nmode = \"off\"\n"), 0o600)
	_, out2, _ := call(t, metricsIn, "hook")
	if out != out2 {
		t.Fatalf("stdout differs: %q vs %q", out, out2)
	}
	if _, err := os.Stat(filepath.Join(h2, ".claude", "state", "policy", "metrics.jsonl")); err == nil {
		t.Fatal("mode off wrote a file")
	}
}

func TestMetricsNoRulesAndNoInput(t *testing.T) {
	h := home(t)
	call(t, `{"hook_event_name":"NoSuchEvent","session_id":"sm"}`, "hook")
	ls := readMetrics(t, h)
	if len(ls) != 1 {
		t.Fatalf("lines: %v", ls)
	}
	if rs, ok := ls[0]["rules"].([]any); !ok || len(rs) != 0 {
		t.Fatalf("rules must be []: %v", ls[0]["rules"])
	}
	h = home(t)
	call(t, `not json`, "hook")
	call(t, ``, "hook")
	if ls := readMetrics(t, h); ls != nil {
		t.Fatalf("unparsable input wrote %v", ls)
	}
}

// projectHome is a HOME whose global file enforces destructive, with a
// project under it carrying body as its .claude/policy.toml.
func projectHome(t *testing.T, body string) (proj string) {
	t.Helper()
	h := home(t)
	proj = filepath.Join(h, "proj")
	for dir, b := range map[string]string{h: "[rules.destructive]\nmode = \"enforce\"\n", proj: body} {
		os.MkdirAll(filepath.Join(dir, ".claude"), 0o700)
		if err := os.WriteFile(filepath.Join(dir, ".claude", "policy.toml"), []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return proj
}

func rebaseIn(cwd string) string {
	b, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": "s1", "cwd": cwd,
		"tool_input": map[string]string{"command": "git rebase --onto a b c"}})
	return string(b)
}

func TestHookReadsProjectPolicy(t *testing.T) {
	proj := projectHome(t, "[rules.destructive.git]\nallow_actions = [\"rebase\"]\n")
	lane := filepath.Join(proj, ".claude", "worktrees", "lane")
	if code, out, errs := call(t, rebaseIn(lane), "hook"); code != 0 || strings.Contains(out, `"ask"`) || errs != "" {
		t.Fatalf("in the project the rebase must pass: code=%d out=%s err=%s", code, out, errs)
	}
	if _, out, _ := call(t, rebaseIn(filepath.Dir(proj)), "hook"); !strings.Contains(out, `"permissionDecision":"ask"`) {
		t.Fatalf("outside the project the rebase must ask: %s", out)
	}
}

func TestHookBadProjectPolicyKeepsGlobal(t *testing.T) {
	proj := projectHome(t, "[rules.destructive]\nmode = \"off\"\n")
	code, out, errs := call(t, rebaseIn(proj), "hook")
	if code != 0 || !strings.Contains(out, `"permissionDecision":"ask"`) {
		t.Fatalf("a project file may not switch the rule off: code=%d out=%s", code, out)
	}
	if !strings.Contains(errs, filepath.Join(proj, ".claude", "policy.toml")) {
		t.Fatalf("stderr must name the project file: %q", errs)
	}
}

func TestConfigCheckProjectFile(t *testing.T) {
	proj := projectHome(t, "[rules.destructive.git]\nallow_actions = [\"rebase\"]\n")
	t.Chdir(proj)
	pp := filepath.Join(proj, ".claude", "policy.toml")
	if code, out, errs := call(t, "", "config", "check"); code != 0 || !strings.Contains(out, "ok") || !strings.Contains(out, pp) {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	os.WriteFile(pp, []byte("[rules.destructive.git]\nmain = \"allow\"\n"), 0o600)
	if code, _, errs := call(t, "", "config", "check"); code != 1 || !strings.Contains(errs, pp) || !strings.Contains(errs, "only the global file") {
		t.Fatalf("code=%d err=%q", code, errs)
	}
}
