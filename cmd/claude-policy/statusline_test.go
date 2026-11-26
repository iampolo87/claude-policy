package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type slEnv struct {
	dir, renderer, herdr, herdrLog, envLog, inLog string
}

// setupSL pins every env var the statusline depends on and writes fake
// renderer + herdr scripts. herdrBody is the shell run after logging argv.
func setupSL(t *testing.T, herdrBody string) *slEnv {
	t.Helper()
	d := t.TempDir()
	e := &slEnv{dir: d, renderer: filepath.Join(d, "render.sh"), herdr: filepath.Join(d, "herdr"),
		herdrLog: filepath.Join(d, "herdr.log"), envLog: filepath.Join(d, "env.log"), inLog: filepath.Join(d, "in.log")}
	t.Setenv("HOME", d)
	t.Setenv("HERDR_PANE_ID", "pane-1")
	t.Setenv("HERDR_BIN_PATH", e.herdr)
	t.Setenv("HERDR_ENV", "1")
	bin := filepath.Join(d, "bin") // hermetic PATH: no real herdr can be found
	os.Mkdir(bin, 0o755)
	for _, n := range []string{"sh", "bash", "env", "cat", "sleep", "printf", "echo"} {
		if p, err := exec.LookPath(n); err == nil {
			os.Symlink(p, filepath.Join(bin, n))
		}
	}
	t.Setenv("PATH", bin)
	t.Setenv("HERDR_SOCKET_PATH", "")
	t.Setenv("HERDR_TAB_ID", "")
	t.Setenv("HERDR_WORKSPACE_ID", "")
	t.Setenv("BASH_MAX_OUTPUT_LENGTH", "12000")
	write := func(p, s string) {
		if err := os.WriteFile(p, []byte(s), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(e.renderer, "#!/bin/sh\nenv > "+e.envLog+"\ncat > "+e.inLog+"\nprintf '\\033[1mhi\\033[0m'\n")
	write(e.herdr, "#!/bin/sh\necho \"$*\" >> "+e.herdrLog+"\n"+herdrBody+"\n")
	e.policy(t, true)
	return e
}

// policy writes [integrations.herdr] report into the test HOME's policy.toml.
func (e *slEnv) policy(t *testing.T, report bool) {
	t.Helper()
	os.MkdirAll(filepath.Join(e.dir, ".claude"), 0o755)
	body := "[integrations.herdr]\nreport = false\n"
	if report {
		body = "[integrations.herdr]\nreport = true\n"
	}
	if err := os.WriteFile(filepath.Join(e.dir, ".claude", "policy.toml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// herdrLines keeps a failure message to the variables under test: the rest
// of the caller's environment does not belong in a test log.
func herdrLines(env []byte) (out []string) {
	for _, l := range strings.Split(string(env), "\n") {
		if strings.HasPrefix(l, "HERDR_") {
			out = append(out, l)
		}
	}
	return out
}

// Off, which is the default: nothing is reported and the renderer sees the
// environment untouched.
func TestStatuslineHerdrOffByDefault(t *testing.T) {
	e := setupSL(t, "exit 0")
	for _, withFile := range []bool{true, false} {
		os.RemoveAll(filepath.Join(e.dir, ".claude"))
		if withFile {
			e.policy(t, false)
		}
		out, code := runSL(t, []string{e.renderer}, fixture(t))
		env, _ := os.ReadFile(e.envLog)
		if code != 0 || out == "" || len(e.calls(t)) != 0 || !strings.Contains(string(env), "HERDR_ENV=1") {
			t.Fatalf("file=%v code=%d out=%q calls=%q env=%q", withFile, code, out, e.calls(t), herdrLines(env))
		}
	}
}

func (e *slEnv) calls(t *testing.T) []string {
	b, _ := os.ReadFile(e.herdrLog)
	s := strings.TrimSpace(string(b))
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func runSL(t *testing.T, args []string, in string) (string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(append([]string{"statusline"}, args...), strings.NewReader(in), &out, &errb)
	return out.String(), code
}

func fixture(t *testing.T) string {
	b, err := os.ReadFile("../../testdata/statusline/real.json")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mk(model, effort, ctx, cost string, size string) string {
	return `{"session_id":"s1","model":{"id":"claude-x","display_name":"` + model + `"},"effort":{"level":"` + effort +
		`"},"cost":{"total_cost_usd":` + cost + `},"context_window":{"context_window_size":` + size + `,"used_percentage":` + ctx + `}}`
}

func TestStatuslineTokensFromFixture(t *testing.T) {
	e := setupSL(t, "exit 0")
	out, code := runSL(t, []string{e.renderer}, fixture(t))
	if code != 0 || out != "\x1b[1mhi\x1b[0m" {
		t.Fatalf("code=%d out=%q", code, out)
	}
	c := e.calls(t)
	want := "pane report-metadata pane-1 --source claude-policy --agent claude --token model=Opus 5.5[1m] --token effort=high --token context=9% --token cost=$1.25"
	if len(c) != 1 || c[0] != want {
		t.Fatalf("calls=%q", c)
	}
}

func TestStatuslineTokenVariants(t *testing.T) {
	e := setupSL(t, "exit 0")
	in := `{"session_id":"s2","model":{"id":"claude-x"},"effort":{"level":""},"cost":{"total_cost_usd":0.5},"context_window":{"context_window_size":200000,"used_percentage":null}}`
	runSL(t, []string{e.renderer}, in)
	c := e.calls(t)
	want := "--token model=claude-x --clear-token effort --clear-token context --token cost=$0.50"
	if len(c) != 1 || !strings.Contains(c[0], want) {
		t.Fatalf("calls=%q", c)
	}
}

func TestStatuslineOnlyOnChange(t *testing.T) {
	e := setupSL(t, "exit 0")
	steps := []struct {
		cost  string
		calls int
	}{{"1.0092", 1}, {"1.0092", 1}, {"1.0093", 1}, {"1.02", 2}}
	for _, s := range steps {
		runSL(t, []string{e.renderer}, mk("M", "high", "9", s.cost, "200000"))
		if n := len(e.calls(t)); n != s.calls {
			t.Fatalf("cost %s: calls=%d want %d", s.cost, n, s.calls)
		}
	}
}

func TestStatuslineHerdrFailureRetries(t *testing.T) {
	e := setupSL(t, "exit 1")
	in := mk("M", "high", "9", "1", "200000")
	runSL(t, []string{e.renderer}, in)
	runSL(t, []string{e.renderer}, in)
	if n := len(e.calls(t)); n != 2 {
		t.Fatalf("calls=%d want 2", n)
	}
}

func TestStatuslineNoPaneOrBinary(t *testing.T) {
	e := setupSL(t, "exit 0")
	t.Setenv("HERDR_PANE_ID", "")
	out, code := runSL(t, []string{e.renderer}, fixture(t))
	if code != 0 || out == "" || len(e.calls(t)) != 0 {
		t.Fatalf("no pane: code=%d out=%q calls=%q", code, out, e.calls(t))
	}
	t.Setenv("HERDR_PANE_ID", "pane-1")
	t.Setenv("HERDR_BIN_PATH", filepath.Join(e.dir, "missing"))
	out, code = runSL(t, []string{e.renderer}, fixture(t))
	if code != 0 || out == "" || len(e.calls(t)) != 0 {
		t.Fatalf("no bin: code=%d out=%q calls=%q", code, out, e.calls(t))
	}
}

func TestStatuslineRendererIO(t *testing.T) {
	e := setupSL(t, "exit 0")
	in := fixture(t)
	runSL(t, []string{e.renderer}, in)
	got, _ := os.ReadFile(e.inLog)
	if string(got) != in {
		t.Fatal("renderer stdin differs")
	}
	env, _ := os.ReadFile(e.envLog)
	if strings.Contains(string(env), "HERDR_ENV") || !strings.Contains(string(env), "HERDR_PANE_ID=pane-1") {
		t.Fatalf("renderer env wrong: %q", herdrLines(env))
	}
}

func TestStatuslineMissingRenderer(t *testing.T) {
	e := setupSL(t, "exit 0")
	for _, args := range [][]string{nil, {filepath.Join(e.dir, "nope")}} {
		os.Remove(e.herdrLog)
		os.RemoveAll(filepath.Join(e.dir, ".claude"))
		e.policy(t, true)
		out, code := runSL(t, args, fixture(t))
		if code != 0 || out != "" || len(e.calls(t)) != 1 {
			t.Fatalf("args=%v code=%d out=%q calls=%q", args, code, out, e.calls(t))
		}
	}
}

func TestStatuslineInvalidJSON(t *testing.T) {
	e := setupSL(t, "exit 0")
	out, code := runSL(t, []string{e.renderer}, "not json")
	got, _ := os.ReadFile(e.inLog)
	if code != 0 || out == "" || string(got) != "not json" || len(e.calls(t)) != 0 {
		t.Fatalf("code=%d out=%q in=%q calls=%q", code, out, got, e.calls(t))
	}
}

func TestStatuslineHungHerdr(t *testing.T) {
	e := setupSL(t, "exec sleep 5")
	start := time.Now()
	out, code := runSL(t, []string{e.renderer}, fixture(t))
	if d := time.Since(start); d > 200*time.Millisecond || code != 0 || out == "" {
		t.Fatalf("took %v code=%d out=%q", d, code, out)
	}
}

func TestStatuslinePaneChangeResends(t *testing.T) {
	e := setupSL(t, "exit 0")
	in := mk("M", "high", "9", "1", "200000")
	runSL(t, []string{e.renderer}, in)
	t.Setenv("HERDR_PANE_ID", "pane-2")
	runSL(t, []string{e.renderer}, in)
	if n := len(e.calls(t)); n != 2 {
		t.Fatalf("calls=%d want 2", n)
	}
}

func TestStatuslineFloatSizeAndEmptyModel(t *testing.T) {
	e := setupSL(t, "exit 0")
	runSL(t, []string{e.renderer}, mk("M", "high", "9", "1", "1000000.0"))
	if c := e.calls(t); len(c) != 1 || !strings.Contains(c[0], "model=M[1m]") {
		t.Fatalf("calls=%q", c)
	}
	os.Remove(e.herdrLog)
	out, _ := runSL(t, []string{e.renderer}, "{}")
	if out == "" || len(e.calls(t)) != 0 {
		t.Fatalf("out=%q calls=%q", out, e.calls(t))
	}
}
