package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeMine installs a fake mempalace running body; it counts calls in $dir/calls.
func fakeMine(t *testing.T, body string) string {
	t.Helper()
	d := t.TempDir()
	bin := filepath.Join(d, "mempalace")
	script := "#!/bin/sh\necho x >> " + d + "/calls\nn=$(wc -l < " + d + "/calls)\n" + body + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	oldB := mineBackoff
	mineBackoff = time.Millisecond
	t.Cleanup(func() { mineBackoff = oldB })
	minePolicy(t, "mine = true\nbin = \""+bin+"\"\nprojects_root = \"/work/user/projects\"\n")
	return d
}

// minePolicy writes [integrations.mempalace] into $HOME's policy.toml.
func minePolicy(t *testing.T, body string) {
	t.Helper()
	dir := filepath.Join(os.Getenv("HOME"), ".claude")
	os.MkdirAll(dir, 0o755)
	if err := os.WriteFile(filepath.Join(dir, "policy.toml"), []byte("[integrations.mempalace]\n"+body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func transcript(t *testing.T, dir string) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), dir)
	os.MkdirAll(d, 0o755)
	p := filepath.Join(d, "s.jsonl")
	os.WriteFile(p, []byte("{}"), 0o644)
	return p
}

// mineRun returns the last decisions.jsonl line.
func mineRun(t *testing.T, h, tp string) string {
	t.Helper()
	code, out, _ := call(t, `{"session_id":"sess1","transcript_path":"`+tp+`"}`, "mine")
	if code != 0 || out != "" {
		t.Fatalf("code=%d out=%q", code, out)
	}
	b, _ := os.ReadFile(filepath.Join(h, ".claude/state/policy/decisions.jsonl"))
	ls := strings.Split(strings.TrimSpace(string(b)), "\n")
	return ls[len(ls)-1]
}

func calls(d string) int {
	b, _ := os.ReadFile(filepath.Join(d, "calls"))
	return strings.Count(string(b), "\n")
}

func TestMineSuccess(t *testing.T) {
	h := home(t)
	d := fakeMine(t, "exit 0")
	line := mineRun(t, h, transcript(t, "-work-user-projects-foo"))
	for _, w := range []string{`"event":"PreCompact"`, `"rule":"mine"`, `"wing":"foo"`, `"attempts":1`, `"result":"ok"`, `"session_id":"sess1"`, `"ts":"`} {
		if !strings.Contains(line, w) {
			t.Fatalf("missing %s in %s", w, line)
		}
	}
	if strings.Contains(line, "stderr_tail") || calls(d) != 1 {
		t.Fatalf("%s calls=%d", line, calls(d))
	}
}

func TestMineLockRetry(t *testing.T) {
	h := home(t)
	d := fakeMine(t, `[ "$n" -lt 3 ] && { echo "lock held by PID 42" >&2; exit 1; }; exit 0`)
	line := mineRun(t, h, transcript(t, "-work-user-projects-foo"))
	if !strings.Contains(line, `"attempts":3`) || !strings.Contains(line, `"result":"ok"`) || calls(d) != 3 {
		t.Fatalf("%s calls=%d", line, calls(d))
	}
}

func TestMineNonLockErrorNoRetry(t *testing.T) {
	h := home(t)
	d := fakeMine(t, `echo boom >&2; exit 1`)
	line := mineRun(t, h, transcript(t, "-work-user-projects-foo"))
	if !strings.Contains(line, `"attempts":1`) || !strings.Contains(line, `"result":"error"`) || !strings.Contains(line, `"stderr_tail":"boom"`) || calls(d) != 1 {
		t.Fatalf("%s calls=%d", line, calls(d))
	}
}

func TestMineLockExhausted(t *testing.T) {
	h := home(t)
	d := fakeMine(t, `echo "held by PID 1" >&2; exit 1`)
	line := mineRun(t, h, transcript(t, "-work-user-projects-foo"))
	if !strings.Contains(line, `"attempts":3`) || !strings.Contains(line, `"result":"error"`) || calls(d) != 3 {
		t.Fatalf("%s calls=%d", line, calls(d))
	}
}

func TestMineSkips(t *testing.T) {
	h := home(t)
	d := fakeMine(t, "exit 0")
	for _, tp := range []string{transcript(t, "-work-user-projects"), transcript(t, "other"), "/nonexistent/-work-user-projects-x/s.jsonl", ""} {
		if line := mineRun(t, h, tp); !strings.Contains(line, `"result":"skipped"`) || !strings.Contains(line, `"attempts":0`) {
			t.Fatalf("%q: %s", tp, line)
		}
	}
	// off, which is the default: with no policy.toml nothing is ever executed
	for _, body := range []string{"mine = false\n", ""} {
		if body == "" {
			os.Remove(filepath.Join(h, ".claude/policy.toml"))
		} else {
			minePolicy(t, body)
		}
		if line := mineRun(t, h, transcript(t, "-work-user-projects-foo")); !strings.Contains(line, `"result":"skipped"`) {
			t.Fatal(line)
		}
	}
	if calls(d) != 0 {
		t.Fatal("exec happened")
	}
}

func TestMineNoSleepAfterFinalAttempt(t *testing.T) {
	h := home(t)
	fakeMine(t, `echo "held by PID 1" >&2; exit 1`)
	mineBackoff = 300 * time.Millisecond // sleeps 0.3s + 0.6s; a trailing 0.9s sleep would exceed the bound
	start := time.Now()
	mineRun(t, h, transcript(t, "-work-user-projects-foo"))
	if el := time.Since(start); el > 1300*time.Millisecond {
		t.Fatalf("took %v", el)
	}
}
