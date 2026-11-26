package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLog(t *testing.T) {
	h := home(t)
	dir := filepath.Join(h, ".claude", "state", "policy")
	os.MkdirAll(dir, 0o700)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	old := time.Now().Add(-72 * time.Hour).UTC().Format(time.RFC3339Nano)
	os.WriteFile(filepath.Join(dir, "decisions.jsonl.1"), []byte(
		`{"ts":"`+old+`","event":"PreToolUse","tool":"Bash","rule":"destructive","mode":"log","decision":{"permission":"ask","reason":"old"}}`+"\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "decisions.jsonl"), []byte(strings.Join([]string{
		`{"ts":"` + now + `","agent_id":"a1","event":"PreToolUse","tool":"Bash","rule":"destructive","mode":"log","decision":{"permission":"deny","reason":"git push --force\nin subagent","hard":true}}`,
		`{"ts":"` + now + `","event":"Stop","rule":"risk_line","mode":"log","decision":{"block":true,"reason":"no Risk line"}}`,
		`{"ts":"` + now + `","event":"PreCompact","rule":"mine","result":"ok","attempts":1}`,
		`not json`,
	}, "\n")+"\n"), 0o600)

	code, out, _ := call(t, "", "log", "--rule", "destructive")
	if code != 0 || !strings.Contains(out, "PreToolUse/Bash main ask: old") ||
		!strings.Contains(out, "log destructive PreToolUse/Bash a1 deny(hard): git push --force in subagent") ||
		strings.Contains(out, "risk_line") || !strings.HasSuffix(out, "2 decisions\n") {
		t.Fatalf("code=%d out:\n%s", code, out)
	}
	if code, out, _ = call(t, "", "log", "--since", "1d"); code != 0 || strings.Contains(out, "old") ||
		!strings.Contains(out, "log risk_line Stop main block: no Risk line") || !strings.Contains(out, "- mine PreCompact main ok") ||
		!strings.HasSuffix(out, "3 decisions\n") {
		t.Fatalf("code=%d out:\n%s", code, out)
	}
	for _, bad := range [][]string{{"log", "--since", "xd"}, {"log", "--bogus"}, {"log", "extra"}} {
		if code, _, _ := call(t, "", bad...); code != 1 {
			t.Fatalf("%v: code=%d, want 1", bad, code)
		}
	}
}

// Timing fields are additive: old lines (no ms) and new lines print the same way.
func TestLogOldAndNewFormat(t *testing.T) {
	h := home(t)
	dir := filepath.Join(h, ".claude", "state", "policy")
	os.MkdirAll(dir, 0o700)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	os.WriteFile(filepath.Join(dir, "decisions.jsonl"), []byte(strings.Join([]string{
		`{"ts":"` + now + `","event":"PostToolUse","tool":"Bash","rule":"output_cap","mode":"log","decision":{"reason":"Bash 9000 → 8000 chars; log mode, no spill"}}`,
		`{"ts":"` + now + `","event":"PostToolUse","tool":"Bash","rule":"output_cap","mode":"log","ms":3,"decision":{"reason":"Bash 9000 → 8000 chars; log mode, no spill","chars_in":9000,"chars_out":8000}}`,
	}, "\n")+"\n"), 0o600)
	code, out, _ := call(t, "", "log")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if code != 0 || len(lines) != 3 || lines[0] != lines[1] || !strings.HasSuffix(out, "2 decisions\n") {
		t.Fatalf("code=%d out:\n%s", code, out)
	}
}
