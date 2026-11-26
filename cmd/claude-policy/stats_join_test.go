package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Two caps in the main transcript (one before a compaction, one after), one in
// a subagent transcript, one whose transcript is gone.
func TestStatsTokensJoin(t *testing.T) {
	d := statsDir(t)
	home := filepath.Dir(filepath.Dir(filepath.Dir(d)))
	proj := filepath.Join(home, ".claude", "projects", "-work-u-projects-x")
	os.MkdirAll(filepath.Join(proj, "sess1", "subagents"), 0o700)
	base := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	at := func(sec int) string { return base.Add(time.Duration(sec) * time.Second).UTC().Format(time.RFC3339Nano) }
	asst := func(sec int, req string) string {
		return `{"type":"assistant","timestamp":"` + at(sec) + `","requestId":"` + req + `","message":{"role":"assistant","id":"m` + req + `"}}`
	}
	boundary := `{"type":"system","subtype":"compact_boundary","timestamp":"` + at(50) + `","content":"Conversation compacted"}`
	// main: cap at 10s sees r2,r3 (r3 twice = one call) before the boundary at 50s; cap at 60s sees r4.
	os.WriteFile(filepath.Join(proj, "sess1.jsonl"), []byte(strings.Join([]string{
		asst(5, "r1"), `{"type":"user","timestamp":"` + at(6) + `","message":{"role":"user","content":[{"type":"tool_result","content":"` + strings.Repeat("x", 100) + `"}]}}`,
		asst(20, "r2"), asst(30, "r3"), asst(31, "r3"), boundary, asst(70, "r4"), "not json",
	}, "\n")+"\n"), 0o600)
	// subagent: cap at 10s sees a2,a3.
	os.WriteFile(filepath.Join(proj, "sess1", "subagents", "agent-ag1.jsonl"), []byte(strings.Join([]string{
		asst(1, "a1"), asst(20, "a2"), asst(40, "a3"),
	}, "\n")+"\n"), 0o600)
	cap := func(sec int, agent string, in, out int) string {
		a := ""
		if agent != "" {
			a = `"agent_id":"` + agent + `",`
		}
		return `{"ts":"` + at(sec) + `","session_id":"sess1",` + a + `"event":"PostToolUse","tool":"Bash","rule":"output_cap","mode":"enforce","ms":0,"us":5,"decision":{"reason":"Bash","chars_in":` + itoa(in) + `,"chars_out":` + itoa(out) + `}}`
	}
	gone := `{"ts":"` + at(10) + `","session_id":"gone","event":"PostToolUse","tool":"Bash","rule":"output_cap","mode":"enforce","ms":0,"us":5,"decision":{"reason":"Bash","chars_in":9000,"chars_out":8000}}`
	os.WriteFile(filepath.Join(d, "decisions.jsonl"), []byte(strings.Join([]string{
		cap(10, "", 10000, 2000),    // cut 8000 → 2000 tok × 2 calls = 4000
		cap(60, "", 8400, 8000),     // cut 400 → 100 tok × 1 call = 100
		cap(10, "ag1", 12000, 8000), // cut 4000 → 1000 tok × 2 calls = 2000
		gone,
	}, "\n")+"\n"), 0o600)

	code, out, _ := call(t, "", "stats", "--json")
	if code != 0 {
		t.Fatalf("code=%d\n%s", code, out)
	}
	var r Report
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatal(err)
	}
	o := r.OutputCap
	if o.TokensSaved == nil || *o.TokensSaved != 6100 {
		t.Fatalf("tokens_saved=%v want 6100", o.TokensSaved)
	}
	if o.Join != (TokensJoin{Caps: 4, Covered: 3, Missing: 1, CoveragePct: 75, LaterTurnsP50: 2, LaterTurnsMax: 2}) {
		t.Fatalf("join=%+v", o.Join)
	}
	_, text, _ := call(t, "", "stats")
	if !strings.Contains(text, "tokens saved: 6100 (") || !strings.Contains(text, "3/4 caps joined, 75.0%") {
		t.Fatalf("text:\n%s", text)
	}
	// --session narrows the join too.
	_, out, _ = call(t, "", "stats", "--json", "--session", "gone")
	json.Unmarshal([]byte(out), &r)
	if r.OutputCap.TokensSaved != nil || r.OutputCap.Join.Missing != 1 || r.OutputCap.Join.Covered != 0 || !strings.Contains(out, `"tokens_saved": null`) {
		t.Fatalf("session filter: %+v %v", r.OutputCap.Join, r.OutputCap.TokensSaved)
	}
}

// Ids with path elements never reach the filesystem.
func TestStatsJoinRejectsPathIDs(t *testing.T) {
	// Real files behind every pattern an unsafe id could reach, so a bad id that slips through is visible.
	p := t.TempDir()
	os.MkdirAll(filepath.Join(p, "slug", "s", "subagents"), 0o700)
	os.MkdirAll(filepath.Join(p, "subagents"), 0o700)
	line := []byte(`{"type":"assistant","timestamp":"2026-10-28T12:00:00Z","requestId":"r"}` + "\n")
	for _, f := range []string{"slug/s.jsonl", "slug/x.jsonl", "slug/s/subagents/agent-x.jsonl", "subagents/agent-x.jsonl"} {
		os.WriteFile(filepath.Join(p, f), line, 0o600)
	}
	if loadTranscript(p, "s", "") == nil || loadTranscript(p, "s", "x") == nil {
		t.Fatal("safe ids rejected")
	}
	for _, id := range []string{"../x", "s/../a", "", ".", "..", "*", "s?", "[a]", strings.Repeat("x", 129)} {
		// an empty agent is the main transcript, so "" is tested only as a session
		if loadTranscript(p, id, "") != nil || loadTranscript(p, id, "x") != nil || (id != "" && loadTranscript(p, "s", id) != nil) {
			t.Fatalf("id %q accepted", id)
		}
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
