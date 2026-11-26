package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func statsDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(home(t), ".claude", "state", "policy")
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func statsFixtures(t *testing.T) {
	t.Helper()
	d := statsDir(t)
	for _, n := range []string{"metrics.jsonl", "metrics.jsonl.1", "decisions.jsonl", "decisions.jsonl.1"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "stats", n))
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(d, n), b, 0o600)
	}
}

func statsJSON(t *testing.T, args ...string) Report {
	t.Helper()
	code, out, errs := call(t, "", append([]string{"stats", "--json"}, args...)...)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errs)
	}
	var r Report
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return r
}

// Expected constants were computed once with jq over the fixtures
// (jq -R 'fromjson? // empty' to skip malformed lines) and pasted here.
func TestStatsFixtures(t *testing.T) {
	statsFixtures(t)
	r := statsJSON(t)
	h := r.Hook
	if h.Calls != 3070 || h.Main != 2300 || h.Subagent != 770 || r.Decisions != 398 {
		t.Fatalf("hook %+v decisions %d", h, r.Decisions)
	}
	mal := map[string]int{}
	for _, f := range r.Files {
		mal[strings.SplitN(f.Path, ".", 2)[0]] += f.Malformed
	}
	// decisions.jsonl also ends with an empty line, which must not count.
	if mal["metrics"] != 1 || mal["decisions"] != 2 || r.Malformed != 3 || len(r.Files) != 4 {
		t.Fatalf("malformed %v total %d files %d", mal, r.Malformed, len(r.Files))
	}
	if r.Files[0].Path != "metrics.jsonl.1" || r.Files[1].Path != "metrics.jsonl" {
		t.Fatalf("order: %+v", r.Files)
	}
	d := r.Rules["destructive"]
	if d.Latency.N != 356 || d.Silent != 316 || d.Decisions != 60 || d.WouldDeny != 59 || d.Untimed != 16 || d.Hard != 1 ||
		d.Fires["ask"].Main != 28 || d.Fires["ask"].Subagent != 8 || d.Fires["deny"].Subagent != 4 {
		t.Fatalf("destructive %+v", d)
	}
	if m := r.Rules["sensitive_paths"].Modes; !reflect.DeepEqual(m, []string{"log", "enforce"}) {
		t.Fatalf("modes %v", m)
	}
	o := r.OutputCap
	if o.Total.Caps != 50 || o.Total.CharsCut != 175077 || o.Total.ReadLogOnly != 10 || o.LinesFromFields != 23 || o.LinesFromReason != 27 ||
		o.Tools["Bash"].Caps != 49 || o.Tools["mcp__plugin_claude-mem_mcp-search"].Caps != 1 || o.TokensSaved != nil {
		t.Fatalf("output_cap %+v", o)
	}
	c := r.Checkpoint
	if c.PrecompactWrites != 29 || c.CompactInjects+c.CompactMisses != 24 || c.CompactInjects != 24 || c.Postcompact != 24 || c.PostcompactMissingAnchors != 67 {
		t.Fatalf("checkpoint %+v", c)
	}
	if r.Mine["ok"] == 0 && len(r.Mine) == 0 {
		t.Fatalf("mine %v", r.Mine)
	}
	n := 0
	for _, v := range r.Mine {
		n += v
	}
	if n != 37 || r.Rules["mine"].Decisions != 37 {
		t.Fatalf("mine %v", r.Mine)
	}

	// text report carries the same numbers
	code, out, _ := call(t, "", "stats")
	if code != 0 || !strings.HasPrefix(out, "stats: 3070 hook calls, 398 decisions, 3 malformed, window ") ||
		!strings.Contains(out, "tokens saved: n/a (no transcript found for 50 caps)") || !strings.Contains(out, "destructive") {
		t.Fatalf("code=%d\n%s", code, out)
	}
}

func TestStatsPercentiles(t *testing.T) {
	if l := latency([]int64{4, 1, 3, 2}); l.P50 != 2 || l.P95 != 4 || l.Max != 4 || l.N != 4 {
		t.Fatalf("%+v", l)
	}
	if l := latency(nil); l != (Latency{}) {
		t.Fatalf("%+v", l)
	}
}

func TestStatsJSONRoundTrip(t *testing.T) {
	statsFixtures(t)
	_, out, _ := call(t, "", "stats", "--json")
	var r Report
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatal(err)
	}
	b, _ := json.MarshalIndent(r, "", "  ")
	if string(b)+"\n" != out {
		t.Fatalf("round trip differs")
	}
	var again Report
	json.Unmarshal(b, &again)
	if !reflect.DeepEqual(r, again) || !strings.Contains(out, `"tokens_saved": null`) {
		t.Fatal("DeepEqual failed or tokens_saved not null")
	}
}

func TestStatsSince(t *testing.T) {
	d := statsDir(t)
	old := time.Now().Add(-72 * time.Hour).UTC().Format(time.RFC3339Nano)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	m := func(ts, ev string) string {
		return `{"ts":"` + ts + `","session_id":"s","event":"` + ev + `","total_ms":0,"total_us":10,"rules":[{"name":"checkpoint","mode":"enforce","ms":0,"us":5,"verdict":"none"}]}` + "\n"
	}
	os.WriteFile(filepath.Join(d, "metrics.jsonl"), []byte(m(old, "Stop")+m(now, "Stop")), 0o600)
	os.WriteFile(filepath.Join(d, "decisions.jsonl"), []byte(
		`{"ts":"`+old+`","session_id":"s","event":"Stop","rule":"risk_line","mode":"log","decision":{"block":true}}`+"\n"+
			`{"ts":"`+now+`","session_id":"s","event":"Stop","rule":"risk_line","mode":"log","decision":{"block":true}}`+"\n"), 0o600)
	if r := statsJSON(t); r.Hook.Calls != 2 || r.Decisions != 2 || r.Hook.Days < 2.9 {
		t.Fatalf("all: %+v %d", r.Hook, r.Decisions)
	}
	r := statsJSON(t, "--since", "1d")
	if r.Hook.Calls != 1 || r.Decisions != 1 || r.Rules["risk_line"].WouldDeny != 1 || r.Hook.Days != 1.0/24 {
		t.Fatalf("since: %+v %d", r.Hook, r.Decisions)
	}
}

func TestStatsFilters(t *testing.T) {
	statsFixtures(t)
	r := statsJSON(t, "--rule", "destructive")
	if len(r.Rules) != 1 || r.Rules["destructive"] == nil || len(r.Rules["destructive"].Reasons) == 0 || len(r.Rules["destructive"].Reasons) > 10 ||
		r.OutputCap.Total.Caps != 0 || r.Checkpoint.PrecompactWrites != 0 || r.Hook.Calls != 3070 {
		t.Fatalf("rule filter: %+v", r.Rules)
	}
	for _, rc := range r.Rules["destructive"].Reasons {
		if len([]rune(rc.Reason)) > 120 || strings.ContainsAny(rc.Reason, "0123456789") {
			t.Fatalf("reason not normalised: %q", rc.Reason)
		}
	}
	if r := statsJSON(t, "--rule", "output_cap"); r.OutputCap.Total.Caps != 50 || len(r.Rules) != 1 {
		t.Fatalf("output_cap filter: %+v", r.OutputCap.Total)
	}
	r = statsJSON(t, "--session", "00000000-0000-4000-8000-000000000034")
	if r.Hook.Calls != 43 {
		t.Fatalf("session: %d", r.Hook.Calls)
	}
	if r = statsJSON(t, "--session", "00000000-0000-4000-8000-0000000000"); r.Hook.Calls != 0 { // exact, not prefix
		t.Fatalf("session prefix matched: %d", r.Hook.Calls)
	}
	if code, out, _ := call(t, "", "stats", "--rule", "destructive"); code != 0 || !strings.Contains(out, "top reasons: destructive") {
		t.Fatalf("code=%d\n%s", code, out)
	}
}

func TestStatsBaselineAndErrors(t *testing.T) {
	statsFixtures(t)
	o := statsJSON(t, "--baseline", "700/70/7").OutputCap
	if o.BaselineCharsPerWeek != 700 || o.BaselineResultsWeek != 70 {
		t.Fatalf("%+v", o)
	}
	for _, bad := range [][]string{{"--bogus"}, {"extra"}, {"--since", "xd"}, {"--baseline", "1/2"}, {"--baseline", "a/b/c"}, {"--baseline", "1/2/0"}} {
		if code, _, errs := call(t, "", append([]string{"stats"}, bad...)...); code != 1 || errs == "" {
			t.Fatalf("%v: code=%d stderr=%q", bad, code, errs)
		}
	}
}

func TestStatsNoFiles(t *testing.T) {
	home(t)
	code, out, _ := call(t, "", "stats")
	if code != 0 || !strings.Contains(out, "stats: 0 hook calls, 0 decisions, 0 malformed") || !strings.Contains(out, "no data") {
		t.Fatalf("code=%d\n%s", code, out)
	}
	if r := statsJSON(t); r.Hook.Calls != 0 || len(r.Files) != 0 || r.Hook.Days != 1.0/24 {
		t.Fatalf("%+v", r)
	}
}

func TestStatsReasonParsing(t *testing.T) {
	if in, out, ok := reasonChars("Bash 9832 → 8000 chars; spill /tmp/x"); !ok || in != 9832 || out != 8000 {
		t.Fatal(in, out, ok)
	}
	if _, _, ok := reasonChars("read log-only: 11293 chars"); ok {
		t.Fatal("parsed a log-only reason")
	}
	if g := toolGroup("mcp__chrome-devtools__take_snapshot"); g != "mcp__chrome-devtools" {
		t.Fatal(g)
	}
}

// writeMetrics fills 4 files (base + .1-.3) of ~10 MB with synthetic lines.
func writeMetrics(tb testing.TB, dir string) {
	tb.Helper()
	line := func(i int) string {
		ts := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano)
		ag := ""
		if i%3 == 0 {
			ag = `"agent_id":"a1",`
		}
		return fmt.Sprintf(`{"ts":"%s","session_id":"s%d",%s"event":"PreToolUse","tool":"Bash","total_ms":1,"total_us":%d,"rules":[{"name":"destructive","mode":"log","ms":0,"us":%d,"verdict":"none"},{"name":"sensitive_paths","mode":"enforce","ms":0,"us":%d,"verdict":"deny"},{"name":"loop_guard","mode":"enforce","ms":0,"us":%d,"verdict":"none"},{"name":"time_budget","mode":"enforce","ms":0,"us":40,"verdict":"none"}]}`,
			ts, i%160, ag, 1000+i%900, 100+i%50, 20+i%30, 400+i%70) + "\n"
	}
	n := 0
	for _, name := range []string{"metrics.jsonl.3", "metrics.jsonl.2", "metrics.jsonl.1", "metrics.jsonl"} {
		var buf bytes.Buffer
		for buf.Len() < 10<<20 {
			buf.WriteString(line(n))
			n++
		}
		if err := os.WriteFile(filepath.Join(dir, name), buf.Bytes(), 0o600); err != nil {
			tb.Fatal(err)
		}
	}
}

func TestStatsPerf(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("perf: timing is meaningless under -short or the race detector")
	}
	writeMetrics(t, statsDir(t))
	// best of three: one run alone also measures whatever else the machine is doing
	el := time.Hour
	for i := 0; i < 3 && el > time.Second; i++ {
		t0 := time.Now()
		code, out, _ := call(t, "", "stats")
		el = min(el, time.Since(t0))
		if code != 0 || !strings.Contains(out, "hook calls") {
			t.Fatalf("code=%d", code)
		}
	}
	t.Logf("4x10MB: %v", el)
	if el > time.Second {
		t.Fatalf("stats took %v, want < 1s", el)
	}
}

func BenchmarkStats(b *testing.B) {
	h := b.TempDir()
	b.Setenv("HOME", h)
	d := filepath.Join(h, ".claude", "state", "policy")
	os.MkdirAll(d, 0o700)
	writeMetrics(b, d)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var o, e bytes.Buffer
		run([]string{"stats"}, strings.NewReader(""), &o, &e)
	}
}

// The window is the span of the lines seen, not the --since span: three days
// of data under --since 30d is a 3-day window, per source.
func TestStatsWindowClampsToData(t *testing.T) {
	d := statsDir(t)
	at := func(h int) string {
		return time.Now().Add(-time.Duration(h) * time.Hour).UTC().Format(time.RFC3339Nano)
	}
	m := func(ts string) string {
		return `{"ts":"` + ts + `","session_id":"s","event":"Stop","total_ms":0,"total_us":10,"rules":[{"name":"risk_line","mode":"log","ms":0,"us":5,"verdict":"none"}]}` + "\n"
	}
	cap := func(ts string) string {
		return `{"ts":"` + ts + `","session_id":"s","event":"PostToolUse","tool":"Bash","rule":"output_cap","mode":"enforce","ms":0,"us":5,"decision":{"reason":"Bash","chars_in":9000,"chars_out":8000}}` + "\n"
	}
	os.WriteFile(filepath.Join(d, "metrics.jsonl"), []byte(m(at(72))+m(at(1))+m(at(0))), 0o600)
	os.WriteFile(filepath.Join(d, "decisions.jsonl"), []byte(cap(at(48))+cap(at(0))), 0o600)
	_, out, _ := call(t, "", "stats", "--since", "30d", "--json")
	var r Report
	json.Unmarshal([]byte(out), &r)
	if r.Hook.Days < 2.95 || r.Hook.Days > 3.05 || r.Hook.CallsPerDay < 0.9 || r.Hook.CallsPerDay > 1.1 {
		t.Fatalf("hook window: %+v", r.Hook)
	}
	if r.OutputCap.Days < 1.95 || r.OutputCap.Days > 2.05 || r.OutputCap.CapsPerWeek < 6.9 || r.OutputCap.CapsPerWeek > 7.1 {
		t.Fatalf("output_cap window: days=%v caps/week=%v", r.OutputCap.Days, r.OutputCap.CapsPerWeek)
	}
	// --since 1d keeps two metrics lines an hour apart: a 1 h window, floored at 1 h.
	_, out, _ = call(t, "", "stats", "--since", "1d", "--json")
	json.Unmarshal([]byte(out), &r)
	if r.Hook.Calls != 2 || r.Hook.Days < 0.04 || r.Hook.Days > 0.05 {
		t.Fatalf("1d window: %+v", r.Hook)
	}
}

// Hard decisions were applied in log mode, so they are not "would deny";
// metrics rule entries without us are untimed, not 0 µs; a negative --since is refused.
func TestStatsWouldDenyUntimedNegativeSince(t *testing.T) {
	d := statsDir(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	os.WriteFile(filepath.Join(d, "decisions.jsonl"), []byte(strings.Join([]string{
		`{"ts":"` + now + `","session_id":"s","event":"PreToolUse","tool":"Bash","rule":"destructive","mode":"log","ms":0,"us":5,"decision":{"permission":"deny","reason":"hard_deny mkfs","hard":true}}`,
		`{"ts":"` + now + `","session_id":"s","event":"PreToolUse","tool":"Bash","rule":"destructive","mode":"log","ms":0,"us":5,"decision":{"permission":"ask","reason":"git reset"}}`,
		`{"ts":"` + now + `","session_id":"s","event":"PostCompact","rule":"checkpoint","mode":"enforce","result":"summary 100 chars sha256:abc, anchors 3, missing 2: a.go, b.go"}`,
		`{"ts":"` + now + `","session_id":"s","event":"PreCompact","rule":"mine","result":"ok"}`,
	}, "\n")+"\n"), 0o600)
	os.WriteFile(filepath.Join(d, "metrics.jsonl"), []byte(
		`{"ts":"`+now+`","session_id":"s","event":"PreToolUse","tool":"Bash","total_ms":1,"rules":[{"name":"destructive","mode":"log","verdict":"ask"},{"name":"loop_guard","mode":"enforce","ms":0,"us":7,"verdict":"none"}]}`+"\n"), 0o600)
	r := statsJSON(t)
	dr := r.Rules["destructive"]
	if dr.WouldDeny != 1 || dr.Hard != 1 || dr.Untimed != 1 || dr.Latency.N != 0 || r.Rules["loop_guard"].Latency.N != 1 || r.Rules["loop_guard"].Untimed != 0 {
		t.Fatalf("destructive=%+v loop_guard=%+v", dr, r.Rules["loop_guard"])
	}
	if r.Rules["mine"].Untimed != 0 || r.Rules["checkpoint"].Untimed != 0 || r.Checkpoint.PostcompactMissingAnchors != 2 {
		t.Fatalf("untimed/anchors: mine=%+v checkpoint=%+v %+v", r.Rules["mine"], r.Rules["checkpoint"], r.Checkpoint)
	}
	if ev := r.Hook.Events["PreToolUse"]; ev.N != 1 || ev.P50 != 1000 {
		t.Fatalf("total_ms fallback: %+v", ev)
	}
	if code, _, _ := call(t, "", "stats", "--since", "-5h"); code != 1 {
		t.Fatal("negative --since accepted")
	}
	if code, _, _ := call(t, "", "stats", "--baseline", "NaN/1/1"); code != 1 {
		t.Fatal("NaN baseline accepted")
	}
}
