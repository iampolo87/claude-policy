package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/iampolo87/claude-policy/internal/state"
)

// Report is the whole `stats` output; --json marshals it as is.
type Report struct {
	Files      []FileStat           `json:"files"`
	Hook       HookStat             `json:"hook"`
	Decisions  int                  `json:"decisions"`
	Malformed  int                  `json:"malformed"`
	Rules      map[string]*RuleStat `json:"rules"`
	OutputCap  OutputCapStat        `json:"output_cap"`
	Checkpoint CheckpointStat       `json:"checkpoint"`
	Mine       map[string]int       `json:"mine"`
}

type FileStat struct {
	Path      string `json:"path"`
	Lines     int    `json:"lines"`
	Malformed int    `json:"malformed"`
	First     string `json:"first_ts"`
	Last      string `json:"last_ts"`
}

// Latency: nearest-rank percentiles over n samples (µs); zeros when n == 0.
type Latency struct {
	N   int   `json:"n"`
	P50 int64 `json:"p50"`
	P95 int64 `json:"p95"`
	Max int64 `json:"max"`
}

type HookStat struct {
	Calls       int                `json:"calls"`
	Main        int                `json:"main"`
	Subagent    int                `json:"subagent"`
	WindowFirst string             `json:"window_first"`
	WindowLast  string             `json:"window_last"`
	Days        float64            `json:"days"`
	CallsPerDay float64            `json:"calls_per_day"`
	Events      map[string]Latency `json:"events"` // total_us per event
}

type Actors struct {
	Main     int `json:"main"`
	Subagent int `json:"subagent"`
}

type ReasonCount struct {
	Reason string `json:"reason"`
	N      int    `json:"n"`
}

type RuleStat struct {
	Modes     []string          `json:"modes"`
	Fires     map[string]Actors `json:"fires"`
	Silent    int               `json:"silent"`
	Latency   Latency           `json:"latency_us"`
	Decisions int               `json:"decisions"`
	WouldDeny int               `json:"would_deny"`
	Hard      int               `json:"hard"`
	Errors    int               `json:"errors"`
	Untimed   int               `json:"untimed"`
	Reasons   []ReasonCount     `json:"reasons,omitempty"`
}

type ToolCap struct {
	Caps        int   `json:"caps"`
	CharsIn     int64 `json:"chars_in"`
	CharsOut    int64 `json:"chars_out"`
	CharsCut    int64 `json:"chars_cut"`
	ReadLogOnly int   `json:"read_log_only"`
	LogWouldCap int   `json:"log_would_cap"`
	Errors      int   `json:"errors"`
}

type OutputCapStat struct {
	Tools                map[string]*ToolCap `json:"tools"`
	Total                ToolCap             `json:"total"`
	LinesFromFields      int                 `json:"lines_from_fields"`
	LinesFromReason      int                 `json:"lines_from_reason"`
	Days                 float64             `json:"days"`
	CapsPerWeek          float64             `json:"caps_per_week"`
	CharsCutPerWeek      float64             `json:"chars_cut_per_week"`
	BaselineCharsPerWeek float64             `json:"baseline_chars_per_week"`
	BaselineResultsWeek  float64             `json:"baseline_results_per_week"`
	CutRatio             float64             `json:"chars_cut_ratio"`
	TokensSaved          *int64              `json:"tokens_saved"` // nil until a transcript was joined
	Join                 TokensJoin          `json:"tokens_join"`
}

type CheckpointStat struct {
	PrecompactWrites          int `json:"precompact_writes"`
	CompactInjects            int `json:"compact_injects"`
	CompactMisses             int `json:"compact_misses"`
	Postcompact               int `json:"postcompact"`
	PostcompactMissingAnchors int `json:"postcompact_missing_anchors"`
}

type mRule struct {
	Name    string `json:"name"`
	Mode    string `json:"mode"`
	Us      *int64 `json:"us"`
	Verdict string `json:"verdict"`
}

type mLine struct {
	TS      string  `json:"ts"`
	Session string  `json:"session_id"`
	Agent   string  `json:"agent_id"`
	Event   string  `json:"event"`
	TotalMs *int64  `json:"total_ms"`
	TotalUs *int64  `json:"total_us"`
	Rules   []mRule `json:"rules"`
}

type dDecision struct {
	Permission string `json:"permission"`
	Reason     string `json:"reason"`
	Context    string `json:"additional_context"`
	Block      bool   `json:"block"`
	Hard       bool   `json:"hard"`
	CharsIn    int64  `json:"chars_in"`
	CharsOut   int64  `json:"chars_out"`
}

type dLine struct {
	TS       string     `json:"ts"`
	Session  string     `json:"session_id"`
	Agent    string     `json:"agent_id"`
	Event    string     `json:"event"`
	Tool     string     `json:"tool"`
	Rule     string     `json:"rule"`
	Mode     string     `json:"mode"`
	Error    string     `json:"error"`
	Result   string     `json:"result"`
	Ms       *int64     `json:"ms"`
	Us       *int64     `json:"us"`
	Decision *dDecision `json:"decision"`
}

const defaultBaseline = "15800000/290/30"

// runStats streams metrics.jsonl* and decisions.jsonl* once each and prints
// the report. --session is an exact session_id match.
func runStats(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("stats", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: claude-policy stats [--since 7d] [--rule R] [--session ID (exact)] [--json] [--baseline chars/results/days]")
	}
	since := fs.String("since", "", "only lines newer than this (e.g. 90m, 7d)")
	rule := fs.String("rule", "", "restrict rules, output_cap, checkpoint and mine to this rule; adds top reasons")
	session := fs.String("session", "", "exact session_id")
	asJSON := fs.Bool("json", false, "machine-readable output")
	baseline := fs.String("baseline", defaultBaseline, "oversized-result baseline: chars/results/days")
	if fs.Parse(args) != nil || fs.NArg() > 0 {
		fs.Usage()
		return 1
	}
	bp := strings.Split(*baseline, "/")
	var bv [3]float64
	for i := range bv {
		var err error
		if len(bp) != 3 {
			err = fmt.Errorf("want chars/results/days")
		} else if bv[i], err = strconv.ParseFloat(bp[i], 64); err == nil && !(bv[i] > 0 && !math.IsInf(bv[i], 0)) {
			err = fmt.Errorf("must be a finite number > 0")
		}
		if err != nil {
			fmt.Fprintf(stderr, "--baseline %q: %v\n", *baseline, err)
			return 1
		}
	}
	s := &statsScan{rule: *rule, session: *session, now: time.Now(), samples: map[string][]int64{}, evSamples: map[string][]int64{},
		rep: &Report{Files: []FileStat{}, Hook: HookStat{Events: map[string]Latency{}}, Rules: map[string]*RuleStat{}, Mine: map[string]int{},
			OutputCap: OutputCapStat{Tools: map[string]*ToolCap{}}}, reasons: map[string]int{}}
	if *since != "" {
		d, err := parseSince(*since)
		if err != nil {
			fmt.Fprintf(stderr, "--since: %v\n", err)
			return 1
		}
		s.cutoff = s.now.Add(-d)
	}
	root, err := state.Root()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	s.scanFiles(root, "metrics.jsonl", s.metric)
	s.scanFiles(root, "decisions.jsonl", s.decision)
	rep := s.finish(bv)
	joinTranscripts(filepath.Join(filepath.Dir(filepath.Dir(root)), "projects"), s.caps, &rep.OutputCap)
	if *asJSON {
		b, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintf(stdout, "%s\n", b)
		return 0
	}
	printStats(stdout, rep, *rule)
	return 0
}

type statsScan struct {
	rule, session string
	cutoff, now   time.Time
	rep           *Report
	samples       map[string][]int64 // rule -> us
	evSamples     map[string][]int64 // event -> total_us
	reasons       map[string]int
	firstT, lastT time.Time // metrics
	dFirst, dLast time.Time // decisions
	dT            time.Time // current decision line
	caps          []capEvent
	m             mLine
	d             dLine
}

func (s *statsScan) want(rule string) bool { return s.rule == "" || s.rule == rule }

// scanFiles reads base.N … base.1, base (oldest first); stops at the first missing N.
func (s *statsScan) scanFiles(root, base string, each func([]byte) (string, bool)) {
	names := []string{base}
	for n := 1; n <= 100; n++ {
		if _, err := os.Stat(filepath.Join(root, base+"."+strconv.Itoa(n))); err != nil {
			break
		}
		names = append([]string{base + "." + strconv.Itoa(n)}, names...)
	}
	for _, name := range names {
		f, err := os.Open(filepath.Join(root, name))
		if err != nil {
			continue
		}
		fst := FileStat{Path: name}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
		for sc.Scan() {
			b := sc.Bytes()
			if len(bytes.TrimSpace(b)) == 0 {
				continue
			}
			fst.Lines++
			ts, ok := each(b)
			if !ok {
				fst.Malformed++
				continue
			}
			if fst.First == "" {
				fst.First = ts
			}
			fst.Last = ts
		}
		if sc.Err() != nil { // an over-long line ends the file early: report it, do not hide it
			fst.Malformed++
		}
		f.Close()
		s.rep.Malformed += fst.Malformed
		s.rep.Files = append(s.rep.Files, fst)
	}
}

func (s *statsScan) keep(session string, t time.Time) bool {
	return !t.Before(s.cutoff) && (s.session == "" || s.session == session)
}

func (s *statsScan) ruleRow(name string) *RuleStat {
	r := s.rep.Rules[name]
	if r == nil {
		r = &RuleStat{Fires: map[string]Actors{}}
		s.rep.Rules[name] = r
	}
	return r
}

func (s *statsScan) metric(b []byte) (string, bool) {
	m := &s.m
	*m = mLine{Rules: m.Rules[:0]}
	if json.Unmarshal(b, m) != nil {
		return "", false
	}
	t, err := time.Parse(time.RFC3339Nano, m.TS)
	if err != nil {
		return "", false
	}
	if !s.keep(m.Session, t) {
		return m.TS, true
	}
	if s.firstT.IsZero() || t.Before(s.firstT) {
		s.firstT = t
	}
	if t.After(s.lastT) {
		s.lastT = t
	}
	h := &s.rep.Hook
	h.Calls++
	sub := m.Agent != ""
	if sub {
		h.Subagent++
	} else {
		h.Main++
	}
	switch { // a line without timing is not a 0 µs sample
	case m.TotalUs != nil:
		s.evSamples[m.Event] = append(s.evSamples[m.Event], *m.TotalUs)
	case m.TotalMs != nil:
		s.evSamples[m.Event] = append(s.evSamples[m.Event], *m.TotalMs*1000)
	}
	for i := range m.Rules {
		r := &m.Rules[i]
		if !s.want(r.Name) {
			continue
		}
		if m.Event == "PreCompact" && !sub && r.Name == "checkpoint" && r.Verdict != "error" {
			s.rep.Checkpoint.PrecompactWrites++
		}
		row := s.ruleRow(r.Name)
		if r.Mode != "" && !slices.Contains(row.Modes, r.Mode) {
			row.Modes = append(row.Modes, r.Mode)
		}
		if r.Us != nil {
			s.samples[r.Name] = append(s.samples[r.Name], *r.Us)
		} else {
			row.Untimed++
		}
		if r.Verdict == "none" || r.Verdict == "" {
			row.Silent++
			continue
		}
		a := row.Fires[r.Verdict]
		if sub {
			a.Subagent++
		} else {
			a.Main++
		}
		row.Fires[r.Verdict] = a
	}
	return m.TS, true
}

func (s *statsScan) decision(b []byte) (string, bool) {
	l := &s.d
	*l = dLine{}
	if json.Unmarshal(b, l) != nil {
		return "", false
	}
	t, err := time.Parse(time.RFC3339Nano, l.TS)
	if err != nil {
		return "", false
	}
	if !s.keep(l.Session, t) {
		return l.TS, true
	}
	s.dT = t
	if s.dFirst.IsZero() || t.Before(s.dFirst) {
		s.dFirst = t
	}
	if t.After(s.dLast) {
		s.dLast = t
	}
	s.rep.Decisions++
	if !s.want(l.Rule) {
		return l.TS, true
	}
	d := l.Decision
	row := s.ruleRow(l.Rule)
	row.Decisions++
	if l.Error != "" {
		row.Errors++
	}
	if d != nil {
		if l.Ms == nil && l.Us == nil { // line from before timings were logged; rule-written lines (error, result) never carry timing
			row.Untimed++
		}
		if d.Hard {
			row.Hard++
		}
		// What an enforce flip would have changed: hard decisions already applied in log mode.
		if l.Mode == "log" && !d.Hard && (d.Permission == "ask" || d.Permission == "deny" || d.Block) {
			row.WouldDeny++
		}
	}
	if s.rule != "" {
		txt := l.Error
		if d != nil && d.Reason != "" {
			txt = d.Reason
		} else if d != nil && d.Context != "" {
			txt = d.Context
		}
		if txt != "" {
			s.reasons[normReason(txt)]++
		}
	}
	switch l.Rule {
	case "output_cap":
		s.outputCap(l, d)
	case "checkpoint":
		s.checkpoint(l, d)
	case "mine":
		r := l.Result
		if r == "" {
			r = "(none)"
		}
		s.rep.Mine[r]++
	}
	return l.TS, true
}

func normReason(t string) string {
	t = strings.Join(strings.Fields(t), " ")
	if r := []rune(t); len(r) > 120 {
		t = string(r[:120])
	}
	var sb strings.Builder
	for i := 0; i < len(t); i++ {
		if t[i] >= '0' && t[i] <= '9' {
			for i+1 < len(t) && t[i+1] >= '0' && t[i+1] <= '9' {
				i++
			}
			sb.WriteByte('N')
			continue
		}
		sb.WriteByte(t[i])
	}
	return sb.String()
}

func toolGroup(tool string) string {
	if rest, ok := strings.CutPrefix(tool, "mcp__"); ok {
		srv, _, _ := strings.Cut(rest, "__")
		return "mcp__" + srv
	}
	return tool
}

// reasonChars parses "<Tool> N → M chars" (lines written before chars_in/out existed).
func reasonChars(reason string) (in, out int64, ok bool) {
	l, r, found := strings.Cut(reason, " → ")
	if !found {
		return
	}
	lf, rf := strings.Fields(l), strings.Fields(r)
	if len(lf) == 0 || len(rf) == 0 {
		return
	}
	var e1, e2 error
	in, e1 = strconv.ParseInt(lf[len(lf)-1], 10, 64)
	out, e2 = strconv.ParseInt(rf[0], 10, 64)
	return in, out, e1 == nil && e2 == nil
}

func (s *statsScan) outputCap(l *dLine, d *dDecision) {
	g := toolGroup(l.Tool)
	tc := s.rep.OutputCap.Tools[g]
	if tc == nil {
		tc = &ToolCap{}
		s.rep.OutputCap.Tools[g] = tc
	}
	if l.Error != "" {
		tc.Errors++
	}
	// Read is log-only whatever the mode: enforce-mode lines say "read log-only: N chars".
	readOnly := d != nil && strings.HasPrefix(d.Reason, "read log-only")
	switch l.Mode {
	case "log":
		tc.LogWouldCap++
		if l.Tool == "Read" || readOnly {
			tc.ReadLogOnly++
		}
	case "enforce":
		if readOnly {
			tc.ReadLogOnly++
			return
		}
		in, out, ok := int64(0), int64(0), false
		if d != nil && d.CharsIn > 0 {
			in, out, ok = d.CharsIn, d.CharsOut, true
			s.rep.OutputCap.LinesFromFields++
		} else if d != nil {
			if in, out, ok = reasonChars(d.Reason); ok {
				s.rep.OutputCap.LinesFromReason++
			}
		}
		tc.Caps++
		if ok {
			tc.CharsIn += in
			tc.CharsOut += out
			tc.CharsCut += in - out
			s.caps = append(s.caps, capEvent{l.Session, l.Agent, s.dT, in - out})
		}
	}
}

func (s *statsScan) checkpoint(l *dLine, d *dDecision) {
	c := &s.rep.Checkpoint
	switch l.Event {
	case "SessionStart":
		if d != nil && strings.HasPrefix(d.Context, "(private, ") {
			c.CompactInjects++
		} else {
			c.CompactMisses++
		}
	case "PostCompact":
		if l.Result == "" {
			return
		}
		c.Postcompact++
		if _, rest, ok := strings.Cut(l.Result, "missing "); ok { // "missing N" or "missing N: a, b"
			end := strings.IndexFunc(rest, func(r rune) bool { return r < '0' || r > '9' })
			if end < 0 {
				end = len(rest)
			}
			if n, err := strconv.Atoi(rest[:end]); err == nil {
				c.PostcompactMissingAnchors += n
			}
		}
	}
}

// latency sorts v in place; nearest-rank percentiles.
func latency(v []int64) Latency {
	if len(v) == 0 {
		return Latency{}
	}
	slices.Sort(v)
	rank := func(p int) int64 { return v[(p*len(v)+99)/100-1] }
	return Latency{N: len(v), P50: rank(50), P95: rank(95), Max: v[len(v)-1]}
}

func (s *statsScan) finish(bv [3]float64) *Report {
	r := s.rep
	h := &r.Hook
	first, last := s.firstT, s.lastT
	if h.Calls == 0 {
		first, last = s.dFirst, s.dLast
	}
	if !first.IsZero() {
		h.WindowFirst, h.WindowLast = first.UTC().Format(time.RFC3339), last.UTC().Format(time.RFC3339)
	}
	h.Days = windowDays(first, last)
	h.CallsPerDay = float64(h.Calls) / h.Days
	for ev, v := range s.evSamples {
		h.Events[ev] = latency(v)
	}
	for name, row := range r.Rules {
		row.Latency = latency(s.samples[name])
		if row.Modes == nil {
			row.Modes = []string{}
		}
		if name == s.rule {
			for k, n := range s.reasons {
				row.Reasons = append(row.Reasons, ReasonCount{k, n})
			}
			slices.SortFunc(row.Reasons, func(a, b ReasonCount) int {
				if a.N != b.N {
					return b.N - a.N
				}
				return strings.Compare(a.Reason, b.Reason)
			})
			if len(row.Reasons) > 10 {
				row.Reasons = row.Reasons[:10]
			}
		}
	}
	o := &r.OutputCap
	for _, tc := range o.Tools {
		o.Total.Caps += tc.Caps
		o.Total.CharsIn += tc.CharsIn
		o.Total.CharsOut += tc.CharsOut
		o.Total.CharsCut += tc.CharsCut
		o.Total.ReadLogOnly += tc.ReadLogOnly
		o.Total.LogWouldCap += tc.LogWouldCap
		o.Total.Errors += tc.Errors
	}
	o.Days = windowDays(s.dFirst, s.dLast) // caps come from decisions, which span differently from metrics
	o.CapsPerWeek = float64(o.Total.Caps) * 7 / o.Days
	o.CharsCutPerWeek = float64(o.Total.CharsCut) * 7 / o.Days
	o.BaselineCharsPerWeek = bv[0] * 7 / bv[2]
	o.BaselineResultsWeek = bv[1] * 7 / bv[2]
	o.CutRatio = o.CharsCutPerWeek / o.BaselineCharsPerWeek
	return r
}

// windowDays is the span of the lines actually seen (after --since/--session),
// floored at one hour so per-day rates stay finite for a one-line window.
func windowDays(first, last time.Time) float64 {
	return max(time.Hour, last.Sub(first)).Hours() / 24
}

func dash(n int, v int64) string {
	if n == 0 {
		return "-"
	}
	return strconv.FormatInt(v, 10)
}

func printStats(w io.Writer, r *Report, rule string) {
	h := r.Hook
	first, last := h.WindowFirst, h.WindowLast
	if first == "" {
		first, last = "-", "-"
	}
	fmt.Fprintf(w, "stats: %d hook calls, %d decisions, %d malformed, window %s..%s (%.1f d)\n", h.Calls, r.Decisions, r.Malformed, first, last, h.Days)
	if h.Calls == 0 && r.Decisions == 0 {
		fmt.Fprintln(w, "no data")
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	section := func(name string) { tw.Flush(); fmt.Fprintf(w, "\n== %s ==\n", name) }

	section("files")
	fmt.Fprintln(tw, "path\tlines\tmalformed\tfirst\tlast")
	for _, f := range r.Files {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%s\t%s\n", f.Path, f.Lines, f.Malformed, f.First, f.Last)
	}

	section("hook")
	fmt.Fprintf(w, "calls %d (main %d, subagent %d), %.1f calls/day\n", h.Calls, h.Main, h.Subagent, h.CallsPerDay)
	fmt.Fprintln(tw, "event\tcalls\tp50_us\tp95_us\tmax_us")
	for _, ev := range sortedKeys(h.Events) {
		l := h.Events[ev]
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\n", ev, l.N, dash(l.N, l.P50), dash(l.N, l.P95), dash(l.N, l.Max))
	}

	names := sortedKeys(r.Rules)
	section("rules")
	fmt.Fprintln(tw, "rule\tmodes\truns\tsilent\tp50_us\tp95_us\tmax_us\tdecisions\twould_deny\thard\terrors\tuntimed")
	for _, n := range names {
		x := r.Rules[n]
		l := x.Latency
		fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\n", n, strings.Join(x.Modes, "→"), l.N, x.Silent,
			dash(l.N, l.P50), dash(l.N, l.P95), dash(l.N, l.Max), x.Decisions, x.WouldDeny, x.Hard, x.Errors, x.Untimed)
	}
	section("rules: fires by verdict (main/subagent)")
	fmt.Fprintln(tw, "rule\tverdict\tmain\tsubagent")
	for _, n := range names {
		for _, v := range sortedKeys(r.Rules[n].Fires) {
			a := r.Rules[n].Fires[v]
			fmt.Fprintf(tw, "%s\t%s\t%d\t%d\n", n, v, a.Main, a.Subagent)
		}
	}
	if x := r.Rules[rule]; rule != "" && x != nil {
		section("top reasons: " + rule)
		for _, rc := range x.Reasons {
			fmt.Fprintf(tw, "%d\t%s\n", rc.N, rc.Reason)
		}
	}

	o := r.OutputCap
	section("output_cap")
	fmt.Fprintln(tw, "tool\tcaps\tchars_in\tchars_out\tchars_cut\tread_log_only\tlog_would_cap\terrors")
	row := func(n string, t ToolCap) {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n", n, t.Caps, t.CharsIn, t.CharsOut, t.CharsCut, t.ReadLogOnly, t.LogWouldCap, t.Errors)
	}
	for _, n := range sortedKeys(o.Tools) {
		row(n, *o.Tools[n])
	}
	row("TOTAL", o.Total)
	tw.Flush()
	fmt.Fprintf(w, "lines: %d from fields, %d parsed from reason\n", o.LinesFromFields, o.LinesFromReason)
	fmt.Fprintf(w, "per week over %.1f d: %.1f caps, %.0f chars cut; baseline %.0f chars, %.1f results; ratio %.4f\n",
		o.Days, o.CapsPerWeek, o.CharsCutPerWeek, o.BaselineCharsPerWeek, o.BaselineResultsWeek, o.CutRatio)
	switch {
	case o.Join.Caps == 0:
		fmt.Fprintln(w, "tokens saved: n/a (no caps)")
	case o.TokensSaved == nil:
		fmt.Fprintf(w, "tokens saved: n/a (no transcript found for %d caps)\n", o.Join.Caps)
	default:
		fmt.Fprintf(w, "tokens saved: %d (chars_cut/4 x later API calls before the next compaction; %d/%d caps joined, %.1f%%; later calls p50 %d max %d)\n",
			*o.TokensSaved, o.Join.Covered, o.Join.Caps, o.Join.CoveragePct, o.Join.LaterTurnsP50, o.Join.LaterTurnsMax)
	}

	c := r.Checkpoint
	section("checkpoint")
	fmt.Fprintf(w, "precompact_writes %d, compact_injects %d, compact_misses %d, postcompact %d, postcompact_missing_anchors %d\n",
		c.PrecompactWrites, c.CompactInjects, c.CompactMisses, c.Postcompact, c.PostcompactMissingAnchors)

	section("mine")
	for _, k := range sortedKeys(r.Mine) {
		fmt.Fprintf(tw, "%s\t%d\n", k, r.Mine[k])
	}
	tw.Flush()
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}
