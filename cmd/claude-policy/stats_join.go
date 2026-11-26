package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/iampolo87/claude-policy/internal/state"
)

// capEvent is one enforce-mode output_cap decision: what was cut, where.
type capEvent struct {
	Session, Agent string
	T              time.Time
	Cut            int64
}

// TokensJoin is the transcript join behind tokens_saved. Formula:
// for every enforce cap, chars_cut ÷ 4 × the number of later API calls in the
// same transcript (distinct assistant requestIds after the cap and before the
// next compact_boundary or compaction summary, which drops the result from context). Main-agent caps
// join ~/.claude/projects/*/<session_id>.jsonl, subagent caps
// ~/.claude/projects/*/<session_id>/subagents/agent-<agent_id>.jsonl. A cap
// whose transcript is gone counts as missing and contributes nothing.
type TokensJoin struct {
	Caps          int     `json:"caps"`
	Covered       int     `json:"covered"`
	Missing       int     `json:"missing"`
	CoveragePct   float64 `json:"coverage_pct"`
	LaterTurnsP50 int     `json:"later_turns_p50"`
	LaterTurnsMax int     `json:"later_turns_max"`
}

type joinedTranscript struct {
	calls  []tCall     // assistant API calls, file order
	bounds []time.Time // compact_boundary timestamps, file order
}

type tCall struct {
	t  time.Time
	id string
}

// joinTranscripts fills o.TokensSaved and o.Join from caps. projects is
// ~/.claude/projects; a missing dir makes every cap missing.
func joinTranscripts(projects string, caps []capEvent, o *OutputCapStat) {
	j := &o.Join
	j.Caps = len(caps)
	if len(caps) == 0 {
		return
	}
	// Transcripts are the slow part (tens of MB each); load them in parallel, then sum in order.
	cache := map[[2]string]*joinedTranscript{}
	var keys [][2]string
	for _, c := range caps {
		if k := [2]string{c.Session, c.Agent}; !slices.Contains(keys, k) {
			keys = append(keys, k)
		}
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, runtime.NumCPU())
	for _, k := range keys {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			tr := loadTranscript(projects, k[0], k[1])
			mu.Lock()
			cache[k] = tr
			mu.Unlock()
		}()
	}
	wg.Wait()
	var saved int64
	var later []int
	for _, c := range caps {
		tr := cache[[2]string{c.Session, c.Agent}]
		if tr == nil {
			j.Missing++
			continue
		}
		j.Covered++
		n := tr.laterCalls(c.T)
		later = append(later, n)
		if c.Cut > 0 {
			saved += c.Cut * int64(n) / 4
		}
	}
	j.CoveragePct = 100 * float64(j.Covered) / float64(j.Caps)
	if len(later) > 0 {
		slices.Sort(later)
		j.LaterTurnsP50 = later[(len(later)-1)/2]
		j.LaterTurnsMax = later[len(later)-1]
	}
	if j.Covered > 0 {
		o.TokensSaved = &saved
	}
}

// laterCalls counts distinct API calls after t and before the first
// compact_boundary after t.
func (tr *joinedTranscript) laterCalls(t time.Time) int {
	var end time.Time
	for _, b := range tr.bounds {
		if b.After(t) && (end.IsZero() || b.Before(end)) {
			end = b
		}
	}
	ids := map[string]struct{}{}
	for _, c := range tr.calls {
		if c.t.After(t) && (end.IsZero() || c.t.Before(end)) {
			ids[c.id] = struct{}{}
		}
	}
	return len(ids)
}

// loadTranscript streams the one transcript file for (session, agent), or
// returns nil when none exists. Only assistant and compact_boundary lines are
// decoded; everything else is skipped on a byte check.
func loadTranscript(projects, session, agent string) *joinedTranscript {
	// session/agent come from hook stdin via the logs: a trust boundary. One
	// path element each, and no glob metacharacters (they go through Glob).
	safe := func(s string) bool { return s != "" && state.SafeName(s, "") == s && !strings.ContainsAny(s, "*?[") }
	if !safe(session) || (agent != "" && !safe(agent)) {
		return nil
	}
	pat := filepath.Join(projects, "*", session+".jsonl")
	if agent != "" {
		pat = filepath.Join(projects, "*", session, "subagents", "agent-"+agent+".jsonl")
	}
	paths, _ := filepath.Glob(pat)
	if len(paths) == 0 {
		return nil
	}
	f, err := os.Open(paths[0])
	if err != nil {
		return nil
	}
	defer f.Close()
	tr := &joinedTranscript{}
	var line struct {
		Type      string `json:"type"`
		Subtype   string `json:"subtype"`
		Summary   bool   `json:"isCompactSummary"`
		Timestamp string `json:"timestamp"`
		RequestID string `json:"requestId"`
		Message   struct {
			ID string `json:"id"`
		} `json:"message"`
	}
	// A resumed session file can hold the summary without its boundary line.
	assistant, boundary, summary := []byte(`"type":"assistant"`), []byte(`"subtype":"compact_boundary"`), []byte(`"isCompactSummary":true`)
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 64<<20)
	for sc.Scan() {
		b := sc.Bytes()
		if !bytes.Contains(b, assistant) && !bytes.Contains(b, boundary) && !bytes.Contains(b, summary) {
			continue
		}
		line.Type, line.Subtype, line.Summary, line.Timestamp, line.RequestID, line.Message.ID = "", "", false, "", "", ""
		if json.Unmarshal(b, &line) != nil {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, line.Timestamp)
		if err != nil {
			continue
		}
		switch {
		case line.Type == "assistant":
			id := line.RequestID
			if id == "" {
				id = line.Message.ID
			}
			if id != "" {
				tr.calls = append(tr.calls, tCall{t, id})
			}
		case line.Type == "system" && line.Subtype == "compact_boundary", line.Summary:
			tr.bounds = append(tr.bounds, t)
		}
	}
	if sc.Err() != nil { // truncated read: treat the transcript as gone rather than under-count silently
		return nil
	}
	return tr
}
