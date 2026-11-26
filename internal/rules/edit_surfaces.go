package rules

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/iampolo87/claude-policy/internal/config"
	"github.com/iampolo87/claude-policy/internal/hook"
	"github.com/iampolo87/claude-policy/internal/state"
)

// editSurfaces confines a subagent's file edits to the "## Allowed edit
// surfaces" list in its brief (line 0 of its transcript). Unreadable brief:
// fail open, logged; a heading that names no path: denied, logged (an empty
// list would leave edits unscoped). Never returns Permission
// "allow" (it would skip the user's permission prompt).
type editSurfaces struct{}

func init() { Registry = append(Registry, editSurfaces{}) }

func (editSurfaces) Name() string     { return "edit_surfaces" }
func (editSurfaces) Events() []string { return []string{"PreToolUse"} }
func (editSurfaces) Tools() []string {
	return []string{"Edit", "Write", "MultiEdit", "NotebookEdit"}
}

const maxBriefLine = 1 << 20

var (
	surfaceBullet = regexp.MustCompile("^(?:[-*+]|\\d+[.)]) +")
	surfaceQuoted = regexp.MustCompile("`([^`]*)`")
	drivePrefix   = regexp.MustCompile(`^(?:/|~|[A-Za-z]:)`)
	// restrictiveNote marks a note that excludes its path: `b.go (read-only)`,
	// `b.go: never touch`, `b.go — do not edit`.
	restrictiveNote = regexp.MustCompile(`(?i)read[- ]?only|reference only|never|no changes?|exclud|do not|don['’]t|must not|not (?:be )?edit|no edit|untouched|off[- ]limits|` +
		`out of scope|no modif|view[- ]?only|informational|context only`)
	// leadInStop is a lead-in that does not introduce edit surfaces:
	// `None: …`, `No edits:`, `Files to read:`, `For context, see:`.
	leadInStop = regexp.MustCompile(`(?i)^\W*(?:none\b|no\s)|\b(?:read|reference|context|see)\b`)
	tableSep   = regexp.MustCompile(`^\|?(?:\s*:?-+:?\s*\|)+\s*(?::?-+:?\s*)?$`)
	// noCells mark a table row's path as not editable.
	noCells = []string{"no", "n", "false", "✗", "❌", "❎", "-"}
)

// maxLeadIn is the longest `…:` line read as a lead-in, not prose.
const maxLeadIn = 80

// surfaceCache is the per-agent parsed brief. A cache from before round 5
// may still carry an "items" key; it is ignored.
type surfaceCache struct {
	Found    bool     `json:"found"` // heading present
	Surfaces []string `json:"surfaces"`
}

// normalizeSurfaceEntry ports reference/gentle-shell/lib/writer-surfaces.ts.
// ponytail: no NFC normalisation (needs golang.org/x/text); non-ASCII
// decomposed spellings of an entry will not match their composed twins.
func normalizeSurfaceEntry(v string) (string, bool) {
	if v == "" || drivePrefix.MatchString(v) {
		return "", false
	}
	var segs []string
	for _, s := range strings.Split(v, "/") {
		if s == ".." {
			return "", false
		}
		if s != "" && s != "." {
			segs = append(segs, s)
		}
	}
	if len(segs) == 0 {
		return "", false
	}
	return strings.ToLower(strings.Join(segs, "/")), true
}

// surfaceItems splits one bullet into its paths: `(…)` notes are dropped
// (nested ones too), the rest splits on commas. A piece is a path: a
// backticked span, else one word that looks like a path (has `/`, `.` or a
// glob character). Text after `: ` in a piece, or after ` — ` in the first,
// is a note that ends the paths; a restrictive one (restrictiveNote, read to
// the line's end) drops its piece too. Any other text in a piece is prose
// (`b.go is off-limits`, `b.go - do not edit`): the piece adds nothing and
// ends the paths. ponytail: an unquoted path containing a space is prose; a
// bare unquoted name without `/` or `.` (`Makefile`) needs backticks; a note
// about another path (`a.go — b.go is off-limits`) drops its piece as well.
func surfaceItems(line string) []string {
	v := stripParens(surfaceBullet.ReplaceAllString(strings.TrimSpace(line), ""))
	if i := strings.Index(v, " — "); i >= 0 && !strings.Contains(v[:i], ",") {
		if restrictiveNote.MatchString(v[i:]) {
			return nil
		}
		v = v[:i]
	}
	var out []string
	pieces := strings.Split(v, ",")
	for k, p := range pieces {
		note := strings.Index(p, ": ")
		if note >= 0 {
			if restrictiveNote.MatchString(strings.Join(append([]string{p[note:]}, pieces[k+1:]...), ",")) {
				break
			}
			p = p[:note]
		}
		p = strings.TrimSpace(p)
		path, rest := "", ""
		if m := surfaceQuoted.FindStringSubmatchIndex(p); m != nil && m[0] == 0 {
			path, rest = strings.TrimSpace(p[m[2]:m[3]]), strings.TrimSpace(p[m[1]:])
		} else if f := strings.Fields(p); len(f) > 0 && !strings.Contains(p, "`") && strings.ContainsAny(f[0], "/.*?[") {
			path, rest = strings.TrimSuffix(f[0], ":"), strings.Join(f[1:], " ")
		}
		if path == "" || rest != "" {
			break
		}
		out = append(out, path)
		if note >= 0 {
			break
		}
	}
	return out
}

// stripParens drops every `(…)` note, nested ones included; an unclosed `(`
// drops the rest of s. A restrictive note (restrictiveNote) leaves a
// non-space marker word instead, so its piece reads as prose and adds
// nothing. A `(` right after a non-space character is part of a path
// (`src/(group)/page.tsx`) and kept with its `)`.
func stripParens(s string) string {
	var b, note strings.Builder
	depth, lit, prev := 0, 0, ' '
	for _, r := range s {
		switch {
		case r == '(' && depth == 0 && !unicode.IsSpace(prev):
			lit++
			b.WriteRune(r)
		case r == ')' && depth == 0 && lit > 0:
			lit--
			b.WriteRune(r)
		case r == '(':
			if depth++; depth > 1 {
				note.WriteRune(r)
			}
		case r == ')' && depth > 0:
			if depth--; depth > 0 {
				note.WriteRune(r)
			} else if restrictiveNote.MatchString(note.String()) {
				b.WriteString(" \x00")
			}
			if depth == 0 {
				note.Reset()
			}
		case depth > 0:
			note.WriteRune(r)
		default:
			b.WriteRune(r)
		}
		prev = r
	}
	if depth > 0 && restrictiveNote.MatchString(note.String()) {
		b.WriteString(" \x00")
	}
	return b.String()
}

// parseSurfaces returns the normalised items of the list right under
// heading. Before it only a lead-in is skipped: blank lines, bold-only lines
// (`**Only these:**`) and short lines ending in `:`. Any other line, a code
// fence, or a lead-in that is restrictive, starts with None/No or points at
// reading (`Files to read:`) ends the section with no surface (denied). The
// list is bullets (`-`, `*`, `+`, `1.`) or table rows, not both: the first
// line of another kind, blank or not, ends it (a later task list or fenced
// example is not surfaces). A table row is its first cell, dropped when a
// later cell is restrictive or a no (no, false, ✗, -); a header row (the one
// before a `|---|` separator) and the separator add nothing. A bullet
// indented deeper than the first item is nested: it annotates its parent
// and adds nothing.
func parseSurfaces(brief, heading string) surfaceCache {
	var c surfaceCache
	kind, indent := byte(0), 0 // kind: 0 before the list, '-' bullets, '|' table rows
	lines := strings.Split(brief, "\n")
	for i, line := range lines {
		line = strings.TrimRight(line, " \t\r")
		t := strings.TrimSpace(line)
		bullet, row := surfaceBullet.MatchString(t), strings.HasPrefix(t, "|")
		switch {
		case !c.Found:
			c.Found = line == heading
		case strings.HasPrefix(t, "#"):
			return c
		case kind == 0 && !bullet && !row: // lead-in
			if t == "" {
				continue
			}
			if strings.HasPrefix(t, "```") || strings.HasPrefix(t, "~~~") || restrictiveNote.MatchString(t) || leadInStop.MatchString(t) {
				return c
			}
			if len(t) > 4 && strings.HasPrefix(t, "**") && strings.HasSuffix(t, "**") || len(t) <= maxLeadIn && strings.HasSuffix(t, ":") {
				continue
			}
			return c
		case row && kind != '-':
			kind = '|'
			if tableSep.MatchString(t) || i+1 < len(lines) && tableSep.MatchString(strings.TrimSpace(lines[i+1])) {
				continue // separator or header
			}
			cells := strings.Split(strings.Trim(t, "|"), "|")
			if restrictiveNote.MatchString(strings.Join(cells[1:], "|")) || slices.ContainsFunc(cells[1:], func(s string) bool {
				return slices.Contains(noCells, strings.ToLower(strings.TrimSpace(s)))
			}) {
				continue
			}
			for _, it := range surfaceItems(strings.TrimSpace(cells[0])) {
				if e, ok := normalizeSurfaceEntry(it); ok {
					c.Surfaces = append(c.Surfaces, e)
				}
			}
		case !bullet || kind == '|':
			return c
		default:
			ind := len(line) - len(strings.TrimLeft(line, " \t"))
			if kind == 0 {
				indent = ind
			}
			kind = '-'
			if ind > indent {
				continue
			}
			for _, it := range surfaceItems(line) {
				if e, ok := normalizeSurfaceEntry(it); ok {
					c.Surfaces = append(c.Surfaces, e)
				}
			}
		}
	}
	return c
}

// readBrief returns the text of the agent transcript's first user message.
func readBrief(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	line, err := bufio.NewReader(io.LimitReader(f, maxBriefLine)).ReadBytes('\n')
	if err != nil && !(errors.Is(err, io.EOF) && len(line) > 0) {
		return "", err
	}
	var m struct {
		Message struct {
			Content json.RawMessage `json:"content"`
		} `json:"message"`
	}
	if err := json.Unmarshal(line, &m); err != nil {
		return "", err
	}
	var s string
	if json.Unmarshal(m.Message.Content, &s) == nil && s != "" {
		return s, nil
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(m.Message.Content, &blocks) == nil {
		var parts []string
		for _, b := range blocks {
			if b.Type == "text" {
				parts = append(parts, b.Text)
			}
		}
		if s = strings.Join(parts, "\n"); s != "" {
			return s, nil
		}
	}
	return "", errors.New("brief has no text content")
}

// gitRoot walks up from dir for a .git entry (dir, or file in a worktree).
func gitRoot(dir string) (string, bool) {
	for {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return dir, true
		}
		p := filepath.Dir(dir)
		if p == dir {
			return "", false
		}
		dir = p
	}
}

func (r editSurfaces) Apply(_ context.Context, in *hook.Input, cfg *config.Config, st *state.Store) *hook.Decision {
	if in.AgentID == "" {
		return nil
	}
	es := cfg.Rules.EditSurfaces
	logError := func(why string) {
		st.AppendDecision(logEntry{
			TS: time.Now().UTC().Format(time.RFC3339Nano), Session: in.SessionID, Agent: in.AgentID,
			Event: in.HookEventName, Tool: in.ToolName, Rule: r.Name(), Mode: cfg.Mode(r.Name()), Error: why,
		})
	}
	fail := func(why string) *hook.Decision {
		logError(why)
		return nil
	}

	var ti struct {
		FilePath     string `json:"file_path"`
		NotebookPath string `json:"notebook_path"`
	}
	if json.Unmarshal(in.ToolInput, &ti) != nil {
		return nil
	}
	target := ti.FilePath
	if in.ToolName == "NotebookEdit" {
		target = ti.NotebookPath
	}
	if target == "" {
		return nil
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(in.Cwd, target)
	}
	target = filepath.Clean(target)

	var sc surfaceCache
	cached, _ := st.Read(st.Agent + ".surfaces")
	if cached == nil || json.Unmarshal(cached, &sc) != nil {
		id := state.SafeName(in.AgentID, "")
		if id == "" {
			return fail("unsafe agent_id")
		}
		path := strings.TrimSuffix(in.TranscriptPath, ".jsonl") + "/subagents/agent-" + id + ".jsonl"
		brief, err := readBrief(path)
		if err != nil {
			return fail("brief unreadable: " + err.Error())
		}
		sc = parseSurfaces(brief, es.Heading)
		if b, err := json.Marshal(sc); err == nil {
			st.Write(st.Agent+".surfaces", b)
		}
	}
	if sc.Found && len(sc.Surfaces) == 0 { // a heading naming no path: failing open would scope nothing
		logError("brief " + es.Heading + " names no path")
		return &hook.Decision{Permission: "deny", Reason: "edit_surfaces: the brief's " + es.Heading +
			" names no readable path; ask the coordinator to list one path per bullet or a comma list of plain paths"}
	}
	if !sc.Found {
		if es.Missing == "deny" {
			return &hook.Decision{Permission: "deny", Reason: "edit_surfaces: brief has no " + es.Heading}
		}
		return nil
	}

	home, _ := os.UserHomeDir()
	for _, g := range es.AlwaysAllowed {
		if strings.Contains(g, "$scratchpad_dir") {
			if in.ScratchpadDir == "" {
				continue
			}
			g = strings.ReplaceAll(g, "$scratchpad_dir", in.ScratchpadDir)
		}
		if g == "~" || strings.HasPrefix(g, "~/") {
			if home == "" {
				continue
			}
			g = home + g[1:]
		}
		if ok, _ := doublestar.Match(g, target); ok {
			return nil
		}
	}

	shown := target
	if root, ok := gitRoot(in.Cwd); ok {
		if rel, err := filepath.Rel(root, target); err == nil && rel != ".." && !strings.HasPrefix(rel, "../") {
			shown = filepath.ToSlash(rel)
			low := strings.ToLower(shown)
			for _, e := range sc.Surfaces {
				if ok, _ := doublestar.Match(e, low); ok || strings.HasPrefix(low, e+"/") {
					return nil
				}
			}
		}
	}
	return &hook.Decision{Permission: "deny", Reason: "edit_surfaces: " + shown +
		" is outside this agent's " + es.Heading + ": " + strings.Join(sc.Surfaces, ", ")}
}
