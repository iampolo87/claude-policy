package rules

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iampolo87/claude-policy/internal/config"
	"github.com/iampolo87/claude-policy/internal/hook"
	"github.com/iampolo87/claude-policy/internal/state"
)

const esBrief = "Task.\n\n## Allowed edit surfaces\n- internal/rules/*.go\n- `Docs`\n- src/**/gen.go\n- ../escape\n- /abs\n\n## Next\n- other/file.go\n"

// esEnv is a fake repo (.git file) plus a parent transcript dir.
type esEnv struct {
	repo, tr, scratch string
	st                *state.Store
}

func newEsEnv(t *testing.T, line0 string) *esEnv {
	t.Helper()
	d := t.TempDir()
	e := &esEnv{repo: filepath.Join(d, "repo"), tr: filepath.Join(d, "sess.jsonl"), scratch: filepath.Join(d, "scratch"),
		st: state.New(filepath.Join(d, "state"), "s", "ag1")}
	os.MkdirAll(filepath.Join(e.repo, "sub"), 0o755)
	os.WriteFile(filepath.Join(e.repo, ".git"), []byte("gitdir: x"), 0o644)
	if line0 != "" {
		os.MkdirAll(filepath.Join(d, "sess", "subagents"), 0o755)
		os.WriteFile(filepath.Join(d, "sess", "subagents", "agent-ag1.jsonl"), []byte(line0+"\n{}\n"), 0o644)
	}
	return e
}

func (e *esEnv) brief(t *testing.T, content any) string {
	b, _ := json.Marshal(map[string]any{"type": "user", "message": map[string]any{"role": "user", "content": content}})
	return string(b)
}

func (e *esEnv) apply(cfg *config.Config, agent, tool, key, path string) *hook.Decision {
	ti, _ := json.Marshal(map[string]string{key: path})
	in := &hook.Input{HookEventName: "PreToolUse", ToolName: tool, ToolInput: ti, AgentID: agent,
		TranscriptPath: e.tr, Cwd: filepath.Join(e.repo, "sub"), ScratchpadDir: e.scratch}
	return editSurfaces{}.Apply(context.Background(), in, cfg, e.st)
}

func TestEditSurfaces(t *testing.T) {
	cfg := suiteCfg()
	e := newEsEnv(t, "")
	e = newEsEnv(t, newEsEnv(t, "").brief(t, esBrief))
	arr := e.brief(t, []map[string]string{{"type": "text", "text": "intro"}, {"type": "text", "text": esBrief}})
	e2 := newEsEnv(t, arr)

	for _, env := range []*esEnv{e, e2} {
		for _, c := range []struct {
			path  string
			allow bool
		}{
			{"../internal/rules/x.go", true},        // glob, relative to cwd
			{"../DOCS/a/b.md", true},                // dir entry covers children, case-insensitive
			{"../Docs", true},                       // the dir itself
			{"../src/a/b/gen.go", true},             // ** glob
			{"../internal/other/x.go", false},       // outside
			{"../../outside.go", false},             // out of root
			{"../internal/rules/../../x.go", false}, // traversal resolved
			{"../other/file.go", false},             // listed under the next heading
		} {
			d := env.apply(cfg, "ag1", "Edit", "file_path", c.path)
			if c.allow != (d == nil) {
				t.Errorf("%s: allow=%v got %+v", c.path, c.allow, d)
			}
			if d != nil && (d.Permission != "deny" || !strings.Contains(d.Reason, "internal/rules/*.go, docs, src/**/gen.go") || strings.Contains(d.Reason, "escape")) {
				t.Errorf("%s: reason %q", c.path, d.Reason)
			}
		}
	}
	if d := e.apply(cfg, "", "Edit", "file_path", "../zzz"); d != nil {
		t.Fatal("main agent must be skipped")
	}
	if d := e.apply(cfg, "ag1", "NotebookEdit", "notebook_path", "../zzz.ipynb"); d == nil {
		t.Fatal("notebook_path must be checked")
	}
	if d := e.apply(cfg, "ag1", "Write", "file_path", filepath.Join(e.scratch, "n.txt")); d != nil {
		t.Fatalf("scratchpad always allowed: %+v", d)
	}
	if d := e.apply(cfg, "ag1", "Write", "file_path", filepath.Join(filepath.Dir(e.repo), "zz.txt")); d == nil {
		t.Fatal("outside root denied")
	}
	cfg.Rules.EditSurfaces.AlwaysAllowed = []string{"$scratchpad_dir/**"}
	in := &hook.Input{ToolName: "Write", ToolInput: json.RawMessage(`{"file_path":"/x/y"}`), AgentID: "ag1", TranscriptPath: e.tr, Cwd: e.repo}
	if d := (editSurfaces{}).Apply(context.Background(), in, cfg, e.st); d == nil {
		t.Fatal("empty scratchpad_dir must skip the entry, not allow everything")
	}
}

// The list ends at the first blank or non-list line after its items: a
// numbered task list later in the brief is not a surface list.
func TestParseSurfacesEndsWithList(t *testing.T) {
	brief := "## Allowed edit surfaces\n\n- docs/a.md\n- `src/**`\n\nSteps:\n1. write x.go\n2. run tests\n"
	got := parseSurfaces(brief, "## Allowed edit surfaces")
	if !got.Found || strings.Join(got.Surfaces, ",") != "docs/a.md,src/**" {
		t.Fatalf("got %+v", got)
	}
	got = parseSurfaces("## Allowed edit surfaces\n- a.go\nnot a list\n- b.go\n", "## Allowed edit surfaces")
	if strings.Join(got.Surfaces, ",") != "a.go" {
		t.Fatalf("got %+v", got)
	}
	// a nested bullet annotates its parent: no surface of its own
	got = parseSurfaces("## Allowed edit surfaces\n- a.go\n  - internal/config/ is read-only\n\t* b/\n- c.go\n", "## Allowed edit surfaces")
	if strings.Join(got.Surfaces, ",") != "a.go,c.go" {
		t.Fatalf("got %+v", got)
	}
	got = parseSurfaces("## Allowed edit surfaces\n  - internal/config/ is read-only\n", "## Allowed edit surfaces")
	if len(got.Surfaces) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestEditSurfacesMissingHeading(t *testing.T) {
	cfg := suiteCfg()
	e := newEsEnv(t, "")
	e = newEsEnv(t, e.brief(t, "no surfaces here"))
	if d := e.apply(cfg, "ag1", "Edit", "file_path", "x.go"); d != nil {
		t.Fatalf("missing=allow: %+v", d)
	}
	// round 4: a heading whose bullets yield no surface is unreadable: denied
	// even with missing=allow, so an empty list never leaves edits unscoped.
	unscopable := "## Allowed edit surfaces\n- /abs/path.go\n- ../up.go\n"
	if d := newEsEnv(t, e.brief(t, unscopable)).apply(cfg, "ag1", "Edit", "file_path", "x.go"); d == nil || d.Permission != "deny" {
		t.Fatalf("only unscopable entries, missing=allow: %+v", d)
	}
	// round 5: a heading with nothing under it scopes nothing: denied too
	if d := newEsEnv(t, e.brief(t, "## Allowed edit surfaces\n\nNone yet.\n")).apply(cfg, "ag1", "Edit", "file_path", "x.go"); d == nil || d.Permission != "deny" {
		t.Fatalf("heading without bullets, missing=allow: %+v", d)
	}
	e = newEsEnv(t, e.brief(t, "no surfaces here"))
	cfg.Rules.EditSurfaces.Missing = "deny"
	d := e.apply(cfg, "ag1", "Edit", "file_path", "x.go")
	if d == nil || d.Permission != "deny" || !strings.Contains(d.Reason, "brief has no ## Allowed edit surfaces") {
		t.Fatalf("missing=deny: %+v", d)
	}
}

func TestEditSurfacesUnreadableLogs(t *testing.T) {
	cfg := suiteCfg()
	for name, line0 := range map[string]string{"missing": "", "badjson": "{nope", "nocontent": `{"message":{"content":[]}}`} {
		e := newEsEnv(t, line0)
		if d := e.apply(cfg, "ag1", "Edit", "file_path", "x.go"); d != nil {
			t.Fatalf("%s: %+v", name, d)
		}
		b, _ := os.ReadFile(filepath.Join(e.st.Root, "decisions.jsonl"))
		if !strings.Contains(string(b), `"rule":"edit_surfaces"`) || !strings.Contains(string(b), `"error":"`) {
			t.Fatalf("%s: log %q", name, b)
		}
	}
}

func TestEditSurfacesCache(t *testing.T) {
	cfg := suiteCfg()
	e := newEsEnv(t, "")
	e = newEsEnv(t, e.brief(t, esBrief))
	if d := e.apply(cfg, "ag1", "Edit", "file_path", "../docs/a"); d != nil {
		t.Fatalf("first: %+v", d)
	}
	os.RemoveAll(filepath.Join(filepath.Dir(e.tr), "sess"))
	if d := e.apply(cfg, "ag1", "Edit", "file_path", "../docs/a"); d != nil {
		t.Fatalf("cache must avoid re-reading: %+v", d)
	}
	if d := e.apply(cfg, "ag1", "Edit", "file_path", "../nope"); d == nil {
		t.Fatal("cached surfaces still enforced")
	}
}

// Brief bullets as coordinators really wrote them.
func TestParseSurfacesAnnotatedBullets(t *testing.T) {
	brief := "## Allowed edit surfaces\n" +
		"- cmd/claude-policy/main.go (dispatch + usage line only), cmd/claude-policy/statusline.go, cmd/claude-policy/statusline_test.go (new), internal/state/x.go\n" +
		"- `cmd/claude-policy/stats.go` (new), `cmd/claude-policy/stats_test.go` (new), `cmd/claude-policy/main.go`: only the dispatch case, usage line\n" +
		"- testdata/stats/ (fixtures, new)\n" +
		"- docs/a.md: append one section\n" +
		"- `zz-ok.txt` (new), docs/none.md: probe only, not this\n"
	got := parseSurfaces(brief, "## Allowed edit surfaces")
	want := "cmd/claude-policy/main.go,cmd/claude-policy/statusline.go,cmd/claude-policy/statusline_test.go,internal/state/x.go," +
		"cmd/claude-policy/stats.go,cmd/claude-policy/stats_test.go,cmd/claude-policy/main.go,testdata/stats,docs/a.md,zz-ok.txt,docs/none.md"
	if strings.Join(got.Surfaces, ",") != want {
		t.Fatalf("got  %s\nwant %s", strings.Join(got.Surfaces, ","), want)
	}
}

// Review: prose next to a path must not widen the list.
func TestParseSurfacesProseDoesNotWiden(t *testing.T) {
	for line, want := range map[string]string{
		"- `internal/rules/x.go`: keep in sync with `internal/config/config.go`": "internal/rules/x.go",
		// round 5: a restrictive ` — ` tail drops its piece, even when it may
		// be about another path (fail closed: the agent is denied and asks)
		"- `cmd/main.go` — see `internal/rules/` for patterns, do not edit": "",
		"- cmd/main.go, internal wiring only":                               "cmd/main.go",
		"- see `x.go` for context":                                          "",
		"- a.go, `b/c.go` (new), d/*.go":                                    "a.go,b/c.go,d/*.go",
		// second blind review: off-limits paths after the first must not count
		"- `cmd/main.go`, `internal/` is off-limits":   "cmd/main.go",
		"- cmd/main.go, internal/x.go stays read-only": "cmd/main.go",
		"- `x.go`, `y.go` must not be touched":         "x.go",
		"- `x.go` must not be touched, y.go":           "",
		"- `a.go` (see (b), `c.go`)":                   "a.go",
		"- `a.go`, b.go is generated, c.go":            "a.go",
		"- a.go — b.go is off-limits":                  "", // round 5: restrictive tail
		"- a.go — b.go is generated":                   "a.go",
		// round 4: a restrictive note drops its piece; a path's own parens stay
		"- a.go, b.go (read-only)":                         "a.go",
		"- a.go, b.go (Do Not edit, generated), c.go":      "a.go",
		"- a.go (new), b.go (readonly)":                    "a.go",
		"- a.go (untouched)":                               "",
		"- a.go (see (b) for don't), c.go":                 "",
		"- `src/(group)/page.tsx`":                         "src/(group)/page.tsx",
		"- src/(group)/page.tsx, app/[id]/(x).tsx (new)":   "src/(group)/page.tsx,app/[id]/(x).tsx",
		"- cmd/main.go (dispatch + usage line only), b.go": "cmd/main.go,b.go",
		// round 5: wider restrictive notes, in parens and in note tails
		"- a.go, b.go (read only)":          "a.go",
		"- a.go, b.go (reference only)":     "a.go",
		"- a.go, b.go (never modify)":       "a.go",
		"- a.go, b.go (no changes)":         "a.go",
		"- a.go, b.go (Excluded)":           "a.go",
		"- a.go, b.go (off limits)":         "a.go",
		"- a.go, b.go (must not be edited)": "a.go",
		"- b.go: read-only":                 "",
		"- b.go — do not edit":              "",
		"- a.go, b.go: never touch":         "a.go",
		"- a.go: new":                       "a.go",
		"- a.go — the parser":               "a.go",
		"- a.go (new), b.go (tests)":        "a.go,b.go",
	} {
		got := parseSurfaces("## Allowed edit surfaces\n"+line+"\n", "## Allowed edit surfaces")
		if s := strings.Join(got.Surfaces, ","); s != want {
			t.Errorf("%q: got %q want %q", line, s, want)
		}
	}
}

// Round 4: bullets that parse to no surface fail closed (deny, logged)
// instead of leaving the agent unscoped under missing="allow".
func TestEditSurfacesUnparseableBulletsDeny(t *testing.T) {
	cfg := suiteCfg()
	for _, line := range []string{
		"- internal/rules/destructive.go and its test",
		"- `a.go` and `b.go`",
		"- a.go b.go",
		"- a.go - fix the bug",
		"- `x.go` must not be touched, y.go",
		"- a.go (read-only)",
	} {
		e := newEsEnv(t, "")
		e = newEsEnv(t, e.brief(t, "## Allowed edit surfaces\n"+line+"\n"))
		d := e.apply(cfg, "ag1", "Edit", "file_path", "../a.go")
		if d == nil || d.Permission != "deny" || !strings.Contains(d.Reason, "one path per bullet") {
			t.Errorf("%q: %+v", line, d)
		}
		b, _ := os.ReadFile(filepath.Join(e.st.Root, "decisions.jsonl"))
		if !strings.Contains(string(b), `"error":"`) {
			t.Errorf("%q: not logged: %q", line, b)
		}
	}
}

// Round 5: prose, bold lines or a table between the heading and its items
// must not leave edits unscoped.
func TestParseSurfacesLeadIn(t *testing.T) {
	for brief, want := range map[string]string{
		"## Allowed edit surfaces\nOnly these files:\n- a.go\n":                                   "a.go",
		"## Allowed edit surfaces\n\n**Only these:**\n\n- a.go\n- b/\n":                           "a.go,b",
		"## Allowed edit surfaces\n| path | why |\n|---|---|\n| a.go | new |\n| `b/c.go` | x |\n": "a.go,b/c.go",
		"## Allowed edit surfaces\n| a.go | new |\n| b.go | read-only |\n":                        "a.go",
		"## Allowed edit surfaces\nNone yet.\n\n## Next\n- other.go\n":                            "",
		// round 6: only blank, bold-only and short `…:` lines are a lead-in
		"## Allowed edit surfaces\nNone: this is a read-only review; do not edit anything.\n\nFiles to read:\n- internal/rules/destructive.go\n": "",
		"## Allowed edit surfaces\nOnly `a.go`. Example:\n```\n- **/*\n```\n- a.go\n":                                                            "",
		"## Allowed edit surfaces\nFiles to read:\n- a.go\n":                                                                                     "",
		"## Allowed edit surfaces\nFor context, see:\n- a.go\n":                                                                                  "",
		"## Allowed edit surfaces\nNo edits:\n- a.go\n":                                                                                          "",
		"## Allowed edit surfaces\n**Do not edit these:**\n- a.go\n":                                                                             "",
		"## Allowed edit surfaces\n```\n- a.go\n```\n":                                                                                           "",
		"## Allowed edit surfaces\n- a.go\n```\n- b.go\n```\n":                                                                                   "a.go",
		"## Allowed edit surfaces\nWork through the steps.\n1. docs/README.md: add a note\n":                                                     "",
		"## Allowed edit surfaces\n1. docs/README.md: add a note\n":                                                                              "docs/readme.md",
		// round 6: table rows
		"## Allowed edit surfaces\n| Path | Editable |\n|---|---|\n| a.go | yes |\n| b.go | no |\n| c.go | ✗ |\n| d.go | - |\n| e.go | false |\n": "a.go",
		"## Allowed edit surfaces\n| x.go | ❌ |\n| y.go | ❎ |\n| z.go | n |\n":                                                                    "",
		"## Allowed edit surfaces\n- a.go\n| b.go | yes |\n":                                                                                      "a.go",
		"## Allowed edit surfaces\n| a.go | yes |\n- b.go\n":                                                                                      "a.go",
		// round 6: wider restrictive notes
		"## Allowed edit surfaces\n- a.go, b.go (out of scope), c.go (no modifications), d.go (view only)\n": "a.go",
		"## Allowed edit surfaces\n- a.go, b.go (informational), c.go (context only)\n":                      "a.go",
	} {
		if got := strings.Join(parseSurfaces(brief, "## Allowed edit surfaces").Surfaces, ","); got != want {
			t.Errorf("%q: got %q want %q", brief, got, want)
		}
	}
}

// Round 5: a found heading with no surface denies whatever the cache says,
// including a cache written before the items field existed.
func TestEditSurfacesEmptyFoundDenies(t *testing.T) {
	cfg := suiteCfg()
	e := newEsEnv(t, "")
	e.st.Write(e.st.Agent+".surfaces", []byte(`{"found":true,"surfaces":[]}`))
	if d := e.apply(cfg, "ag1", "Edit", "file_path", "x.go"); d == nil || d.Permission != "deny" {
		t.Fatalf("legacy cache: %+v", d)
	}
	e = newEsEnv(t, e.brief(t, "## Allowed edit surfaces\nOnly these files:\n- a.go\n"))
	if d := e.apply(cfg, "ag1", "Edit", "file_path", "../b.go"); d == nil || d.Permission != "deny" {
		t.Fatalf("lead-in prose: %+v", d)
	}
	if d := e.apply(cfg, "ag1", "Edit", "file_path", "../a.go"); d != nil {
		t.Fatalf("lead-in prose, listed: %+v", d)
	}
}
