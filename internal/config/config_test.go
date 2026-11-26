package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestMissingFileIsDefaults(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "nope.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c, Defaults()) {
		t.Fatal("missing file must yield defaults")
	}
	// A new install only observes: every rule logs, nothing is enforced.
	for name, mode := range c.modes() {
		if *mode != "log" {
			t.Errorf("rule %s defaults to %q, want log", name, *mode)
		}
	}
	if c.Mode("no_such_rule") != "log" {
		t.Fatalf("unknown rule: %q", c.Mode("no_such_rule"))
	}
	if len(c.Rules.Ponytail.Signatures) != 6 || c.Rules.Destructive.FS.AllowRoots[0] != "$scratchpad_dir" ||
		len(c.Rules.Destructive.FS.Regenerable) != 0 {
		t.Fatal("defaults drifted")
	}
	// Nothing outside Claude Code is touched until policy.toml asks for it.
	if !reflect.DeepEqual(c.Integrations, Integrations{Mempalace: Mempalace{Bin: "mempalace"}}) ||
		c.Rules.Ponytail.LevelFile != "" || c.Rules.SessionNotice.Startup != "" || c.Rules.Lint.PHPStan || c.Rules.Lint.PHPCS {
		t.Fatalf("an integration is on by default: %+v", c.Integrations)
	}
	for _, s := range append(append([]string{}, c.Rules.Destructive.FS.AllowRoots...), c.Rules.EditSurfaces.AlwaysAllowed...) {
		if strings.Contains(s, "claude-") && !strings.Contains(s, fmt.Sprintf("/tmp/claude-%d", os.Getuid())) {
			t.Errorf("temp root %q is not the caller's", s)
		}
	}
}

func TestIntegrations(t *testing.T) {
	c, err := Load(write(t, `
[integrations.claude_mem]
work_state_url = "http://127.0.0.1:9/api/work-state"
[integrations.mempalace]
mine = true
projects_root = "/work/user/my.projects"
[integrations.herdr]
report = true
notice = "pane {pane}"
`))
	if err != nil {
		t.Fatal(err)
	}
	m := c.Integrations.Mempalace
	for tp, want := range map[string]string{
		"/h/.claude/projects/-work-user-my-projects-foo-bar/s.jsonl": "foo-bar",
		"/h/.claude/projects/-work-user-my-projects-/s.jsonl":        "",
		"/h/.claude/projects/-work-user-my-projects/s.jsonl":         "",
		"/h/.claude/projects/other/s.jsonl":                          "",
		"":                                                           "",
	} {
		if got := m.Wing(tp); got != want {
			t.Errorf("Wing(%q) = %q, want %q", tp, got, want)
		}
	}
	m.Mine = false
	if got := m.Wing("/h/.claude/projects/-work-user-my-projects-foo/s.jsonl"); got != "" {
		t.Errorf("off: Wing = %q", got)
	}
	t.Setenv("HOME", "/work/user")
	if got := (Mempalace{Mine: true, ProjectsRoot: "~/my.projects"}).Wing("/h/.claude/projects/-work-user-my-projects-foo/s.jsonl"); got != "foo" {
		t.Errorf("~: Wing = %q", got)
	}
	for _, bad := range []string{
		"[integrations.claude_mem]\nwork_state_url = \"file:///etc/passwd\"\n",
		"[integrations.claude_mem]\nwork_state_url = \"127.0.0.1:9\"\n",
		"[integrations.claude_mem]\nwork_state_url = \"http://127.0.0.1:9/ws?a=b\"\n",
		"[integrations.claude_mem]\nwork_state_url = \"http://127.0.0.1:9/ws#x\"\n",
		"[integrations.mempalace]\nprojects_root = \"projects\"\n",
		"[integrations.mempalace]\nmine = true\n",
		"[integrations.mempalace]\nmine = true\nprojects_root = \"/p\"\nbin = \"\"\n",
		"[integrations.nope]\nx = 1\n",
	} {
		if _, err := Load(write(t, bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestOverlayReplacesOnlyGivenKeys(t *testing.T) {
	c, err := Load(write(t, `
[global]
mode = "enforce"
[rules.loop_guard]
fail_threshold = 5
[rules.destructive.fs]
main = "deny"
[rules.sensitive_paths]
mode = ""
paths = ["x"]
[[rules.ponytail.signatures]]
label = "l"
regex = "r"
hint = "h"
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Rules.LoopGuard.FailThreshold != 5 || c.Rules.LoopGuard.TTLSeconds != 1800 {
		t.Fatalf("loop_guard: %+v", c.Rules.LoopGuard)
	}
	if c.Rules.Destructive.FS.Main != "deny" || c.Rules.Destructive.FS.Subagent != "deny" || len(c.Rules.Destructive.FS.AllowRoots) != 2 {
		t.Fatalf("embedded policy: %+v", c.Rules.Destructive.FS)
	}
	if !reflect.DeepEqual(c.Rules.SensitivePaths.Paths, []string{"x"}) {
		t.Fatalf("arrays must replace defaults, got %v", c.Rules.SensitivePaths.Paths)
	}
	if len(c.Rules.Ponytail.Signatures) != 1 {
		t.Fatalf("array tables must replace defaults, got %d", len(c.Rules.Ponytail.Signatures))
	}
	if c.Mode("sensitive_paths") != "enforce" || c.Mode("destructive") != "log" {
		t.Fatal("empty rule mode must fall back to global")
	}
}

func TestBadConfigYieldsDefaultsAndError(t *testing.T) {
	cases := map[string]string{
		"typo":        "[rules.loop_guard]\nfail_treshold = 2\n[rules.nope]\nx = 1\n",
		"syntax":      "[rules.loop_guard\n",
		"type":        "[rules.loop_guard]\nfail_threshold = \"two\"\n",
		"mode":        "[rules.lint]\nmode = \"enforcee\"\n",
		"globalmode":  "[global]\nmode = \"\"\n",
		"policy":      "[rules.destructive.git]\nmain = \"maybe\"\n",
		"regex":       "[rules.risk_line]\npattern = \"(\"\n",
		"fail0":       "[rules.loop_guard]\nfail_threshold = 0\n",
		"streak0":     "[rules.loop_guard]\nstreak_threshold = 0\n",
		"ttl0":        "[rules.loop_guard]\nttl_seconds = -1\n",
		"maxlines0":   "[rules.commit_message]\nmax_lines = 0\n",
		"bashchars":   "[rules.output_cap]\nbash_chars = 9900\n", // CC spills hook values over 10k
		"mcpchars0":   "[rules.output_cap]\nmcp_chars = 0\n",
		"metricsmode": "[metrics]\nmode = \"maybe\"\n",
		"metricstypo": "[metrics]\nkeeep = 2\n",
		"keepneg":     "[metrics]\nkeep = -1\n",
		"keepbig":     "[metrics]\nkeep = 101\n",
		"maxbytes0":   "[metrics]\nmax_bytes = 0\n",
		"regenerable": "[rules.destructive.fs]\nregenerable = [\"var/[cache\"]\n",
	}
	for name, body := range cases {
		c, err := Load(write(t, body))
		if err == nil {
			t.Fatalf("%s: want error", name)
		}
		if !reflect.DeepEqual(c, Defaults()) {
			t.Fatalf("%s: want pristine defaults", name)
		}
		if name == "typo" && (!strings.Contains(err.Error(), "rules.loop_guard.fail_treshold") || !strings.Contains(err.Error(), "rules.nope")) {
			t.Fatalf("typo error must name every bad key: %v", err)
		}
	}
}

func TestPathUsesHome(t *testing.T) {
	h := t.TempDir()
	t.Setenv("HOME", h)
	if p, err := Path(); err != nil || p != filepath.Join(h, ".claude", "policy.toml") {
		t.Fatalf("Path() = %q, %v", p, err)
	}
	t.Setenv("HOME", "relative")
	if _, err := Path(); err == nil {
		t.Fatal("relative HOME must be rejected")
	}
}

func TestMetricsTable(t *testing.T) {
	if m := Defaults().Metrics; m.Mode != "on" || m.Keep != 4 || m.MaxBytes != 10485760 {
		t.Fatalf("defaults: %+v", m)
	}
	c, err := Load(write(t, "[metrics]\nmode = \"off\"\nkeep = 2\nmax_bytes = 100\n"))
	if err != nil {
		t.Fatal(err)
	}
	if m := c.Metrics; m.Mode != "off" || m.Keep != 2 || m.MaxBytes != 100 {
		t.Fatalf("parsed: %+v", m)
	}
}

func TestSearchScopeTable(t *testing.T) {
	if m := Defaults().Rules.SearchScope; m.Mode != "log" || len(m.Dirs) != 1 || m.Dirs[0] != "vendor" {
		t.Fatalf("defaults: %+v", m)
	}
	c, err := Load(write(t, "[rules.search_scope]\nmode = \"enforce\"\ndirs = [\"vendor\", \"node_modules\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if m := c.Rules.SearchScope; c.Mode("search_scope") != "enforce" || len(m.Dirs) != 2 {
		t.Fatalf("parsed: %+v", m)
	}
}

func TestSearchBatchTable(t *testing.T) {
	if m := Defaults().Rules.SearchBatch; m.Mode != "log" || m.Threshold != 4 {
		t.Fatalf("defaults: %+v", m)
	}
	c, err := Load(write(t, "[rules.search_batch]\nmode = \"enforce\"\nthreshold = 6\n"))
	if err != nil {
		t.Fatal(err)
	}
	if m := c.Rules.SearchBatch; c.Mode("search_batch") != "enforce" || m.Threshold != 6 {
		t.Fatalf("loaded: %+v", m)
	}
	if _, err := Load(write(t, "[rules.search_batch]\nthreshold = 0\n")); err == nil {
		t.Fatal("threshold 0 must be rejected")
	}
}

func TestPIIEgressNeedlesValidated(t *testing.T) {
	c, err := Load(write(t, "[rules.pii_egress]\nneedles = [\"@acme.test\"]\n"))
	if err != nil || c.Rules.PIIEgress.Needles[0] != "@acme.test" || c.Mode("pii_egress") != "log" {
		t.Fatalf("valid needle: %v %+v", err, c.Rules.PIIEgress)
	}
	many := strings.Repeat(`"needle-x",`, 33)
	for _, body := range []string{
		"[rules.pii_egress]\nneedles = [\"a\"]\n",      // matches almost every call
		"[rules.pii_egress]\nneedles = [\"  ab  \"]\n", // trimmed length counts
		"[rules.pii_egress]\nneedles = [" + many + "]\n",
		"[rules.pii_egress]\nneedles = [\"" + strings.Repeat("x", 257) + "\"]\n",
	} {
		if _, err := Load(write(t, body)); err == nil {
			t.Fatalf("must be rejected: %.60s", body)
		}
	}
}

// projectTree builds home/.claude/policy.toml (global) and
// home/proj/.claude/policy.toml (project); "" skips a file.
func projectTree(t *testing.T, global, project string) (globalPath, proj string) {
	t.Helper()
	home := t.TempDir()
	proj = filepath.Join(home, "proj")
	for dir, body := range map[string]string{home: global, proj: project} {
		if err := os.MkdirAll(filepath.Join(dir, ".claude"), 0o700); err != nil {
			t.Fatal(err)
		}
		if body == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, ".claude", "policy.toml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(home, ".claude", "policy.toml"), proj
}

func TestProjectPathWalksUpAndSkipsGlobal(t *testing.T) {
	global, proj := projectTree(t, "[global]\nmode = \"enforce\"\n", "[rules.destructive.git]\nallow_actions = [\"rebase\"]\n")
	want := filepath.Join(proj, ".claude", "policy.toml")
	lane := filepath.Join(proj, ".claude", "worktrees", "lane", "src")
	if got := ProjectPath(lane, global); got != want {
		t.Fatalf("worktree cwd: got %q want %q", got, want)
	}
	if got := ProjectPath(proj, global); got != want {
		t.Fatalf("project root cwd: got %q want %q", got, want)
	}
	// a sibling of the project walks up to home, whose file is the global one
	if got := ProjectPath(filepath.Join(filepath.Dir(proj), "other"), global); got != "" {
		t.Fatalf("the global file must never be the project file, got %q", got)
	}
	if got := ProjectPath("proj", global); got != "" {
		t.Fatalf("relative cwd: got %q", got)
	}
	if got := ProjectPath("", global); got != "" {
		t.Fatalf("empty cwd: got %q", got)
	}
}

func TestLoadForOverlaysProjectKeys(t *testing.T) {
	global, proj := projectTree(t, "[rules.destructive]\nmode = \"enforce\"\n", "[rules.destructive.git]\nallow_actions = [\"rebase\"]\n")
	c, err := LoadFor(global, proj)
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode("destructive") != "enforce" || c.Rules.Destructive.Git.Main != "ask" {
		t.Fatalf("global values lost: %q %+v", c.Mode("destructive"), c.Rules.Destructive.Git)
	}
	if !reflect.DeepEqual(c.Rules.Destructive.Git.AllowActions, []string{"rebase"}) {
		t.Fatalf("project allow_actions: %v", c.Rules.Destructive.Git.AllowActions)
	}
	// outside the project the same global file gives no exception
	if c, err := LoadFor(global, filepath.Dir(proj)); err != nil || len(c.Rules.Destructive.Git.AllowActions) != 0 {
		t.Fatalf("outside the project: %v %v", c.Rules.Destructive.Git.AllowActions, err)
	}
}

func TestLoadForBadProjectFileKeepsGlobal(t *testing.T) {
	const global = "[rules.destructive]\nmode = \"enforce\"\n"
	cases := map[string]string{
		"rule mode":       "[rules.destructive]\nmode = \"off\"\n",
		"global mode":     "[global]\nmode = \"off\"\n",
		"category policy": "[rules.destructive.git]\nmain = \"allow\"\nallow_actions = [\"rebase\"]\n",
		"inline policy":   "[rules.destructive]\ngit = { main = \"allow\" }\n",
		"hard_deny":       "[rules.destructive]\nhard_deny = []\n",
		"protected refs":  "[rules.destructive.git]\nprotected_refs = []\n",
		"other rule":      "[rules.loop_guard]\nfail_threshold = 99\n",
		"wide action":     "[rules.destructive.git]\nallow_actions = [\"rebase\", \"clean\"]\n",
		"unknown key":     "[rules.destructive.git]\nallow_action = [\"rebase\"]\n",
		"bad toml":        "[rules.destructive.git\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			gp, proj := projectTree(t, global, body)
			want, err := Load(gp)
			if err != nil {
				t.Fatal(err)
			}
			got, err := LoadFor(gp, proj)
			if err == nil {
				t.Fatal("a project file outside the allowed keys must be an error")
			}
			if !strings.Contains(err.Error(), filepath.Join(proj, ".claude", "policy.toml")) {
				t.Fatalf("the error must name the project file: %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("the global config must stay in force unchanged, got %+v", got.Rules.Destructive)
			}
		})
	}
}

func TestGitAllowActionsValidated(t *testing.T) {
	c, err := Load(write(t, "[rules.destructive.git]\nallow_actions = [\"rebase\", \"clean\"]\n"))
	if err != nil || len(c.Rules.Destructive.Git.AllowActions) != 2 {
		t.Fatalf("the global file may allow any known action: %v %v", c.Rules.Destructive.Git.AllowActions, err)
	}
	if _, err := Load(write(t, "[rules.destructive.git]\nallow_actions = [\"frobnicate\"]\n")); err == nil {
		t.Fatal("an unknown git action must be rejected")
	}
	if len(Defaults().Rules.Destructive.Git.AllowActions) != 0 {
		t.Fatal("no action is allowed by default")
	}
}

func TestGitProtectedRefs(t *testing.T) {
	if got := Defaults().Rules.Destructive.Git.ProtectedRefs; !reflect.DeepEqual(got, []string{"main", "master", "production", "staging"}) {
		t.Fatalf("default protected_refs: %v", got)
	}
	if c, err := Load(write(t, "[rules.destructive.git]\nprotected_refs = []\n")); err != nil || len(c.Rules.Destructive.Git.ProtectedRefs) != 0 {
		t.Fatalf("an empty list turns the check off: %v %v", c.Rules.Destructive.Git.ProtectedRefs, err)
	}
	for _, bad := range []string{`""`, `" "`, `"refs/heads/main"`, `"rel ease"`, `"main*"`} {
		if _, err := Load(write(t, "[rules.destructive.git]\nprotected_refs = ["+bad+"]\n")); err == nil {
			t.Errorf("protected_refs = [%s] must be rejected", bad)
		}
	}
}

func TestLoadForProjectFileSilentOnGlobalActions(t *testing.T) {
	// the project value limit applies to what the project file sets, not to
	// what the global file already allows
	global, proj := projectTree(t, "[rules.destructive.git]\nallow_actions = [\"clean\"]\n", "# nothing set\n")
	c, err := LoadFor(global, proj)
	if err != nil || !reflect.DeepEqual(c.Rules.Destructive.Git.AllowActions, []string{"clean"}) {
		t.Fatalf("got %v %v", c.Rules.Destructive.Git.AllowActions, err)
	}
}

// Review: HOME through a symlink names the global file by another
// spelling; it is still the global file.
func TestProjectPathSkipsGlobalThroughSymlink(t *testing.T) {
	global, proj := projectTree(t, "[global]\nmode = \"enforce\"\n", "")
	realHome := filepath.Dir(proj)
	link := filepath.Join(t.TempDir(), "home")
	if err := os.Symlink(realHome, link); err != nil {
		t.Skip(err)
	}
	if got := ProjectPath(proj, filepath.Join(link, ".claude", "policy.toml")); got != "" {
		t.Fatalf("got %q (the global file is %q)", got, global)
	}
	if got := ProjectPath(filepath.Join(link, "proj"), global); got != "" {
		t.Fatalf("cwd through the link: got %q", got)
	}
}

// policy.example.toml documents the defaults: decoding it must change nothing.
func TestExamplePolicyIsTheDefaults(t *testing.T) {
	c, err := Load("../../policy.example.toml")
	if err != nil {
		t.Fatal(err)
	}
	// %+v, not DeepEqual: the file spells out empty lists the defaults leave nil.
	if got, want := fmt.Sprintf("%+v", c), fmt.Sprintf("%+v", Defaults()); got != want {
		t.Fatalf("policy.example.toml drifted from Defaults():\n got %s\nwant %s", got, want)
	}
}

// The suite profile must stay loadable: every other test package builds on it.
func TestSuitePolicyLoads(t *testing.T) {
	if _, err := Load("../../testdata/suite.policy.toml"); err != nil {
		t.Fatal(err)
	}
}
