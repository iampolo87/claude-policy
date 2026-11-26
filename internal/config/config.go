// Package config loads ~/.claude/policy.toml over compiled-in defaults.
// It is decoded on every call (hot load, no cache). Path strings such as
// "$scratchpad_dir" and "~" stay raw; rules expand them.
package config

import (
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/bmatcuk/doublestar/v4"
)

type Config struct {
	Global Global `toml:"global"`
	Rules  Rules  `toml:"rules"`
	// Metrics configures the per-call metrics.jsonl sink.
	Metrics Metrics `toml:"metrics"`
	// Integrations are optional couplings to tools outside Claude Code.
	Integrations Integrations `toml:"integrations"`
}

// Integrations: every one is off until policy.toml enables it and points it
// at its endpoint or path. Nothing here runs by default.
type Integrations struct {
	ClaudeMem ClaudeMem `toml:"claude_mem"`
	Mempalace Mempalace `toml:"mempalace"`
	Herdr     Herdr     `toml:"herdr"`
}

// ClaudeMem: WorkStateURL is fetched as GET <url>?cwd=<cwd> at PreCompact and
// its plain-text body goes into the checkpoint; "" skips the section.
type ClaudeMem struct {
	WorkStateURL string `toml:"work_state_url"`
}

// Mempalace: Mine makes `claude-policy mine` (an async PreCompact hook) run
// `<bin> mine <transcript> --wing <wing>`. ProjectsRoot is the directory the
// wings are named below ("~" expands); a session started outside it is skipped.
// ponytail: Claude Code's project directory name writes "/" and "-" alike, so
// a sibling whose name extends the root's (projects-old) reads as inside it.
type Mempalace struct {
	Mine         bool   `toml:"mine"`
	Bin          string `toml:"bin"`
	ProjectsRoot string `toml:"projects_root"`
}

// Wing is the mempalace wing of a transcript: its Claude Code project
// directory name with the ProjectsRoot prefix removed. "" when the
// integration is off or the session did not start below ProjectsRoot.
func (m Mempalace) Wing(transcriptPath string) string {
	root := m.ProjectsRoot
	if !m.Mine || root == "" || transcriptPath == "" {
		return ""
	}
	if root == "~" || strings.HasPrefix(root, "~/") {
		h, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		root = h + root[1:]
	}
	// Claude Code names a project directory after its cwd, every character
	// outside [A-Za-z0-9] turned into "-".
	prefix := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return '-'
	}, filepath.Clean(root)) + "-"
	dir := filepath.Base(filepath.Dir(transcriptPath))
	if wing := strings.TrimPrefix(dir, prefix); wing != dir {
		return wing
	}
	return ""
}

// Herdr: Report makes `claude-policy statusline` report model, effort,
// context and cost to the herdr pane it runs in. Notice is a line added at
// SessionStart inside a pane; "{pane}" expands to the pane id.
type Herdr struct {
	Report bool   `toml:"report"`
	Notice string `toml:"notice"`
}

// Metrics: Mode on|off; Keep rotated generations; MaxBytes rotation size.
type Metrics struct {
	Mode     string `toml:"mode"`
	Keep     int    `toml:"keep"`
	MaxBytes int64  `toml:"max_bytes"`
}

type Global struct {
	Mode string `toml:"mode"` // default for rules that omit mode
}

type Rules struct {
	Destructive    Destructive    `toml:"destructive"`
	SensitivePaths SensitivePaths `toml:"sensitive_paths"`
	EditSurfaces   EditSurfaces   `toml:"edit_surfaces"`
	RiskLine       RiskLine       `toml:"risk_line"`
	OutputCap      OutputCap      `toml:"output_cap"`
	LoopGuard      LoopGuard      `toml:"loop_guard"`
	CommitMessage  CommitMessage  `toml:"commit_message"`
	ExploreModel   ExploreModel   `toml:"explore_model"`
	Ponytail       Ponytail       `toml:"ponytail"`
	Lint           Lint           `toml:"lint"`
	TimeBudget     TimeBudget     `toml:"time_budget"`
	SessionNotice  SessionNotice  `toml:"session_notice"`
	Checkpoint     Checkpoint     `toml:"checkpoint"`
	SearchScope    SearchScope    `toml:"search_scope"`
	SearchBatch    SearchBatch    `toml:"search_batch"`
	PIIEgress      PIIEgress      `toml:"pii_egress"`
}

// Policy is the action per actor for a destructive category: allow|ask|deny.
type Policy struct {
	Main     string `toml:"main"`
	Subagent string `toml:"subagent"`
}

type Destructive struct {
	Mode     string    `toml:"mode"`
	HardDeny []string  `toml:"hard_deny"`
	Git      GitPolicy `toml:"git"`
	FS       FSPolicy  `toml:"fs"`
	SQL      Policy    `toml:"sql"`
	Magento  Magento   `toml:"magento"`
}

type GitPolicy struct {
	Policy
	// AllowActions are git subcommands (GitActions) the main agent runs
	// without the git policy being consulted. Subagents are not exempted.
	AllowActions []string `toml:"allow_actions"`
	// ProtectedRefs are branch names (no refs/heads/) a push may not reach
	// and no other local branch may take as its upstream unasked. Global
	// only, and never exempted by AllowActions.
	ProtectedRefs []string `toml:"protected_refs"`
}

// GitActions are the subcommands the destructive rule recognizes.
var GitActions = []string{"push", "reset", "restore", "clean", "rebase", "checkout", "branch", "stash"}

// projectKeys are the only keys a project file (ProjectPath) may set, with
// the values it may give them (nil: any value the global file accepts).
// Modes, hard_deny and the per-category allow|ask|deny stay global: the
// project file lives where the guarded agent works and comes with a clone.
// rebase alone: its result is recoverable from the reflog.
var projectKeys = map[string][]string{
	"rules.destructive.git.allow_actions": {"rebase"},
}

type FSPolicy struct {
	Policy
	AllowRoots []string `toml:"allow_roots"`
	// Regenerable are doublestar globs of build output a recursive rm may
	// remove, relative to the nearest enclosing work tree (a .git entry).
	Regenerable []string `toml:"regenerable"`
}

type Magento struct {
	Policy
	Globs []string `toml:"globs"`
}

type SensitivePaths struct {
	Mode  string   `toml:"mode"`
	Paths []string `toml:"paths"`
}

type EditSurfaces struct {
	Mode          string   `toml:"mode"`
	Heading       string   `toml:"heading"`
	Missing       string   `toml:"missing"` // allow | deny
	AlwaysAllowed []string `toml:"always_allowed"`
}

type RiskLine struct {
	Mode    string `toml:"mode"`
	Pattern string `toml:"pattern"`
	// Reminder is the context injected at a turn's first code edit; it must
	// describe a line Pattern accepts.
	Reminder string   `toml:"reminder"`
	Skip     []string `toml:"skip"`
	Docs     []string `toml:"docs"` // doublestar globs on the absolute path; edits matching them need no Risk line
	// DocsExcept are docs-glob matches that still need one (agent
	// instructions, build and crawler config).
	DocsExcept []string `toml:"docs_except"`
}

type OutputCap struct {
	Mode      string   `toml:"mode"`
	BashChars int      `toml:"bash_chars"`
	MCPChars  int      `toml:"mcp_chars"`
	Read      string   `toml:"read"`       // a mode; enforce caps only ReadPaths, other Reads stay log-only
	ReadPaths []string `toml:"read_paths"` // doublestar globs on the absolute path; "~/" expands
	Exempt    []string `toml:"exempt"`
}

type LoopGuard struct {
	Mode            string `toml:"mode"`
	FailThreshold   int    `toml:"fail_threshold"`
	TTLSeconds      int    `toml:"ttl_seconds"`
	StreakThreshold int    `toml:"streak_threshold"`
}

// SearchScope names the directories whose gitignored status makes a
// recursive search silently skip them.
type SearchScope struct {
	Mode string   `toml:"mode"`
	Dirs []string `toml:"dirs"`
}

// SearchBatch: Threshold is how many one-lookup messages in a row earn the
// batching nudge.
type SearchBatch struct {
	Mode      string `toml:"mode"`
	Threshold int    `toml:"threshold"`
}

type CommitMessage struct {
	Mode     string   `toml:"mode"`
	MaxLines int      `toml:"max_lines"`
	Deny     []string `toml:"deny"`
}

// PIIEgress: Needles are extra strings (matched case-insensitively) that
// must not leave in a Bash, WebFetch or WebSearch call without asking; the
// Claude account email is always one of them.
type PIIEgress struct {
	Mode    string   `toml:"mode"`
	Needles []string `toml:"needles"`
}

type ExploreModel struct {
	Mode         string `toml:"mode"`
	DefaultModel string `toml:"default_model"`
}

// Ponytail: LevelFile, when set, is a file holding off|lite|full|ultra that
// overrides the level per machine ("~" expands); "" means always full.
type Ponytail struct {
	Mode       string      `toml:"mode"`
	LevelFile  string      `toml:"level_file"`
	Signatures []Signature `toml:"signatures"`
}

// Signature regexes are matched case-insensitively.
type Signature struct {
	Label string `toml:"label"`
	Regex string `toml:"regex"`
	Hint  string `toml:"hint"`
}

type Lint struct {
	Mode    string `toml:"mode"`
	PHP     bool   `toml:"php"`
	Node    bool   `toml:"node"`
	PHPStan bool   `toml:"phpstan"`
	PHPCS   bool   `toml:"phpcs"`
	// PHPCSStandard is passed as --standard; "" leaves it to the project's ruleset.
	PHPCSStandard string `toml:"phpcs_standard"`
}

type TimeBudget struct {
	Mode string `toml:"mode"`
}

// SessionNotice: Startup is a line added to every SessionStart ("" for
// none); PostCompact is the line added after a compaction.
type SessionNotice struct {
	Mode              string  `toml:"mode"`
	ColdResumeUSDWarn float64 `toml:"cold_resume_usd_warn"`
	Startup           string  `toml:"startup"`
	PostCompact       string  `toml:"post_compact"`
}

type Checkpoint struct {
	Mode string `toml:"mode"`
}

// Defaults returns a fresh copy of the compiled-in config: every rule in
// log mode, every integration off.
func Defaults() *Config {
	ask := Policy{Main: "ask", Subagent: "deny"}
	// Claude Code's per-user temp root on Linux; the session's own scratchpad
	// is $scratchpad_dir wherever it lives.
	tmp := fmt.Sprintf("/tmp/claude-%d", os.Getuid())
	return &Config{
		Global:  Global{Mode: "log"},
		Metrics: Metrics{Mode: "on", Keep: 4, MaxBytes: 10 << 20},
		Rules: Rules{
			Destructive: Destructive{
				Mode:     "log",
				HardDeny: []string{"rm -rf /", "rm -rf ~", "--no-preserve-root", "mkfs"},
				Git:      GitPolicy{Policy: ask, ProtectedRefs: []string{"main", "master", "production", "staging"}},
				FS:       FSPolicy{Policy: ask, AllowRoots: []string{"$scratchpad_dir", tmp}},
				SQL:      ask,
				Magento:  Magento{Policy: ask, Globs: []string{"setup:uninstall", "module:uninstall", "setup:db:*clean*", "indexer:reset"}},
			},
			SensitivePaths: SensitivePaths{Mode: "log", Paths: []string{".env", "app/etc/env.php", "auth.json"}},
			EditSurfaces: EditSurfaces{
				Mode:          "log",
				Heading:       "## Allowed edit surfaces",
				Missing:       "allow",
				AlwaysAllowed: []string{"$scratchpad_dir/**", tmp + "/**"},
			},
			RiskLine: RiskLine{
				Mode:    "log",
				Pattern: `(?m)^Risk: (none|item [1-6])`,
				Reminder: "risk_line: this turn edits code. End the final message with a line `Risk: none` or " +
					"`Risk: item N (reason)`, N being one of: 1 irreversible data effects, 2 security, " +
					"3 consumed contracts, 4 concurrency, 5 delivery or environment, 6 no test would catch a regression.",
				Skip: []string{"$scratchpad_dir", "~/.claude/plans"},
				Docs: []string{"**/*.md", "**/*.txt"},
				DocsExcept: []string{"**/CLAUDE*.md", "**/AGENTS*.md", "**/GEMINI*.md", "**/SKILL.md", "**/.claude/**", "**/.github/**",
					"**/.cursor/**", "**/requirements*.txt", "**/requirements/**", "**/CMakeLists.txt", "**/robots.txt"},
			},
			OutputCap: OutputCap{
				Mode:      "log",
				BashChars: 8000,
				MCPChars:  8000,
				Read:      "log",
				// CC's own spill files and scratchpad dumps, read back whole.
				ReadPaths: []string{"~/.claude/projects/*/*/tool-results/**", "/tmp/claude-*/*/*/scratchpad/**"},
				Exempt:    []string{"mcp__chrome-devtools__take_screenshot"},
			},
			LoopGuard: LoopGuard{Mode: "log", FailThreshold: 2, TTLSeconds: 1800, StreakThreshold: 4},
			CommitMessage: CommitMessage{
				Mode:     "log",
				MaxLines: 3,
				Deny:     []string{"co-authored-by", "generated with", "noreply@anthropic.com", "claude.com/claude-code", "claude-session:", "claude.ai/code/session", "🤖", "--no-verify"},
			},
			ExploreModel: ExploreModel{Mode: "log", DefaultModel: "haiku"},
			Ponytail: Ponytail{Mode: "log", Signatures: []Signature{
				{"debounce", `\b(function\s+debounce|const\s+debounce\s*=)`, "debounce exists (lodash / 3-line native); don't reinvent"},
				{"throttle", `\b(function\s+throttle|const\s+throttle\s*=)`, "throttle exists (lodash); don't reinvent"},
				{"uuid-mathrandom", `Math\.random\(\)\.toString\(`, "use crypto.randomUUID() (native), not Math.random() ids"},
				{"email-regex", `\[\^@\]\+@`, "email validation: use a vetted validator / input[type=email], not a hand regex"},
				{"php-polyfill", `function\s+(str_contains|str_starts_with|str_ends_with|array_is_list)\s*\(`, "PHP 8+ has this natively; drop the polyfill"},
				{"php-uuid", `function\s+\w*[Uu]uid\w*\s*\(`, "PHP uuid: prefer ramsey/uuid or a random_bytes helper if already present"},
			}},
			// phpstan and phpcs are opt-in: slow, and only useful where the project configures them.
			Lint:       Lint{Mode: "log", PHP: true, Node: true},
			TimeBudget: TimeBudget{Mode: "log"},
			SessionNotice: SessionNotice{Mode: "log", ColdResumeUSDWarn: 0.50,
				PostCompact: "[POST-COMPACT] Summary is lossy. Before editing: reconcile git state and checks, then restate the task in ≤10 bullets."},
			Checkpoint:  Checkpoint{Mode: "log"},
			SearchScope: SearchScope{Mode: "log", Dirs: []string{"vendor"}},
			SearchBatch: SearchBatch{Mode: "log", Threshold: 4},
			PIIEgress:   PIIEgress{Mode: "log"},
		},
		Integrations: Integrations{Mempalace: Mempalace{Bin: "mempalace"}},
	}
}

// Path is ~/.claude/policy.toml; HOME must be absolute.
func Path() (string, error) {
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(h) {
		return "", fmt.Errorf("HOME %q is not absolute", h)
	}
	return filepath.Join(h, ".claude", "policy.toml"), nil
}

// Load decodes path over the defaults. A missing file is not an error. Any
// read, parse, unknown-key or validation error returns pristine defaults
// together with the error (one joined entry per problem).
func Load(path string) (*Config, error) {
	c := Defaults()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return Defaults(), err
	}
	md, err := toml.Decode(string(data), c)
	if err != nil {
		return Defaults(), err
	}
	var errs []error
	for _, k := range md.Undecoded() {
		errs = append(errs, fmt.Errorf("unknown key %s", k))
	}
	errs = append(errs, c.validate()...)
	if len(errs) > 0 {
		return Defaults(), errors.Join(errs...)
	}
	return c, nil
}

// ProjectPath is the nearest .claude/policy.toml at or above cwd, never the
// global file itself (a cwd under HOME walks up to it; compared as files,
// HOME may be a symlink); "" for none or a
// relative cwd. A lane worktree under .claude/worktrees/ finds its repo's.
func ProjectPath(cwd, global string) string {
	if !filepath.IsAbs(cwd) {
		return ""
	}
	g, _ := os.Stat(global) // nil when missing: SameFile is then false
	for dir := filepath.Clean(cwd); ; dir = filepath.Dir(dir) {
		p := filepath.Join(dir, ".claude", "policy.toml")
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && !os.SameFile(st, g) {
			return p
		}
		if dir == filepath.Dir(dir) {
			return ""
		}
	}
}

// LoadFor is Load(global) with cwd's project file decoded on top. The
// project file may set projectKeys only; with any error in it the global
// config stays in force unchanged and the error names the file.
func LoadFor(global, cwd string) (*Config, error) {
	c, err := Load(global)
	if err != nil {
		return c, fmt.Errorf("%s (using defaults):\n%w", global, err)
	}
	pp := ProjectPath(cwd, global)
	if pp == "" {
		return c, nil
	}
	fail := func(err error) (*Config, error) {
		return c, fmt.Errorf("%s (project file ignored):\n%w", pp, err)
	}
	data, err := os.ReadFile(pp)
	if err != nil {
		return fail(err)
	}
	merged, err := Load(global) // a second copy: a failed decode leaves its target half written
	if err != nil {
		return fail(err) // the global file changed between the two reads
	}
	md, err := toml.Decode(string(data), merged)
	if err != nil {
		return fail(err)
	}
	var errs []error
	for _, k := range md.Undecoded() {
		errs = append(errs, fmt.Errorf("unknown key %s", k))
	}
	const allowKey = "rules.destructive.git.allow_actions"
	for _, k := range md.Keys() {
		key := k.String()
		_, ok := projectKeys[key]
		for a := range projectKeys { // a table on the way to an allowed key
			ok = ok || strings.HasPrefix(a, key+".")
		}
		if !ok {
			errs = append(errs, fmt.Errorf("%s: only the global file may set it", key))
		}
		if key == allowKey {
			for _, a := range merged.Rules.Destructive.Git.AllowActions {
				if !slices.Contains(projectKeys[allowKey], a) {
					errs = append(errs, fmt.Errorf("%s: only the global file may allow %q", allowKey, a))
				}
			}
		}
	}
	if errs = append(errs, merged.validate()...); len(errs) > 0 {
		return fail(errors.Join(errs...))
	}
	return merged, nil
}

// modes maps every configured rule name to its mode field.
func (c *Config) modes() map[string]*string {
	r := &c.Rules
	return map[string]*string{
		"destructive":     &r.Destructive.Mode,
		"sensitive_paths": &r.SensitivePaths.Mode,
		"edit_surfaces":   &r.EditSurfaces.Mode,
		"risk_line":       &r.RiskLine.Mode,
		"output_cap":      &r.OutputCap.Mode,
		"loop_guard":      &r.LoopGuard.Mode,
		"commit_message":  &r.CommitMessage.Mode,
		"explore_model":   &r.ExploreModel.Mode,
		"ponytail":        &r.Ponytail.Mode,
		"lint":            &r.Lint.Mode,
		"time_budget":     &r.TimeBudget.Mode,
		"session_notice":  &r.SessionNotice.Mode,
		"checkpoint":      &r.Checkpoint.Mode,
		"search_scope":    &r.SearchScope.Mode,
		"search_batch":    &r.SearchBatch.Mode,
		"pii_egress":      &r.PIIEgress.Mode,
	}
}

// Mode returns off|log|enforce for a rule: its own mode, else [global] mode.
func (c *Config) Mode(rule string) string {
	if p, ok := c.modes()[rule]; ok && *p != "" {
		return *p
	}
	return c.Global.Mode
}

var validModes = map[string]bool{"off": true, "log": true, "enforce": true}

func (c *Config) validate() []error {
	var errs []error
	oneOf := func(key, v string, ok map[string]bool) {
		if !ok[v] {
			errs = append(errs, fmt.Errorf("%s: invalid value %q", key, v))
		}
	}
	oneOf("global.mode", c.Global.Mode, validModes)
	m := c.modes()
	for _, name := range slices.Sorted(maps.Keys(m)) {
		if *m[name] != "" {
			oneOf("rules."+name+".mode", *m[name], validModes)
		}
	}
	oneOf("metrics.mode", c.Metrics.Mode, map[string]bool{"on": true, "off": true})
	if c.Metrics.Keep < 0 || c.Metrics.Keep > 100 {
		errs = append(errs, fmt.Errorf("metrics.keep: must be 0..100, got %d", c.Metrics.Keep))
	}
	if c.Metrics.MaxBytes < 1 {
		errs = append(errs, fmt.Errorf("metrics.max_bytes: must be >= 1, got %d", c.Metrics.MaxBytes))
	}
	oneOf("rules.output_cap.read", c.Rules.OutputCap.Read, validModes)
	for i, g := range c.Rules.OutputCap.ReadPaths {
		if !doublestar.ValidatePattern(g) {
			errs = append(errs, fmt.Errorf("rules.output_cap.read_paths[%d]: invalid glob %q", i, g))
		}
	}

	actions := map[string]bool{"allow": true, "ask": true, "deny": true}
	d := &c.Rules.Destructive
	for _, p := range []struct {
		cat string
		p   Policy
	}{{"git", d.Git.Policy}, {"fs", d.FS.Policy}, {"sql", d.SQL}, {"magento", d.Magento.Policy}} {
		oneOf("rules.destructive."+p.cat+".main", p.p.Main, actions)
		oneOf("rules.destructive."+p.cat+".subagent", p.p.Subagent, actions)
	}
	for i, a := range d.Git.AllowActions {
		if !slices.Contains(GitActions, a) {
			errs = append(errs, fmt.Errorf("rules.destructive.git.allow_actions[%d]: unknown action %q", i, a))
		}
	}
	for i, r := range d.Git.ProtectedRefs {
		if r == "" || strings.HasPrefix(r, "refs/") || strings.ContainsAny(r, " \t\n*?[{$`~^:\\") {
			errs = append(errs, fmt.Errorf("rules.destructive.git.protected_refs[%d]: not a short branch name: %q", i, r))
		}
	}
	for i, g := range d.FS.Regenerable {
		if !doublestar.ValidatePattern(g) {
			errs = append(errs, fmt.Errorf("rules.destructive.fs.regenerable[%d]: invalid glob %q", i, g))
		}
	}
	// a short needle asks on nearly every call; a long list nears the deadline,
	// past which the rule fails open.
	if n := len(c.Rules.PIIEgress.Needles); n > 32 {
		errs = append(errs, fmt.Errorf("rules.pii_egress.needles: at most 32, got %d", n))
	}
	for i, s := range c.Rules.PIIEgress.Needles {
		if n := len(strings.TrimSpace(s)); n < 5 || n > 256 {
			errs = append(errs, fmt.Errorf("rules.pii_egress.needles[%d]: trimmed length must be 5..256, got %d", i, n))
		}
	}
	if u := c.Integrations.ClaudeMem.WorkStateURL; u != "" {
		// ?cwd= is appended as is: a query or fragment of its own would swallow it.
		if p, err := url.Parse(u); err != nil || p.Scheme != "http" && p.Scheme != "https" || p.Host == "" || p.RawQuery != "" || p.Fragment != "" {
			errs = append(errs, fmt.Errorf("integrations.claude_mem.work_state_url: not an http(s) URL without query or fragment: %q", u))
		}
	}
	if m := c.Integrations.Mempalace; m.Mine && (m.Bin == "" || m.ProjectsRoot == "") {
		errs = append(errs, errors.New("integrations.mempalace: mine needs bin and projects_root"))
	}
	// a relative root never matches a transcript directory: mining would be silently off.
	if r := c.Integrations.Mempalace.ProjectsRoot; r != "" && r != "~" && !strings.HasPrefix(r, "~/") && !filepath.IsAbs(r) {
		errs = append(errs, fmt.Errorf("integrations.mempalace.projects_root: not an absolute or ~ path: %q", r))
	}
	oneOf("rules.edit_surfaces.missing", c.Rules.EditSurfaces.Missing, map[string]bool{"allow": true, "deny": true})

	for key, v := range map[string]int{
		"rules.loop_guard.fail_threshold":   c.Rules.LoopGuard.FailThreshold,
		"rules.loop_guard.streak_threshold": c.Rules.LoopGuard.StreakThreshold,
		"rules.loop_guard.ttl_seconds":      c.Rules.LoopGuard.TTLSeconds,
		"rules.commit_message.max_lines":    c.Rules.CommitMessage.MaxLines,
		"rules.search_batch.threshold":      c.Rules.SearchBatch.Threshold,
	} {
		if v < 1 {
			errs = append(errs, fmt.Errorf("%s: must be >= 1, got %d", key, v))
		}
	}

	// output_cap budgets include the pointer; CC spills hook values over 10k.
	for key, v := range map[string]int{
		"rules.output_cap.bash_chars": c.Rules.OutputCap.BashChars,
		"rules.output_cap.mcp_chars":  c.Rules.OutputCap.MCPChars,
	} {
		if v < 1000 || v > 9000 {
			errs = append(errs, fmt.Errorf("%s: must be in 1000..9000, got %d", key, v))
		}
	}

	rx := map[string]string{"rules.risk_line.pattern": c.Rules.RiskLine.Pattern}
	for i, s := range c.Rules.Ponytail.Signatures {
		rx[fmt.Sprintf("rules.ponytail.signatures[%d].regex", i)] = s.Regex
	}
	for _, key := range slices.Sorted(maps.Keys(rx)) {
		if _, err := regexp.Compile(rx[key]); err != nil {
			errs = append(errs, fmt.Errorf("%s: %v", key, err))
		}
	}
	return errs
}
