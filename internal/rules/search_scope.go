package rules

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/iampolo87/claude-policy/internal/config"
	"github.com/iampolo87/claude-policy/internal/hook"
	"github.com/iampolo87/claude-policy/internal/shell"
	"github.com/iampolo87/claude-policy/internal/state"
)

func init() { Registry = append(Registry, searchScope{}) }

// searchScope warns (context only, never a deny or rewrite) when a recursive
// grep through CC's ugrep shim, or rg/git grep, silently skips a gitignored directory
// such as vendor/.
type searchScope struct{}

func (searchScope) Name() string     { return "search_scope" }
func (searchScope) Events() []string { return []string{"PreToolUse"} }
func (searchScope) Tools() []string  { return []string{"Bash"} }

// maxSearchScan: the tokenizer is superlinear, see maxCommitScan.
const maxSearchScan = 16 << 10

var (
	searchGateRe   = regexp.MustCompile(`\b(grep|rg)\b`)
	assignRe       = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\+?=`)
	shimPrefix     = map[string]bool{"time": true, "-p": true, "!": true, "{": true, "if": true, "then": true, "else": true, "elif": true, "do": true, "while": true, "until": true}
	grepShortValue = "efABCmdDgJMNOt" // the shim runs ugrep: -g -J -M -N -O -t take values too
	grepLongValue  = setOf("regexp", "file", "include", "exclude", "exclude-dir", "include-dir", "max-count", "context", "after-context", "before-context", "directories", "devices", "label", "binary-files", "glob", "iglob", "jobs", "file-magic", "neg-regexp", "file-extension", "file-type")
	rgShortValue   = "efgtTmABCjMErd"
	rgLongValue    = setOf("regexp", "file", "glob", "iglob", "type", "type-not", "type-add", "max-count", "context", "after-context", "before-context", "threads", "max-columns", "encoding", "replace", "max-depth", "sort", "sortr", "max-filesize", "pre", "pre-glob", "engine", "ignore-file", "path-separator", "color", "colors", "context-separator", "field-match-separator", "dfa-size-limit", "regex-size-limit", "hyperlink-format", "hostname-bin")
	gitShortValue  = "efABCm" // -O takes only an attached value
	gitLongValue   = setOf("max-depth", "threads", "context", "after-context", "before-context", "max-count")
	ugrepDepthRe   = regexp.MustCompile(`^-[0-9][0-9,-]*$`) // -3, -10, -3-5, -3,5: depth, enables -r
)

func setOf(s ...string) map[string]bool {
	m := make(map[string]bool, len(s))
	for _, v := range s {
		m[v] = true
	}
	return m
}

// gitPath is resolved once; "" when git is not installed.
var gitPath = sync.OnceValues(func() (string, error) { return exec.LookPath("git") })

// checkIgnore reports whether dir (relative to root) is gitignored by pattern,
// tracked or not: ugrep and rg skip by pattern regardless of the index.
// ponytail: --no-index can false-positive for git grep on a force-tracked
// gitignored dir (git grep still searches tracked files there).
var checkIgnore = func(ctx context.Context, root, dir string) bool {
	if ctx.Err() != nil {
		return false
	}
	git, err := gitPath()
	if err != nil {
		return false
	}
	cmd := exec.CommandContext(ctx, git, "-C", root, "-c", "core.fsmonitor=false", "check-ignore", "--no-index", "-q", "--", dir)
	cmd.WaitDelay = 50 * time.Millisecond
	return cmd.Run() == nil // exit 1 = not ignored, 128 = not a repo
}

const dynamicChars = "$`\\*?[~{"

func (searchScope) Apply(ctx context.Context, in *hook.Input, cfg *config.Config, _ *state.Store) *hook.Decision {
	var ti struct {
		Command string `json:"command"`
	}
	if in.Cwd == "" || json.Unmarshal(in.ToolInput, &ti) != nil || len(ti.Command) > maxSearchScan ||
		!searchGateRe.MatchString(ti.Command) || shell.Opaque(ti.Command) {
		return nil
	}
	dirs := cfg.Rules.SearchScope.Dirs
	cwd, known := in.Cwd, true
	type key struct{ r, d string }
	cache := map[key]bool{}
	prevPipe := false
	segs := shell.Segments(ti.Command)
	for si, s := range segs {
		pipe := prevPipe
		prevPipe = s.Separator == "|" || s.Separator == "|&"
		if ctx.Err() != nil {
			return nil
		}
		name := s.Name()
		if name == "cd" || name == "pushd" || name == "popd" {
			a := s.Args()
			if h := os.Getenv("HOME"); len(a) == 1 && filepath.IsAbs(h) && (a[0] == "~" || strings.HasPrefix(a[0], "~/")) {
				a = []string{h + a[0][1:]} // bash expands a bare leading ~ from HOME
			}
			if name != "cd" || len(a) != 1 || a[0] == "-" || strings.ContainsAny(a[0], dynamicChars) {
				known = false
			} else if filepath.IsAbs(a[0]) {
				cwd = filepath.Clean(a[0])
			} else {
				cwd = filepath.Join(cwd, a[0])
			}
			continue
		}
		if !known {
			continue
		}
		kind, roots, typed := parseSearch(s, cwd, pipe)
		if kind == "" {
			continue
		}
		var opts []string
		if kind == "grep" {
			_, opts = scanOptions(s.Args(), grepShortValue, grepLongValue)
		}
		for i, r := range roots {
			for _, d := range dirs {
				child := filepath.Join(r, d)
				if excludedDir(opts, d) || droppedDownstream(segs, si, d) {
					continue
				}
				if fi, err := os.Stat(child); err != nil || !fi.IsDir() || coveredBy(roots, child) {
					continue
				}
				k := key{r, d}
				ig, seen := cache[k]
				if !seen {
					if ctx.Err() != nil {
						return nil
					}
					ig = checkIgnore(ctx, r, d)
					cache[k] = ig
				}
				if ig {
					return &hook.Decision{AdditionalContext: scopeMessage(d, kind, typed[i])}
				}
			}
		}
	}
	return nil
}

// coveredBy: some root is child or lies below it.
func coveredBy(roots []string, child string) bool {
	for _, r := range roots {
		if r == child || strings.HasPrefix(r, child+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// excludedDir: an --exclude-dir glob matches d. An unquoted {a,b} value is
// brace-expanded by bash into one option per item.
// ponytail: a quoted '{a,b}' is treated as expanded too.
func excludedDir(opts []string, d string) bool {
	for _, o := range opts {
		v, ok := strings.CutPrefix(o, "--exclude-dir=")
		if !ok {
			continue
		}
		alts := []string{v}
		if b, ok := strings.CutPrefix(v, "{"); ok && strings.HasSuffix(b, "}") {
			alts = strings.Split(strings.TrimSuffix(b, "}"), ",")
		}
		for _, g := range alts {
			if m, _ := filepath.Match(strings.TrimSuffix(g, "/"), d); m {
				return true
			}
		}
	}
	return false
}

// droppedDownstream: a later grep -v in the same pipeline names d, so the
// command drops d/ on purpose.
// ponytail: substring match, so `grep -v vendorx` silences too.
func droppedDownstream(segs []shell.Segment, i int, d string) bool {
	for j := i + 1; j < len(segs) && (segs[j-1].Separator == "|" || segs[j-1].Separator == "|&"); j++ {
		if segs[j].Name() != "grep" {
			continue
		}
		args := segs[j].Args()
		if _, opts := scanOptions(args, grepShortValue, grepLongValue); !hasEq(opts, "-v", "--invert-match") {
			continue
		}
		for _, a := range args {
			if strings.Contains(a, d) {
				return true
			}
		}
	}
	return false
}

func scopeMessage(d, kind, typed string) string {
	msg := func(e string) string {
		return "search_scope: " + d + "/ is gitignored and skipped by this " + kind + "; name it as a path (e.g. " + e + ") or use `command grep -r` to include it."
	}
	if m := msg(filepath.Join(typed, d)); len(m) <= 200 && !strings.ContainsAny(typed, "\n\r`") {
		return m
	}
	return msg(d)
}

// parseSearch classifies a segment. kind is "" unless it is a recursive
// search through a shim that skips ignored dirs; roots are absolute and typed
// are the roots as written ("" for the implicit cwd).
func parseSearch(s shell.Segment, cwd string, pipe bool) (kind string, roots, typed []string) {
	head, ok := s.Head()
	name := s.Name()
	native := name == "git" || name == "rg" // the real binaries skip ignored dirs too: paths and wrappers keep them
	if !ok || strings.ContainsAny(head.Value, "$`") || (!native && strings.Contains(head.Value, "/")) {
		return
	}
	for i := 0; i < s.Cursor && !native; i++ { // only shim-preserving words may precede a grep head
		t := s.Tokens[i]
		if t.Redirect {
			i++
			continue
		}
		if !shimPrefix[t.Value] && !assignRe.MatchString(t.Value) {
			return
		}
	}
	args := s.Args()
	var shortV string
	var longV map[string]bool
	switch s.Name() {
	case "grep":
		kind, shortV, longV = "grep", grepShortValue, grepLongValue
		for _, a := range args {
			if grepFallback(a) {
				return "", nil, nil
			}
		}
	case "rg":
		kind, shortV, longV = "rg", rgShortValue, rgLongValue
	case "git":
		var rest []string
		for i := 0; i < len(args); i++ {
			a := args[i]
			switch {
			case a == "-C":
				if i+1 >= len(args) || strings.ContainsAny(args[i+1], dynamicChars) {
					return
				}
				i++
				if filepath.IsAbs(args[i]) {
					cwd = filepath.Clean(args[i])
				} else {
					cwd = filepath.Join(cwd, args[i])
				}
			case a == "-c":
				i++
			case a == "grep":
				rest = args[i+1:]
				i = len(args)
			case strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--git-dir") && !strings.HasPrefix(a, "--work-tree"):
			default:
				return
			}
		}
		if rest == nil {
			return
		}
		kind, shortV, longV, args = "git grep", gitShortValue, gitLongValue, rest
	default:
		return
	}
	pos, opts := scanOptions(args, shortV, longV)
	has := func(names ...string) bool {
		for _, o := range opts {
			for _, n := range names {
				if o == n || strings.HasPrefix(o, n+"=") {
					return true
				}
			}
		}
		return false
	}
	patternGiven := has("-e", "-f", "--regexp", "--file")
	switch kind {
	case "grep":
		recursive := has("-r", "-R", "--recursive", "--dereference-recursive", "--depth") && !hasEq(opts, "--depth=1") ||
			hasEq(opts, "-d=recurse", "--directories=recurse") || depthArg(args)
		if !recursive || has("--no-ignore-files", "--all") {
			return "", nil, nil
		}
	case "rg":
		if has("--no-ignore", "--no-ignore-vcs", "-u", "--unrestricted") {
			return "", nil, nil
		}
		pipe = pipe || stdinRedirect(s) // rg searches stdin when it is a pipe or file; ugrep -r and git grep never do
		patternGiven = patternGiven || has("--files")
	case "git grep":
		if has("--no-index") && !has("--exclude-standard") || has("--untracked") && has("--no-exclude-standard") {
			return "", nil, nil
		}
	}
	if !patternGiven && len(pos) > 0 {
		pos = pos[1:]
	}
	if len(pos) == 0 {
		if pipe && kind == "rg" {
			return "", nil, nil
		}
		return kind, []string{cwd}, []string{""}
	}
	for _, p := range pos {
		if strings.ContainsAny(p, dynamicChars) {
			return "", nil, nil
		}
		if filepath.IsAbs(p) {
			roots = append(roots, filepath.Clean(p))
		} else {
			roots = append(roots, filepath.Join(cwd, p))
		}
	}
	return kind, roots, pos
}

func hasEq(opts []string, vals ...string) bool {
	for _, o := range opts {
		for _, v := range vals {
			if o == v {
				return true
			}
		}
	}
	return false
}

// depthArg: an ugrep depth option other than -1 (-1 does not recurse).
func depthArg(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if ugrepDepthRe.MatchString(a) && a != "-1" {
			return true
		}
	}
	return false
}

// stdinRedirect: the segment redirects stdin (`<`, `0<`), not a here-doc or here-string.
func stdinRedirect(s shell.Segment) bool {
	for _, t := range s.Tokens {
		if t.Redirect && strings.TrimLeft(t.Value, "0") == "<" {
			return true
		}
	}
	return false
}

// grepFallback mirrors the shim's bash case: these args run the real grep.
func grepFallback(a string) bool {
	if len(a) < 2 || a[0] != '-' {
		return false
	}
	r := a[1:]
	for _, s := range []string{"-filter", "-pager", "-view", "-format-open", "-config", "-save-config"} {
		if strings.Contains(r, s) {
			return true
		}
	}
	return strings.HasPrefix(a, "---") || strings.HasPrefix(a, "-@") || a[1] == 'z' || a[1] == 'Z' ||
		a[1] != '-' && strings.ContainsAny(a[2:], "zZ") || a == "--null" || a == "--null-data"
}

// scanOptions splits args into positionals and normalized options: "-x" per
// short flag, "-x=v" / "--name=v" for value options (the next word is taken
// when the value is not attached). "--" ends options.
func scanOptions(args []string, shortV string, longV map[string]bool) (pos, opts []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return append(pos, args[i+1:]...), opts
		case strings.HasPrefix(a, "--"):
			name, val, eq := strings.Cut(a[2:], "=")
			if longV[name] && !eq && i+1 < len(args) {
				i++
				val, eq = args[i], true
			}
			if eq {
				opts = append(opts, "--"+name+"="+val)
			} else {
				opts = append(opts, "--"+name)
			}
		case len(a) > 1 && a[0] == '-':
			for j := 1; j < len(a); j++ {
				if !strings.ContainsRune(shortV, rune(a[j])) {
					opts = append(opts, "-"+a[j:j+1])
					continue
				}
				val := a[j+1:]
				if val == "" && i+1 < len(args) {
					i++
					val = args[i]
				}
				opts = append(opts, "-"+a[j:j+1]+"="+val)
				break
			}
		default:
			pos = append(pos, a)
		}
	}
	return pos, opts
}
