package rules

import (
	"context"
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/iampolo87/claude-policy/internal/config"
	"github.com/iampolo87/claude-policy/internal/hook"
	"github.com/iampolo87/claude-policy/internal/shell"
	"github.com/iampolo87/claude-policy/internal/state"
)

// sensitivePaths denies subagents (agent_id set) access to the configured
// paths: file tool paths, Grep path and glob, and every Bash word. The main
// agent is never checked; paths no agent may read belong in settings
// permissions.deny. Never emits updatedInput (other hooks may rewrite
// Bash and Read).
//
// A Bash command over maxDestructiveScan is denied unscanned (the scan of
// spam is superlinear; the rule is subagent-only).
//
// Known gaps, misses: a Grep path that is a directory holding a sensitive
// file (too broad to deny); variables and expansions (`${f}nv`),
// `cd dir && cat file`, interpreter scripts (`python x.py`) and code
// building a path (`".e"."nv"`), `env -S`; an Opaque
// command (substitution in an unquoted heredoc body) is left to destructive.
// False positives: a sensitive path as a plain argument that opens nothing
// (`echo .env >> .gitignore`, `git commit -m ".env"`).
type sensitivePaths struct{}

func init() { Registry = append(Registry, sensitivePaths{}) }

func (sensitivePaths) Name() string     { return "sensitive_paths" }
func (sensitivePaths) Events() []string { return []string{"PreToolUse"} }
func (sensitivePaths) Tools() []string {
	return []string{"Read", "Edit", "Write", "MultiEdit", "NotebookEdit", "Grep", "Bash"}
}

var (
	// toolGlobOpts take a glob the tool itself matches against file names.
	toolGlobOpts   = map[string]bool{"-name": true, "-iname": true, "-path": true, "-ipath": true, "-wholename": true, "-iwholename": true, "-g": true, "--glob": true, "--iglob": true, "--include": true}
	toolGlobPrefix = regexp.MustCompile(`^--(include|glob|iglob)=`)
	// foldGlobOpts match their glob case-insensitively.
	foldGlobOpts = map[string]bool{"-iname": true, "-ipath": true, "-iwholename": true, "--iglob": true}
	optPrefix    = regexp.MustCompile(`^-{0,2}[A-Za-z_][\w.-]*=`) // --opt=, NAME=
	// shellHeads run their arguments and their stdin as commands.
	shellHeads = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "eval": true, "su": true}
	// interpreter is a head whose inline code (codeFlags) is scanned.
	interpreter = regexp.MustCompile(`^(php|python|pypy|node|nodejs|perl|ruby|bun|deno|lua|luajit|Rscript)[\d.]*$`)
	// codeFlags are the short options taking inline code, per interpreter
	// family; node and bun also take --eval/--print.
	codeFlags = map[string]string{"php": "rBRE", "python": "c", "pypy": "c", "node": "ep", "nodejs": "ep", "bun": "ep",
		"perl": "eE", "ruby": "e", "lua": "e", "luajit": "e", "Rscript": "e"}
	// programHeads take their program as an argument (`awk 'getline <
	// ".env"'`, `sed '1r .env'`, `deno eval CODE`): every argument is code.
	programHeads = map[string]bool{"awk": true, "gawk": true, "mawk": true, "nawk": true, "sed": true, "gsed": true, "perl": true, "deno": true}
	// findGlobOpts are find's: its `*` also matches a leading dot.
	findGlobOpts = map[string]bool{"-name": true, "-iname": true, "-path": true, "-ipath": true, "-wholename": true, "-iwholename": true}
	// excludeOpt values select nothing (`grep -r --exclude=.env* PASS .`).
	excludeOpt = regexp.MustCompile(`^--exclude(-dir)?=`)
	// gitValueOpts are git's global options taking the next word as value.
	// ponytail: --exec-path and --super-prefix take only `=value`; skipping
	// the next word as theirs only shifts the subcommand, and every word
	// after it is checked anyway.
	gitValueOpts = map[string]bool{"-C": true, "-c": true, "--git-dir": true, "--work-tree": true, "--namespace": true,
		"--config-env": true, "--attr-source": true, "--exec-path": true, "--super-prefix": true}
)

// findRegex is a find -regex (or, fold, -iregex) value.
type findRegex struct {
	re   string
	fold bool
}

const (
	maxShellDepth = 3
	tooDeep       = "\x00depth" // bashSensitive's entry past maxShellDepth: unscanned, denied
	badRegex      = "\x00regex" // regexEntry's entry for a regex no spelling compiles: denied
	// A command's find -regex/-iregex values are compiled only after every
	// cheap check, and past these caps not at all (denied): compiling is the
	// one superlinear step, and a run past the rule deadline has no opinion.
	maxFindRegexes    = 8
	maxFindRegexBytes = 512
)

func (sensitivePaths) Apply(ctx context.Context, in *hook.Input, cfg *config.Config, _ *state.Store) *hook.Decision {
	if in.AgentID == "" {
		return nil
	}
	var ti struct {
		FilePath     string `json:"file_path"`
		NotebookPath string `json:"notebook_path"`
		Path         string `json:"path"`
		Glob         string `json:"glob"`
		Command      string `json:"command"`
	}
	_ = json.Unmarshal(in.ToolInput, &ti) // a mistyped field stays zero, the rest decode
	entries := cfg.Rules.SensitivePaths.Paths
	var target, entry string
	switch in.ToolName {
	case "Bash":
		if len(ti.Command) > maxDestructiveScan {
			return &hook.Decision{Permission: "deny", Reason: "sensitive_paths: command over 16 KiB not scanned"}
		}
		var rx []findRegex
		target, entry = bashSensitive(ctx, ti.Command, in.Cwd, entries, 0, &rx)
		if entry == tooDeep {
			return &hook.Decision{Permission: "deny", Reason: "sensitive_paths: command nested deeper than 3 not scanned"}
		}
		if entry == "" {
			n := 0
			for _, r := range rx {
				n += len(r.re)
			}
			if len(rx) > maxFindRegexes || n > maxFindRegexBytes {
				return &hook.Decision{Permission: "deny", Reason: "sensitive_paths: more than 8 find -regex values or 512 bytes of them not scanned"}
			}
			for _, r := range rx {
				if entry = regexEntry(r.re, r.fold, entries); entry == badRegex {
					return &hook.Decision{Permission: "deny", Reason: "sensitive_paths: find -regex " + r.re + " could not be checked"}
				} else if entry != "" {
					target = r.re
					break
				}
			}
		}
	case "Grep":
		target, entry = ti.Path, sensitiveEntry(ti.Path, in.Cwd, entries)
		if entry == "" && ti.Glob != "" {
			dir := in.Cwd
			if ti.Path != "" {
				dir = resolve(ti.Path, in.Cwd)
			}
			target, entry = ti.Glob, sensitiveGlob(ti.Glob, dir, entries, false)
		}
	default:
		target = ti.FilePath + ti.NotebookPath // at most one is set
		entry = sensitiveEntry(target, in.Cwd, entries)
	}
	if entry == "" {
		return nil
	}
	return &hook.Decision{Permission: "deny",
		Reason: "sensitive_paths: subagents may not access " + target + " (matches " + entry + "); ask the main agent"}
}

func resolve(p, dir string) string {
	if !filepath.IsAbs(p) && dir != "" {
		return filepath.Join(dir, p)
	}
	return filepath.Clean(p)
}

// sensitiveEntry is the entry naming path p (relative to dir): the cleaned
// path matches **/<entry> or equals it. "" for none.
func sensitiveEntry(p, dir string, entries []string) string {
	if p == "" {
		return ""
	}
	p = resolve(p, dir)
	for _, e := range entries {
		if ok, _ := doublestar.Match("**/"+e, p); ok || p == e {
			return e
		}
	}
	return ""
}

// sensitiveGlob is the entry a glob g (relative to dir) could select: g's
// last component matches the entry's basename and either g's directory is
// the entry's (`app/etc/*.php`) or g is targeted, i.e. does not also match
// an arbitrary name with the same extension (`.env*`, `.en?`,
// `**/auth.json` are; `*`, `*.json`, `*.php` are not). With dots (find's
// globs, whose `*` also matches a leading dot) a dotfile entry is targeted
// unless g also matches a dotless name (`*.env` is; `*` is not).
// ponytail: globs in g's directory part (`a*/etc/env.php`) only match literally.
func sensitiveGlob(g, dir string, entries []string, dots bool) string {
	g = resolve(g, dir)
	gd, gb := filepath.Dir(g), filepath.Base(g)
	for _, e := range entries {
		eb := filepath.Base(e)
		if ok, _ := doublestar.Match(gb, eb); !ok {
			continue
		}
		if filepath.Dir(e) != "." && sensitiveEntry(filepath.Join(gd, eb), "", []string{e}) != "" {
			return e
		}
		probe := "zz" + filepath.Ext(eb)
		if dots && strings.HasPrefix(eb, ".") {
			probe = "zz"
		}
		if ok, _ := doublestar.Match(gb, probe); !ok {
			return e
		}
	}
	return ""
}

// bashSensitive checks every word of command (heredoc bodies and comments
// blanked; redirection targets included), minus an --opt=/NAME= prefix,
// then recurses into
// what bash also runs: $(...) and backtick bodies, and for a shell or eval
// head its arguments and the words of its pipeline up to it (`echo 'cat
// .env' | sh`). With a shell head anywhere, every heredoc body counts as
// commands (`bash <<EOF`, `cat <<EOF | sh`; ponytail: not only that shell's
// own, from one shell.Heredocs scan); otherwise a heredoc (`cat <<EOF`) is
// data, not a path, and is ignored. A quoted word is never a glob. For an
// interpreter head its inline code, a heredoc fed to it and echo/printf
// arguments piped to it are scanned with codePath; ponytail: once any
// interpreter reads a pipe, every heredoc and echo/printf counts (sees
// through `{ … } | php` without matching groups); process substitution into
// an interpreter (`python3 <(echo CODE)`, `python3 < <(…)`) counts as a pipe.
// A programHeads head has every argument scanned with programPath. find
// -regex values are only collected into rx, for the caller to cap and
// compile after every cheap check. It returns the word and its entry
// (tooDeep for text nested past maxShellDepth).
func bashSensitive(ctx context.Context, command, cwd string, entries []string, depth int, rx *[]findRegex) (string, string) {
	if ctx.Err() != nil {
		return "", ""
	}
	if depth > maxShellDepth {
		return command, tooDeep
	}
	var nested []string
	shellSeen, hasInterp := false, false
	segs := shell.Segments(command)
	// feeds[k]: segment k or a later stage of its pipeline is an interpreter
	// (`cat <<EOF | php`); piped: some interpreter reads a pipe. One backward
	// pass keeps this linear in segments.
	feeds, piped := make([]bool, len(segs)+1), false
	for k := len(segs) - 1; k >= 0; k-- {
		interp, sep, toks := interpreter.MatchString(segs[k].Name()), segs[k].Separator, segs[k].Tokens
		feeds[k] = interp || (sep == "|" || sep == "|&") && feeds[k+1]
		// `<(`: a `<` word (not a redirection) ends the segment before `(`
		procSub := sep == "(" && len(toks) > 0 && toks[len(toks)-1].Value == "<" && !toks[len(toks)-1].Redirect
		piped = piped || interp && (procSub || k > 0 && (segs[k-1].Separator == "|" || segs[k-1].Separator == "|&"))
	}
	next := 0 // first segment not yet queued: each pipeline is queued once (linear in segments)
	for i, s := range segs {
		prev, pathspec := "", false
		var gitPaths []bool
		if s.Name() == "git" {
			gitPaths = gitPathWords(s)
		}
		for j, t := range s.Tokens {
			opt, v, gitPath := prev, t.Value, pathspec || gitPaths != nil && gitPaths[j]
			pathspec = pathspec || v == "--" && s.Name() == "git"
			prev = v
			if opt == "-regex" || opt == "-iregex" {
				*rx = append(*rx, findRegex{v, opt == "-iregex"})
			}
			fold := foldGlobOpts[opt] || strings.HasPrefix(v, "--iglob=")
			skip, literal := excludeOpt.MatchString(v), false
			if gitPath {
				var icase bool
				v, skip, icase, literal = gitPathspec(v)
				fold = fold || icase
			}
			if skip { // an exclude selects nothing
				continue
			}
			w := optPrefix.ReplaceAllString(v, "")
			if e := sensitiveEntry(w, cwd, entries); e != "" {
				return w, e
			}
			// Quoted glob characters are literal, unless the tool matches the
			// glob itself (find -name, grep --include, rg -g, a git pathspec
			// without literal magic; with icase too, which only overscans).
			tool := toolGlobOpts[opt] || gitPath && (!literal || fold) || toolGlobPrefix.MatchString(v)
			if !tool && len(v) > 2 && strings.HasPrefix(v, "-g") { // rg -g'.env*'
				tool, w = true, v[2:]
			}
			if (fold || strings.ContainsAny(w, "*?[{")) && (tool || unquotedGlob(t.Raw)) {
				if e := foldedGlob(w, cwd, entries, fold, findGlobOpts[opt]); e != "" {
					return w, e
				}
			}
		}
		if s.Name() == "git" { // git -c 'alias.x=!cat .env' x, -c core.pager='cat .env'
			for k := s.Cursor + 1; k < len(s.Tokens) && strings.HasPrefix(s.Tokens[k].Value, "-"); k++ {
				v := s.Tokens[k].Value
				if gitValueOpts[v] && k+1 < len(s.Tokens) {
					k++
					if v != "-c" && v != "--config-env" {
						continue
					}
					v = s.Tokens[k].Value
				} else if !strings.HasPrefix(v, "-c") && !strings.HasPrefix(v, "--config-env=") {
					continue
				}
				if e := programPath(v, entries); e != "" {
					return v, e
				}
			}
		}
		if programHeads[s.Name()] { // awk 'getline < ".env"', sed '1r.env'
			for _, a := range s.Args() {
				if e := programPath(a, entries); e != "" {
					return a, e
				}
			}
		}
		if (s.Name() == "echo" || s.Name() == "printf") && (feeds[i] || piped) { // echo CODE | php
			for _, a := range s.Args() {
				if e := codePath(a, entries); e != "" {
					return a, e
				}
			}
		}
		if m := interpreter.FindStringSubmatch(s.Name()); m != nil {
			hasInterp = true
			if w, e := inlineCode(s, codeFlags[m[1]], entries); e != "" {
				return w, e
			}
		}
		if !shellHeads[s.Name()] {
			continue
		}
		shellSeen = true
		from := i
		for from > next && segs[from-1].Separator == "|" {
			from--
		}
		next = i + 1
		for _, u := range segs[from : i+1] {
			if u.Start == s.Start && s.Name() != "eval" {
				for _, t := range u.Tokens[u.Cursor+1:] { // sh -c 'cmd', bash <<<'cmd': the command is one word
					if !t.Redirect {
						nested = append(nested, t.Value)
					}
				}
			} else {
				nested = append(nested, strings.Join(u.Args(), " ")) // eval and echo | sh join their words
			}
		}
	}
	if shellSeen || hasInterp {
		k := 0 // segment holding the heredoc operator; both are in offset order
		for _, h := range shell.Heredocs(command) {
			body := command[h.BodyStart:h.BodyEnd]
			if shellSeen {
				nested = append(nested, body)
			}
			for k < len(segs)-1 && segs[k].End <= h.Index {
				k++
			}
			if feeds[k] || piped { // `php <<EOF`, `cat <<EOF | php`, `{ cat <<EOF; } | php` feed it code
				if e := codePath(body, entries); e != "" {
					return body, e
				}
			}
		}
	}
	for _, b := range shell.BacktickBodies(command) {
		nested = append(nested, b.Body)
	}
	nested = append(nested, substitutions(shell.BlankHeredocs(command))...)
	for _, n := range nested {
		if w, e := bashSensitive(ctx, n, cwd, entries, depth+1, rx); e != "" {
			return w, e
		}
	}
	return "", ""
}

// substitutions are the bodies of the $(...) in s outside single quotes
// (nested ones stay in their outer body).
func substitutions(s string) []string {
	var bodies []string
	dq := false
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\':
			i++
		case s[i] == '"':
			dq = !dq
		case s[i] == '\'' && !dq:
			if j := strings.IndexByte(s[i+1:], '\''); j >= 0 {
				i += j + 1
			}
		case strings.HasPrefix(s[i:], "$("):
			end := closeParen(s, i+2)
			bodies = append(bodies, s[i+2:end])
			i = end
		}
	}
	return bodies
}

// closeParen is the offset of the `)` closing the `(` just before i, or
// len(s). ponytail: an escaped quote inside a quoted string, or a case
// pattern `)`, ends the body early; the rest is still scanned by the caller.
func closeParen(s string, i int) int {
	for depth := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '\'', '"':
			if j := strings.IndexByte(s[i+1:], s[i]); j >= 0 {
				i += j + 1
			}
		case '(':
			depth++
		case ')':
			if depth--; depth == 0 {
				return i
			}
		}
	}
	return len(s)
}

// inlineCode scans the inline code of interpreter segment s for a sensitive
// path (codePath): the word after a code flag (a short option, possibly
// last in a cluster: `-lne CODE`), the rest of the word when attached
// (`-rCODE`), node's --eval/--print (`=CODE` or the next word), and a
// here-string. ponytail: a cluster is any letters before the flag, so a
// value option's attached value holding a flag letter (`-dmemory_limit=1`)
// is scanned too; that only overscans.
func inlineCode(s shell.Segment, flags string, entries []string) (string, string) {
	code := func(w string) (string, string) {
		if e := codePath(w, entries); e != "" {
			return w, e
		}
		return "", ""
	}
	for i := s.Cursor + 1; i < len(s.Tokens); i++ {
		t := s.Tokens[i]
		next := ""
		if i+1 < len(s.Tokens) {
			next = s.Tokens[i+1].Value
		}
		if t.Redirect {
			if strings.HasSuffix(t.Value, "<<<") {
				if w, e := code(next); e != "" {
					return w, e
				}
			}
			i++ // a redirection target is no option
			continue
		}
		v := t.Value
		switch {
		case strings.HasPrefix(v, "--"):
			if strings.Contains(flags, "p") { // node
				for _, o := range []string{"--eval", "--print"} {
					if v == o {
						if w, e := code(next); e != "" {
							return w, e
						}
					} else if strings.HasPrefix(v, o+"=") {
						if w, e := code(v[len(o)+1:]); e != "" {
							return w, e
						}
					}
				}
			}
		case len(v) > 1 && v[0] == '-':
			for j := 1; j < len(v); j++ {
				if strings.IndexByte(flags, v[j]) >= 0 {
					c := v[j+1:]
					if c == "" {
						c = next
					}
					if w, e := code(c); e != "" {
						return w, e
					}
					break
				}
				if !isLetter(v[j]) {
					break
				}
			}
		}
	}
	return "", ""
}

// unquotedGlob reports a glob character outside quotes in raw shell text
// (`".env"*` globs, `"X=.*"` does not).
func unquotedGlob(raw string) bool {
	var q byte
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; {
		case c == '\\' && q != '\'':
			i++
		case q != 0:
			if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case strings.IndexByte("*?[{", c) >= 0:
			return true
		}
	}
	return false
}

// foldedGlob is sensitiveGlob, matched case-insensitively when fold
// (`find -iname`, `rg --iglob`).
func foldedGlob(g, dir string, entries []string, fold, dots bool) string {
	if !fold {
		return sensitiveGlob(g, dir, entries, dots)
	}
	g, dir = strings.ToLower(g), strings.ToLower(dir)
	for _, e := range entries {
		if sensitiveGlob(g, dir, []string{strings.ToLower(e)}, dots) != "" {
			return e
		}
	}
	return ""
}

// regexEntry is the entry a find -regex/-iregex re selects: re, read as RE2
// or as find's default emacs syntax (emacsRegex) and compiled with Go regexp
// as a full match, matches the entry or ./entry. When any spelling fails to
// compile and none matches it is badRegex: GNU find accepts syntax Go
// rejects, and the spelling that compiles may be the wrong one
// (`\{1,1001\}` read as a literal). ponytail: a path under a start dir other
// than `.` (`find /x -regex`) is not tried; -regextype is ignored (both are
// tried).
func regexEntry(re string, fold bool, entries []string) string {
	prefix := ""
	if fold {
		prefix = "(?i)"
	}
	spellings := []string{re}
	if em := emacsRegex(re); em != re {
		spellings = append(spellings, em)
	}
	failed := false
	for _, v := range spellings {
		r, err := regexp.Compile(prefix + `^(?:` + v + `)$`)
		if err != nil {
			failed = true
			continue
		}
		for _, e := range entries {
			if r.MatchString(e) || r.MatchString("./"+e) {
				return e
			}
		}
	}
	if failed {
		return badRegex
	}
	return ""
}

// emacsRegex rewrites emacs regex syntax to RE2: `\(` `\)` `\|` `\{` `\}`
// are the operators and bare `( ) | { }` literals; the anchors "\\`" and
// `\'` are `^` and `$`; the word boundaries `\<` `\>` `\_<` `\_>` `\b` `\B`
// are dropped (that only widens the match). A backslash inside a bracket
// expression is literal: `[\v]` is `\` or `v` (emacsBracket).
func emacsRegex(re string) string {
	var b strings.Builder
	for i := 0; i < len(re); i++ {
		switch c := re[i]; {
		case c == '[':
			i = emacsBracket(&b, re, i)
		case c == '\\' && i+2 < len(re) && re[i+1] == '_' && (re[i+2] == '<' || re[i+2] == '>'):
			i += 2
		case c == '\\' && i+1 < len(re) && strings.IndexByte("<>bB", re[i+1]) >= 0:
			i++
		case c == '\\' && i+1 < len(re) && (re[i+1] == '`' || re[i+1] == '\''):
			i++
			b.WriteByte("^$"[strings.IndexByte("`'", re[i])])
		case c == '\\' && i+1 < len(re):
			i++
			if strings.IndexByte("()|{}", re[i]) < 0 {
				b.WriteByte(c)
			}
			b.WriteByte(re[i])
		case strings.IndexByte("()|{}", c) >= 0:
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// emacsBracket writes the bracket expression opening at re[i] with its
// backslashes escaped and returns the index of its closing `]`; an unclosed
// one is written as is (RE2 then rejects it: badRegex).
func emacsBracket(b *strings.Builder, re string, i int) int {
	j := i + 1
	if j < len(re) && re[j] == '^' {
		j++
	}
	if j < len(re) && re[j] == ']' { // a leading ] is literal
		j++
	}
	for j < len(re) && re[j] != ']' {
		if re[j] == '[' && j+1 < len(re) && strings.IndexByte(":.=", re[j+1]) >= 0 { // [:alpha:]
			if k := strings.Index(re[j+2:], string(re[j+1])+"]"); k >= 0 {
				j += k + 4
				continue
			}
		}
		j++
	}
	if j >= len(re) {
		b.WriteString(re[i:])
		return len(re)
	}
	b.WriteString(strings.ReplaceAll(re[i:j+1], `\`, `\\`))
	return j
}

// gitPathspec strips a git pathspec's magic, the long `:(top,icase)` or the
// short `:/`, `:!`, `:^` (optionally closed by `:`), and reports it: exclude
// (`exclude`, `!`, `^`: selects nothing), icase and literal.
func gitPathspec(v string) (p string, exclude, icase, literal bool) {
	if !strings.HasPrefix(v, ":") {
		return v, false, false, false
	}
	if strings.HasPrefix(v, ":(") {
		end := strings.IndexByte(v, ')')
		if end < 0 {
			return v, false, false, false
		}
		for _, m := range strings.Split(v[2:end], ",") {
			switch strings.TrimSpace(m) {
			case "exclude":
				exclude = true
			case "icase":
				icase = true
			case "literal":
				literal = true
			}
		}
		return v[end+1:], exclude, icase, literal
	}
	i := 1
	for ; i < len(v) && strings.IndexByte("/!^", v[i]) >= 0; i++ {
		exclude = exclude || v[i] != '/'
	}
	if i < len(v) && v[i] == ':' {
		i++
	}
	return v[i:], exclude, false, false
}

// gitPathWords marks the tokens of a git segment read as pathspecs: every
// non-option word after the subcommand (`git diff ':(top)x'`, an alias's
// `git g PASS ':(top)x'`), for `git grep` minus its pattern, which is the
// first one unless -e/-f give it, with or without `--`. ponytail: a
// revision, an option's separate value (`-m MSG`) and an alias's pattern
// count too; that only overscans.
func gitPathWords(s shell.Segment) []bool {
	i := s.Cursor + 1
	for ; i < len(s.Tokens) && strings.HasPrefix(s.Tokens[i].Value, "-"); i++ { // git -C dir grep
		if gitValueOpts[s.Tokens[i].Value] {
			i++
		}
	}
	grep := i < len(s.Tokens) && s.Tokens[i].Value == "grep"
	// plain[j]: token j is a word, not an option, its value or a redirection.
	plain, given := make([]bool, len(s.Tokens)), false
	for j := i + 1; j < len(s.Tokens); j++ {
		t, v := s.Tokens[j], s.Tokens[j].Value
		switch {
		case t.Redirect:
			j++
		case v == "--":
			for j++; j < len(s.Tokens); j++ {
				plain[j] = true
			}
		case !grep:
			plain[j] = !strings.HasPrefix(v, "-")
		case v == "--regexp" || v == "--file":
			given = true
			j++
		case strings.HasPrefix(v, "--regexp=") || strings.HasPrefix(v, "--file="):
			given = true
		case len(v) > 1 && v[0] == '-' && v[1] != '-':
			if k := strings.IndexAny(v[1:], "ef"); k >= 0 {
				given = true
				if k == len(v)-2 { // -e PATTERN, not -ePATTERN
					j++
				}
			}
		case !strings.HasPrefix(v, "-"):
			plain[j] = true
		}
	}
	for j := range plain {
		if plain[j] && !given && grep {
			given, plain[j] = true, false // the pattern
		}
	}
	return plain
}

func isLetter(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }

// programPath is the entry a programHeads argument names anywhere, not
// followed by a word character: sed's r/R/w/W take the file name glued on
// (`1rFILE`), so codePath's left boundary does not hold. ponytail:
// overscans (`process.env.X` in awk code); the deny reason names the entry.
// `/./` and `//` are cleaned out first (`1rapp/etc/./env.php`).
func programPath(code string, entries []string) string {
	code = squeezeSlashes(code)
	for _, e := range entries {
		for off := 0; ; {
			j := strings.Index(code[off:], e)
			if j < 0 {
				break
			}
			end := off + j + len(e)
			if end == len(code) || !isLetter(code[end]) && (code[end] < '0' || code[end] > '9') && code[end] != '_' {
				return e
			}
			off += j + 1
		}
	}
	return ""
}

// squeezeSlashes drops every `./` and `/` that directly follows a `/`, in
// one pass: `a//./b` is `a/b`.
func squeezeSlashes(s string) string {
	if !strings.Contains(s, "//") && !strings.Contains(s, "/./") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		b.WriteByte(s[i])
		for s[i] == '/' && i+1 < len(s) {
			if s[i+1] == '/' {
				i++
			} else if s[i+1] == '.' && i+2 < len(s) && s[i+2] == '/' {
				i += 2
			} else {
				break
			}
		}
	}
	return b.String()
}

// codePath is the entry code names as a path-like substring: the entry
// starts at the text start or after one of "'`/ \t\n(=< and ends at the text
// end or before one of "'` \t\n);, (`"app/etc/env.php"`, `open('.env')`,
// `'/x/auth.json'`; not `process.env.HOME` or `.environment`).
func codePath(code string, entries []string) string {
	for _, e := range entries {
		for off := 0; ; {
			j := strings.Index(code[off:], e)
			if j < 0 {
				break
			}
			j += off
			end := j + len(e)
			if (j == 0 || strings.IndexByte("\"'`/ \t\n(=<", code[j-1]) >= 0) &&
				(end == len(code) || strings.IndexByte("\"'` \t\n);,", code[end]) >= 0) {
				return e
			}
			off = j + 1
		}
	}
	return ""
}
