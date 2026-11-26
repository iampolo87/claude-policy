package rules

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/iampolo87/claude-policy/internal/config"
	"github.com/iampolo87/claude-policy/internal/hook"
	"github.com/iampolo87/claude-policy/internal/shell"
	"github.com/iampolo87/claude-policy/internal/state"
)

func init() { Registry = append(Registry, destructive{}) }

// destructive asks or denies recognizable destructive Bash commands per
// category (git, fs, sql, magento) and actor; hard_deny entries deny in
// every mode. The recognizer is gentle-shell's recognizeDestructiveCommands
// on top of internal/shell: parsed segments, never substrings, so prose,
// data-command arguments, comments and heredoc bodies are not commands.
// Variables assigned a literal earlier in the command are expanded first
// (bindVars), and a `cd DIR &&` chain sets where relative targets resolve.
//
// Known gaps, misses: a lone `$cmd` or `$(...)` word as a command (eval
// "$cmd"); `bash -c "$X"`; a script file operand (`bash x.sh`, `source f`);
// an unknown producer piped into a SQL client; Symfony abbreviations of a
// wildcard command part (`s:d:st-cl`); git option abbreviations. False
// positives: a dynamic head with arguments (`$EDITOR f`) asks; any input
// piped into a shell from a command other than echo, printf or cat asks.
type destructive struct{}

func (destructive) Name() string     { return "destructive" }
func (destructive) Events() []string { return []string{"PreToolUse"} }
func (destructive) Tools() []string {
	return []string{"Bash", "Edit", "Write", "MultiEdit", "NotebookEdit"}
}

// policyFiles names this binary's own config, global and per project
// (config.ProjectPath), by file name alone: a symlinked or renamed directory
// must not hide it. A write to one loosens the guard, so the main agent is
// asked and a subagent denied, whatever the category policies say. In Bash
// any word naming one counts, a read included (bashSensitive and its known
// gaps; nesting past its depth is not scanned). policyDirWriters given a
// directory named .claude count too: they place or link a whole directory.
// ponytail: interpreters and other writers (python -c, dd of=) are not seen.
var (
	policyFiles      = []string{"policy.toml"}
	policyDirWriters = map[string]bool{"cp": true, "mv": true, "ln": true, "install": true, "rsync": true, "tar": true}
)

// maxDestructiveScan bounds what is tokenized, as in commit_message: the
// scan is superlinear on spam (64 KiB of nested eval or `$(` takes ~100 ms,
// 16 KiB ~10 ms); a longer command asks. maxDestructiveDepth caps sh -c,
// eval, find -exec and substitution recursion; deeper asks.
const (
	maxDestructiveScan  = 16 << 10
	maxDestructiveDepth = 4
	maxSQLFile          = 1 << 20 // `mysql < f.sql`, `cat f.sql | mysql` read at most this much
)

type dFinding struct {
	cat  string // git|fs|sql|magento, or unresolved (ask for both actors)
	text string // the matched segment
	hard string // the matched hard_deny entry
}

type allowedRm struct {
	depth, idx int
	raw        string
	heads      []string // the words up to its command word: a function of that name runs instead
}

type dScan struct {
	ctx   context.Context
	in    *hook.Input
	c     *config.Destructive
	hard  []hardEntry
	roots []string // resolved
	home  string   // cleaned; "" when unknown
	user  string   // current user name, for ~user
	// pwHome is the passwd home (cleaned; "" when unknown): the root walk
	// stops there too, whatever HOME says
	pwHome string
	ran    bool // code the allow paths cannot follow may have run (see recognize)
	// shadowed: rm may not be the program (alias, enable, an imported
	// function, a command word the scan cannot read); funcs: the functions
	// defined anywhere in the command. See concurrent.
	shadowed bool
	funcs    map[string]bool
	rehomed  bool // the text names HOME: ~ may not be the home the hook knows
	// gitEnv: the text names a GIT_ variable, which can point git at another
	// repository or config than the one the hook reads; repos caches what
	// was read (see gitRefs.repo)
	gitEnv bool
	repos  map[string]*gitRepo
	// reglobbed: the text names GLOBIGNORE, which makes * match dot files
	reglobbed bool
	// noAllow > 0 inside an xargs, find -exec/-ok or trap body: its rm runs
	// again, later or on a name the scan cannot see, so it is never allowed
	noAllow int
	// see concurrent: rms the allow paths passed, held until the scan ends
	allowed    []allowedRm
	unsafeAny  bool            // an unsafe segment (safeSeg) at any depth
	concNested bool            // a & or | below top level
	amp        bool            // a top-level &
	pipes      [2]int          // 1 + index of the first and last top-level |; 0 when none
	top        []shell.Segment // the top-level segments
	found      []dFinding
	cd         bool   // a cd, pushd or popd was scanned: relative targets leave Cwd
	dir        string // where a `cd DIR &&` chain is known to be; "" outside one
	cds        int    // cd, pushd and popd segments scanned
	// bindVars' segments of segsOf, reused when it returns the command as is
	segsOf string
	segs   []shell.Segment
}

func (destructive) Apply(ctx context.Context, in *hook.Input, cfg *config.Config, _ *state.Store) *hook.Decision {
	var ti struct {
		Command      string `json:"command"`
		FilePath     string `json:"file_path"`
		NotebookPath string `json:"notebook_path"`
	}
	if json.Unmarshal(in.ToolInput, &ti) != nil {
		return nil
	}
	if in.ToolName != "Bash" {
		target := ti.FilePath + ti.NotebookPath // at most one is set
		if sensitiveEntry(target, in.Cwd, policyFiles) == "" {
			return nil
		}
		s := &dScan{in: in, c: &cfg.Rules.Destructive}
		s.add("policy", target)
		return s.decide()
	}
	if strings.TrimSpace(ti.Command) == "" {
		return nil
	}
	home, _ := os.UserHomeDir()
	if home != "" {
		home = filepath.Clean(home)
	}
	s := &dScan{ctx: ctx, in: in, c: &cfg.Rules.Destructive, home: home}
	if u, err := userCurrent(); err == nil {
		s.user = u.Username
		if u.HomeDir != "" {
			s.pwHome = filepath.Clean(u.HomeDir)
		}
	}
	for _, e := range s.c.HardDeny {
		if h, ok := parseHardEntry(e); ok {
			s.hard = append(s.hard, h)
		}
	}
	for _, r := range s.c.FS.AllowRoots {
		if r = s.expand(r); r != "" {
			s.roots = append(s.roots, resolved(r))
		}
	}
	command := ti.Command
	if len(command) > maxDestructiveScan {
		// An inert quoted heredoc write is scanned without its body; its
		// first line is tokenized, so it must fit the cap itself.
		var st string
		ok := false
		if line, _, _ := strings.Cut(command, "\n"); len(line) <= maxDestructiveScan {
			st, ok = shell.InertHeredocWrite(command)
		}
		if ok && len(st) <= maxDestructiveScan && ctx.Err() == nil {
			command = st
		} else {
			s.add("unresolved", command)
			command = ""
		}
	}
	if command != "" {
		joined := strings.ReplaceAll(command, "\\\n", "")
		bound := s.bindVars(command)
		// names as bash reads them: quotes, backslashes and bound variables
		// can spell one in pieces
		names := unquote.Replace(joined + "\n" + bound)
		for _, n := range []string{"BASH_FUNC_", "BASH_CMDS", "BASH_ALIASES", "EXECIGNORE"} {
			s.shadowed = s.shadowed || strings.Contains(names, n)
		}
		s.rehomed = s.rehomed || strings.Contains(names, "HOME")
		s.gitEnv = s.gitEnv || strings.Contains(names, "GIT_")
		for _, n := range []string{"GLOBIGNORE", "dotglob", "BASHOPTS", "SHELLOPTS"} { // bash -O dotglob -c too
			s.reglobbed = s.reglobbed || strings.Contains(names, n)
		}
		for _, text := range []string{command, joined} {
			s.ran = s.ran || indirectRun.MatchString(text) || arithmetic.MatchString(text) || lastArg.MatchString(text)
		}
		s.recognize(bound, 0, true)
		s.concurrent()
		var rx []findRegex
		if t, e := bashSensitive(ctx, command, in.Cwd, policyFiles, 0, &rx); e != "" && e != tooDeep {
			s.add("policy", t)
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	return s.decide()
}

// mktempRoot stands for the fresh directory of `V=$(mktemp ...)`: a
// target at or under it is allowed. The nonce keeps a typed path from
// matching it.
var userCurrent = user.Current // a test seam

var mktempRoot = func() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "/.mktemp-" + hex.EncodeToString(b)
}()

var (
	assignWord = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
	writeWord  = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)(?:\+?=|\[)`)
	fdVarRedir = regexp.MustCompile(`^\{([A-Za-z_][A-Za-z0-9_]*)[\[}]`)
	// plainWord is an option or argument with nothing bash expands
	plainWord = regexp.MustCompile(`^[A-Za-z0-9_./%+=:,@-]+$`)
	// bindBreakers can set any variable: binding stops for the command.
	bindBreakers = []string{"eval", "source", ".", "declare", "typeset", "local", "let", "read", "mapfile", "readarray",
		"getopts", "unset", "trap"}
	// bashSpecials are dynamic or shell-maintained variables: an assignment
	// does not fix what they expand to, so they are never bound.
	bashSpecials = []string{"HOME", "PWD", "OLDPWD", "IFS", "LINENO", "SECONDS", "RANDOM", "SRANDOM", "HISTCMD", "OPTIND",
		"OPTARG", "PPID", "UID", "EUID", "GROUPS", "FUNCNAME", "DIRSTACK", "SHELLOPTS", "PIPESTATUS", "REPLY", "COLUMNS",
		"LINES", "EPOCHSECONDS", "EPOCHREALTIME"}
	// defaultAssign is ${V=, ${V:=, ${V? or ${V:?: V may be set where it
	// stands, inside quotes or a heredoc body too.
	defaultAssign = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?:\[[^]]*\])?:?[=?]`) // ${V[0]:=x} sets $V too
	// indirectRun: bash runs text the scan never sees as a command: ANSI-C
	// or locale quoting that spells a `$(` (`$""(`), prompt expansion (@P, PS4 under xtrace,
	// PROMPT_COMMAND), startup files (BASH_ENV, ENV), a PATH or CDPATH that
	// changes what a safe head runs or where cd goes, printf -v, or a
	// context that evaluates a variable's value as arithmetic, subscripts
	// and their `$(` included ([[ -eq ]], [[ -v ]], test -v, ${V:off},
	// ${!V}; see arithmetic), or the command's own text run again after
	// what follows its rm (BASH_EXECUTION_STRING). The allow paths are off
	// for the whole command.
	// ponytail: anywhere in the text, quotes and words included.
	indirectRun = regexp.MustCompile(`\$'|\$"|@P|\bPS4\b|PROMPT_COMMAND|BASH_ENV|BASH_EXECUTION_STRING|\bENV\b[+:]?=|\b(?:CD)?PATH\b[+:]?=|xtrace|` +
		`\bset\s+(?:[-+]\w+\s+)*-\w*x|\bprintf\b[^;&|\n]*\s-v|(?:\btest|\[)\s+(?:!\s+)?-v\s|` +
		`\[\[[^\n]*\s-(?:eq|ne|lt|le|gt|ge|v)\b|\$\{!|\$\{[^}:]*:[^-=?+]`)
	// lastArg: $_ is the previous command's last argument, not what an
	// assignment bound it to
	lastArg = regexp.MustCompile(`\$_(?:[^A-Za-z0-9_]|$)|\$\{_[^A-Za-z0-9_]`)
	unquote = strings.NewReplacer("'", "", `"`, "", `\`, "")
	// arithmetic can assign any variable: ((, $((, $[, let, or an array
	// subscript in ${...}. ponytail: anywhere in the text, words and quotes
	// included.
	arithmetic  = regexp.MustCompile(`\(\(|\$\[|\blet\b|\$\{[^}]*\[`)
	bindOpeners = map[string]int{"if": 1, "while": 1, "until": 1, "for": 1, "select": 1, "{": 1, "fi": -1, "done": -1, "}": -1}
	bindSeq     = []string{";", "\n", "&&"}
)

type binding struct {
	val         string
	ok          bool // false: the assignment's value is unknown
	from, until int  // in force at offsets [from, until)
}

// bindVars rewrites $V and ${V} outside single quotes with the value of a
// literal assignment made earlier in the command, so that every check
// sees the word bash runs. An assignment binds when it is the whole
// segment (or `export` and assignments), at top level, after a list start,
// `;`, a newline or `&&`, and before `;`, a newline, `&&` or the end; after
// `&&` it holds to the end of that && chain. Its value is a word, '...' or
// "..." whose only expansions are a leading ~/, $HOME and bound variables, made of
// characters bash keeps as one word or splits on spaces exactly as the
// rewritten text tokenizes; `V=$(mktemp ...)` followed by `&&` binds
// mktempRoot for the rest of that && chain. The last binding before a use
// wins. A variable written any other way (prefix assignment, subshell,
// pipeline, loop, for, +=, ${V:=...} anywhere in the text, a nested shell's
// text) or a bash special (bashSpecials, BASH*) is never rewritten, and a
// command that defines a function, uses case, arithmetic (see arithmetic),
// eval, source, read, trap and the like, or writes IFS is left as is; a
// mktemp option outside mktempArgs binds nothing; nothing binds after a
// command word bash expands unless it resolves to a non-writer. Heredoc
// bodies, words holding `$(` or a backtick, and over-cap results are left
// as is.
func (s *dScan) bindVars(command string) string {
	joined := strings.ReplaceAll(command, "\\\n", "")
	if !strings.Contains(command, "=") || !strings.Contains(command, "$") || arithmetic.MatchString(joined) {
		return command
	}
	segs := shell.Segments(command)
	s.segsOf, s.segs = command, segs
	type cand struct{ k, last int } // assignment segment k, binding after segment last
	var cands []cand
	bound := map[int]bool{}      // token offsets of candidate assignments
	written := map[string]bool{} // written other than by a candidate
	type dynHead struct{ k, depth int }
	var heads []dynHead // segments whose command word bash expands
	// breaks: the command can set any variable
	breaks := func(seg shell.Segment) bool {
		name, args := seg.Name(), seg.Args()
		return slices.Contains(bindBreakers, name) ||
			name == "printf" && slices.ContainsFunc(args, func(a string) bool { return strings.HasPrefix(a, "-v") }) ||
			name == "wait" && slices.ContainsFunc(args, func(a string) bool { return strings.HasPrefix(a, "-p") })
	}
	depth := 0
	for k, seg := range segs {
		for _, t := range seg.Tokens {
			if d, ok := bindOpeners[t.Bare()]; ok {
				depth += d
			} else if w := t.Bare(); w == "case" || w == "function" {
				return command // ponytail: case patterns end in `)`; functions run later
			} else if !slices.Contains([]string{"then", "do", "else", "elif", "!"}, w) {
				break
			}
		}
		switch name, args := seg.Name(), seg.Args(); {
		case breaks(seg),
			seg.Separator == "(" && k+1 < len(segs) && len(segs[k+1].Tokens) == 0 && segs[k+1].Separator == ")": // f()
			return command
		case (name == "for" || name == "select") && len(args) > 0:
			written[args[0]] = true
		}
		// export $V=x, local $1=x: any name, HOME and GLOBIGNORE included
		if slices.Contains([]string{"export", "readonly", "local"}, seg.Name()) && slices.ContainsFunc(seg.ArgTokens(), func(t shell.Token) bool {
			name, _, _ := strings.Cut(t.Raw, "=")
			return expandedWord(name)
		}) {
			s.rehomed, s.reglobbed = true, true
		}
		if h, ok := seg.Head(); ok && expandedWord(h.Raw) || hiddenWriter(seg) {
			heads = append(heads, dynHead{k, depth})
		}
		toks := seg.Tokens
		if len(toks) > 0 && toks[0].Raw == "export" {
			toks = toks[1:]
		}
		seq := depth == 0 && (k == 0 || slices.Contains(bindSeq, segs[k-1].Separator))
		switch {
		case !seq || len(toks) == 0 || slices.ContainsFunc(toks, func(t shell.Token) bool { return !assignWord.MatchString(t.Raw) }):
		case len(toks) == 1 && strings.HasSuffix(toks[0].Raw, "=$") && seg.Separator == "(" && k+2 < len(segs) &&
			segs[k+1].Name() == "mktemp" && segs[k+1].Cursor == 0 && segs[k+1].Separator == ")" &&
			!slices.ContainsFunc(segs[k+1].Tokens, func(t shell.Token) bool { return t.Redirect }) &&
			mktempArgs(rawArgs(segs[k+1].Tokens[1:])) &&
			len(segs[k+2].Tokens) == 0 && segs[k+2].Separator == "&&": // a failed or redirected mktemp leaves V empty
			cands, bound[toks[0].Index] = append(cands, cand{k, k + 2}), true
		case seg.Separator == "" || slices.Contains(bindSeq, seg.Separator):
			cands = append(cands, cand{k, k})
			for _, t := range toks {
				bound[t.Index] = true
			}
		}
		for _, t := range seg.Tokens {
			if m := writeWord.FindStringSubmatch(t.Value); m != nil && !bound[t.Index] {
				written[m[1]] = true
			}
			// {V}>file stores an fd number in V; a {V[ word redirection() left
			// unparsed (expanding subscript) may be one too.
			if m := fdVarRedir.FindStringSubmatch(t.Raw); m != nil && (t.Redirect || strings.HasSuffix(m[0], "[")) {
				written[m[1]] = true
				s.ran = s.ran || strings.HasSuffix(m[0], "[") // its subscript is arithmetic: {a[V=5]}>
			}
		}
		switch seg.Separator {
		case "(":
			depth++
		case ")":
			depth--
		}
		if depth < 0 {
			return command
		}
	}
	for _, n := range []string{"HOME", "PWD", "OLDPWD"} { // set by the shell or cd
		written[n] = written[n] || slices.ContainsFunc(cands, func(c cand) bool {
			return slices.ContainsFunc(segs[c.k].Tokens, func(t shell.Token) bool { return strings.HasPrefix(t.Raw, n+"=") })
		})
	}
	if written["IFS"] || slices.ContainsFunc(cands, func(c cand) bool {
		return slices.ContainsFunc(segs[c.k].Tokens, func(t shell.Token) bool { return strings.HasPrefix(t.Raw, "IFS=") })
	}) {
		return command
	}

	// bash drops a backslash-newline before expanding: ${D\<newline>:=x} is ${D:=x}
	for _, m := range defaultAssign.FindAllStringSubmatch(joined, -1) {
		written[m[1]] = true
	}

	binds := map[string][]binding{}
	cut := len(command) + 1 // no binding holds from here: a command word before it may have written any variable
	lookup := func(name string, at int) (string, bool) {
		if at >= cut || written[name] || slices.Contains(bashSpecials, name) || strings.HasPrefix(name, "BASH") {
			return "", false
		}
		bs := binds[name]
		i := sort.Search(len(bs), func(i int) bool { return bs[i].from > at }) - 1
		if i < 0 || !bs[i].ok || at >= bs[i].until {
			return "", false
		}
		return bs[i].val, true
	}
	// budget bounds the bytes all values copy from other variables: a
	// ten-fold chain of assignments grows exponentially, past the deadline.
	budget := 4 * maxDestructiveScan
	for _, c := range cands {
		if s.ctx.Err() != nil {
			return command
		}
		from, until := segs[c.last].End, len(command)+1
		if c.k > 0 && segs[c.k-1].Separator == "&&" || c.last != c.k {
			e := c.last
			for e+1 < len(segs) && segs[e].Separator == "&&" {
				e++
			}
			until = segs[e].End
		}
		for _, t := range segs[c.k].Tokens {
			name, raw, _ := strings.Cut(t.Raw, "=")
			if name == "export" {
				continue
			}
			b := binding{val: mktempRoot, ok: true, from: from, until: until}
			if c.last == c.k {
				b.val, b.ok = evalValue(raw, func(n string) (string, bool) {
					v, ok := s.home, s.home != "" && !written["HOME"]
					if n != "HOME" {
						v, ok = lookup(n, from)
					}
					if budget -= len(v); budget < 0 {
						return "", false
					}
					return v, ok
				})
			}
			binds[name] = append(binds[name], b)
		}
	}
	// A command word bash expands (`$R D` with R=read, `{read,D}`, `$C $R D`
	// with C=command) or a hiddenWriter may be a writer the first pass could
	// not name: unless the whole segment, rewritten, has a plain head that
	// breaks and hiddenWriter reject, nothing binds after it, or anywhere
	// when it sits in a loop, group or subshell. The rewrites share budget.
	for _, h := range heads {
		if s.ctx.Err() != nil {
			return command
		}
		seg := segs[h.k]
		words := make([]string, len(seg.Tokens))
		for i, t := range seg.Tokens {
			words[i], _ = substitute(t.Raw, func(n string) (string, bool) {
				v, ok := lookup(n, t.Index)
				if budget -= len(v); budget < 0 {
					return "", false
				}
				return v, ok
			})
		}
		if rs := shell.Segments(strings.Join(words, " ")); len(rs) == 1 {
			// an export or readonly here had a name bash expands: it may assign
			if hd, ok := rs[0].Head(); ok && !expandedWord(hd.Raw) && !breaks(rs[0]) && !hiddenWriter(rs[0]) &&
				rs[0].Name() != "export" && rs[0].Name() != "readonly" {
				continue
			}
		}
		if h.depth > 0 {
			return command
		}
		cut = seg.End
		break
	}

	var out strings.Builder
	last := 0
	over := false // the rewrite would pass the scan cap: left as is
	for _, seg := range segs {
		for _, t := range seg.Tokens {
			if !strings.Contains(t.Raw, "$") || strings.Contains(t.Raw, "$(") || strings.Contains(t.Raw, "`") {
				continue
			}
			grown := out.Len()
			raw, changed := substitute(t.Raw, func(n string) (string, bool) {
				v, ok := lookup(n, t.Index)
				if grown += len(v); grown > maxDestructiveScan {
					over = true
					return "", false
				}
				return v, ok
			})
			if over {
				return command
			}
			if !changed {
				continue
			}
			out.WriteString(command[last:t.Index])
			out.WriteString(raw)
			if last = t.Index + len(t.Raw); out.Len()+len(command)-last > maxDestructiveScan {
				return command
			}
		}
	}
	if last == 0 {
		return command
	}
	out.WriteString(command[last:])
	return out.String()
}

// evalValue is the value of an assignment's raw right-hand side: quotes
// removed, a leading unquoted ~/ and lookup's variables expanded; ok is false
// for any other expansion, any other unquoted ~, or a character unsafeRune
// rejects.
func evalValue(raw string, lookup func(string) (string, bool)) (string, bool) {
	var b strings.Builder
	var quote byte
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			} else {
				b.WriteByte(c)
			}
		case c == '\\':
			if i++; i == len(raw) {
				return "", false
			}
			if quote == '"' && !strings.ContainsRune("$`\"\\\n", rune(raw[i])) {
				b.WriteByte('\\')
			}
			if raw[i] != '\n' {
				b.WriteByte(raw[i])
			}
		case c == '\'' && quote == 0:
			quote = '\''
		case c == '"':
			quote ^= '"'
		case c == '$':
			name, n := varRef(raw[i:])
			if n == 0 {
				return "", false
			}
			v, ok := lookup(name)
			if !ok {
				return "", false
			}
			b.WriteString(v)
			i += n - 1
		case c == '~' && quote == 0 && i == 0 && strings.HasPrefix(raw, "~/"):
			v, ok := lookup("HOME")
			if !ok {
				return "", false
			}
			b.WriteString(v)
		case c == '`', c == '~' && quote == 0:
			return "", false
		default:
			b.WriteByte(c)
		}
	}
	v := b.String()
	return v, quote == 0 && !strings.ContainsFunc(v, unsafeRune)
}

// expandedWord: bash expands the raw word before running it (a variable,
// substitution, brace or glob); a bare `[` or `[[` is the test command.
func expandedWord(raw string) bool {
	return raw != "[" && raw != "[[" && strings.ContainsAny(raw, "$`{*?[")
}

// hiddenWriter: a builtin that writes the variable a word bash expands may
// name: `export $V` or `readonly $V` (V=D=/x), or printf or wait with an
// expanded word where an option goes (V=-v, V=-p).
func hiddenWriter(seg shell.Segment) bool {
	switch seg.Name() {
	case "export", "readonly":
		return slices.ContainsFunc(seg.ArgTokens(), func(t shell.Token) bool {
			name, _, _ := strings.Cut(t.Raw, "=")
			return expandedWord(name)
		})
	case "printf", "wait":
		for _, t := range seg.ArgTokens() {
			switch {
			case expandedWord(t.Raw):
				return true
			case t.Raw == "--" || !strings.HasPrefix(t.Value, "-"):
				return false
			}
		}
	}
	return false
}

// braceWord: the raw word may brace-expand ({a,b} or {a..b}, not ${), which
// bash does before parameter expansion: `{$B,}x` runs $Bx. ponytail: quotes
// ignored, so a quoted brace leaves the word unresolved too.
func braceWord(raw string) bool {
	for i := 0; i < len(raw); i++ {
		if raw[i] == '{' && (i == 0 || raw[i-1] != '$') { // the first one: any later , or .. follows it too
			return strings.Contains(raw[i:], ",") || strings.Contains(raw[i:], "..")
		}
	}
	return false
}

// unsafeRune: a character a value may not hold, because the rewritten text
// would tokenize differently from bash's expansion (quotes, operators,
// comments, globs, braces, ~, other whitespace) or carry another expansion.
func unsafeRune(r rune) bool {
	return !('a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9' || strings.ContainsRune(" /._+,:@%=-", r))
}

// varRef is the name and length of the `$NAME` or `${NAME}` that s starts
// with; n is 0 for any other `$` form.
func varRef(s string) (name string, n int) {
	if strings.HasPrefix(s, "${") {
		if j := strings.IndexByte(s, '}'); j > 2 && assignWord.MatchString(s[2:j]+"=") && !strings.Contains(s[2:j], "=") {
			return s[2:j], j + 1
		}
		return "", 0
	}
	j := 1
	for j < len(s) && (s[j] == '_' || 'a' <= s[j] && s[j] <= 'z' || 'A' <= s[j] && s[j] <= 'Z' || j > 1 && '0' <= s[j] && s[j] <= '9') {
		j++
	}
	if j == 1 {
		return "", 0
	}
	return s[1:j], j
}

// substitute replaces in a raw word each `$NAME`/`${NAME}` outside single
// quotes and $'...' that lookup resolves.
func substitute(raw string, lookup func(string) (string, bool)) (string, bool) {
	if braceWord(raw) {
		return raw, false
	}
	var b strings.Builder
	changed, double := false, false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c == '\\':
			b.WriteString(raw[i:min(i+2, len(raw))])
			i++
			continue
		case c == '"':
			double = !double
		case c == '\'' && !double, c == '$' && !double && strings.HasPrefix(raw[i+1:], "'"):
			j := i + 1
			if c == '$' {
				j++
			}
			for ; j < len(raw) && raw[j] != '\''; j++ {
				if c == '$' && raw[j] == '\\' {
					j++
				}
			}
			j = min(j+1, len(raw))
			b.WriteString(raw[i:j])
			i = j - 1
			continue
		case c == '$' && strings.HasPrefix(raw[i+1:], "$"): // $$ is the PID
			b.WriteString("$$")
			i++
			continue
		case c == '$':
			if name, n := varRef(raw[i:]); n > 0 {
				// unquoted, a value ending in a space puts a following # or ~
				// at a word start in the rewritten text (a comment, a tilde)
				next := byte(0)
				if i+n < len(raw) {
					next = raw[i+n]
				}
				if v, ok := lookup(name); ok && (double || !strings.HasSuffix(v, " ") || next != '#' && next != '~') {
					b.WriteString(v)
					i += n - 1
					changed = true
					continue
				}
			}
		}
		b.WriteByte(c)
	}
	return b.String(), changed
}

func (s *dScan) add(cat, text string) {
	s.found = append(s.found, dFinding{cat: cat, text: clip(text)})
}

func clip(s string) string {
	if s = strings.TrimSpace(s); len(s) > 200 {
		s = strings.ToValidUTF8(s[:200], "")
	}
	return s
}

func (s *dScan) decide() *hook.Decision {
	for _, f := range s.found {
		if f.hard != "" {
			return &hook.Decision{Permission: "deny", Hard: true, Reason: fmt.Sprintf("destructive: hard_deny %q: %s", f.hard, f.text)}
		}
	}
	actor := "main"
	if s.in.AgentID != "" {
		actor = "subagent"
	}
	var best *hook.Decision
	for _, f := range s.found {
		p := config.Policy{Main: "ask", Subagent: "ask"} // unresolved
		switch f.cat {
		case "git":
			p = s.c.Git.Policy
		case "policy":
			p = config.Policy{Main: "ask", Subagent: "deny"}
		case "fs":
			p = s.c.FS.Policy
		case "sql":
			p = s.c.SQL
		case "magento":
			p = s.c.Magento.Policy
		}
		v := p.Main
		if actor == "subagent" {
			v = p.Subagent
		}
		if (v == "deny" || v == "ask") && (best == nil || v == "deny" && best.Permission == "ask") {
			best = &hook.Decision{Permission: v, Reason: fmt.Sprintf("destructive: %s %s (%s): %s", f.cat, v, actor, f.text)}
		}
	}
	return best
}

// recognize scans command's segments; checkOpaque is false for substitution
// bodies, which come from heredoc-blanked text (a blanked heredoc reads as
// unterminated).
func (s *dScan) recognize(command string, depth int, checkOpaque bool) {
	if s.ctx.Err() != nil {
		return
	}
	if depth > maxDestructiveDepth {
		s.add("unresolved", command)
		return
	}
	if checkOpaque && shell.Opaque(command) || shell.Unread(command) {
		s.add("unresolved", command)
	}
	// A nested text (eval, sh -c, a substitution) that changes directory
	// leaves the caller's directory unknown; otherwise it is kept.
	dir, cds := s.dir, s.cds
	defer func() {
		if s.dir = dir; s.cds != cds {
			s.dir = ""
		}
	}()
	segs := s.segs
	if depth > 0 || command != s.segsOf {
		segs = shell.Segments(command)
	}
	if depth == 0 {
		s.top = segs
	}
	var docs []shell.Heredoc // one linear scan per command, on first use
	heredoc := func(seg shell.Segment) (string, bool) {
		if docs == nil {
			docs = append(shell.Heredocs(command), shell.Heredoc{Index: -1}) // the sentinel marks the scan done
		}
		for _, h := range docs {
			if h.Index >= seg.Start && h.Index < seg.End {
				body := command[h.BodyStart:h.BodyEnd]
				if h.Expands { // what the reader gets: bash removed these backslashes
					body = heredocEscapes.Replace(body)
				}
				return body, true
			}
		}
		return "", false
	}
	// s.ran turns the allow paths off once code they cannot follow may
	// have run: an unsafe segment (safeSeg) once scanned, a bad substitution
	// (badSubst) from the segment that holds it on, everything in a loop or
	// function that holds either or a cd. A segment ending in "(" may have a substitution in its
	// redirect, here-string or arguments: the rest of the text counts.
	bad := badSubst(command)
	for i := range segs {
		s.shadows(segs, i)
	}
	// A loop or function body may also run again after a directory change
	// written after it.
	if deferred(segs) && (bad >= 0 || slices.ContainsFunc(segs, func(seg shell.Segment) bool {
		return !safeSeg(seg) || slices.Contains([]string{"cd", "pushd", "popd"}, seg.Name())
	})) {
		s.ran = true
	}
	unsafe := false
	var closing map[int]int // see closingSegments, on first use
	for i, seg := range segs {
		if i > 0 && segs[i-1].Separator != "&&" {
			s.dir = "" // the cd chain ended: either directory may be current
		}
		end := seg.End
		if seg.Separator == "(" {
			end = len(command) // ponytail: the whole rest, not just this command's words
		}
		s.ran = s.ran || unsafe || bad >= 0 && bad < end
		unsafe = !safeSeg(seg)
		s.unsafeAny = s.unsafeAny || unsafe
		switch {
		case seg.Separator != "&" && seg.Separator != "|":
		case depth > 0:
			s.concNested = true
		case seg.Separator == "&":
			s.amp = true
		default:
			if s.pipes[0] == 0 {
				s.pipes[0] = i + 1
			}
			s.pipes[1] = i + 1
		}
		if len(seg.Tokens) == 0 {
			continue
		}
		for _, t := range seg.Tokens {
			for _, body := range dqSubstitutions(t.Raw) {
				s.recognize(body, depth+1, false)
			}
		}
		head, ok := seg.Head()
		if !ok {
			// Appending a plain word tells an unknown wrapper option (the
			// word stays unresolved) from a segment that runs nothing:
			// assignments, reserved words or a bare `env`.
			ext := append(seg.Tokens[:len(seg.Tokens):len(seg.Tokens)], shell.Token{Value: "x", Raw: "x"})
			if shell.HeadCursor(ext) == len(ext) {
				s.add("unresolved", seg.Raw)
			}
			continue
		}
		s.hardDeny(seg)
		if strings.ContainsAny(head.Value, "$`") {
			if closing == nil {
				closing = closingSegments(segs)
			}
			s.dynamic(command, segs, i, closing)
			continue
		}
		name, args := shell.Executable(head.Value), seg.Args()
		for k := range args {
			args[k] = longOpt(name, args[k])
		}
		// xargs runs its command once per input line, on words it appends
		// or replaces (-I) that the scan cannot see.
		xargs := slices.ContainsFunc(seg.Tokens[:seg.Cursor], func(t shell.Token) bool { return shell.Executable(t.Value) == "xargs" })
		if policyDirWriters[name] && slices.ContainsFunc(args, func(a string) bool {
			return filepath.Base(filepath.Clean(a[strings.LastIndexByte(a, '=')+1:])) == ".claude" // also --target-directory=DIR
		}) {
			s.add("policy", seg.Raw)
		}
		if xargs {
			s.noAllow++
		}
		switch name {
		case "cd", "pushd", "popd":
			// `cd DIR &&` at a list start or after && puts the rest of the
			// && chain in DIR: a failing cd skips it.
			d := ""
			if name == "cd" && seg.Separator == "&&" && (i == 0 || slices.Contains([]string{";", "\n", "&&"}, segs[i-1].Separator)) &&
				!slices.ContainsFunc(seg.Tokens[:min(seg.Cursor, len(seg.Tokens))], func(t shell.Token) bool { return t.Bare() == "!" }) { // ! cd: a failed cd goes on
				d = s.cdTarget(seg)
			}
			s.cd, s.cds, s.dir = true, s.cds+1, d
		case "sh", "bash", "zsh", "dash", "ksh":
			s.shell(segs, i, heredoc, depth)
		case "su":
			for k, a := range args {
				if v, ok := strings.CutPrefix(a, "--command="); ok {
					s.recognize(v, depth+1, true)
				} else if (a == "-c" || a == "--command") && k+1 < len(args) {
					s.recognize(args[k+1], depth+1, true)
				}
			}
		case "-c", "--command": // flock FILE -c CMD
			if len(args) > 0 && slices.ContainsFunc(seg.Tokens[:seg.Cursor], func(t shell.Token) bool { return shell.Executable(t.Value) == "flock" }) {
				s.recognize(args[0], depth+1, true)
			}
		case "source", ".":
			if slices.Contains(args, "<") { // source <(...): text the scan cannot see
				s.add("unresolved", seg.Raw)
			}
		case "eval": // runs its arguments joined by spaces
			if len(args) > 0 && args[0] == "--" {
				args = args[1:]
			}
			s.recognize(strings.Join(args, " "), depth+1, true)
		case "psql", "mysql", "mariadb", "sqlite3":
			var payloads []string
			for _, a := range args {
				payloads = append(payloads, strings.TrimPrefix(strings.TrimPrefix(a, "--command="), "--execute="))
				if len(a) > 2 && a[0] == '-' && a[1] != '-' {
					payloads = append(payloads, a[2:]) // -e'DROP ...', -c'DROP ...'
				}
			}
			texts, unknown := s.stdin(segs, i, heredoc)
			if unknown == "file" {
				s.add("unresolved", seg.Raw)
			}
			if slices.ContainsFunc(append(payloads, texts...), sqlDestroys) {
				s.add("sql", seg.Raw)
			}
		case "rm":
			if !slices.ContainsFunc(args, func(a string) bool { return a == "--recursive" || shortFlag(a, "rR") }) {
			} else if s.allowedRemoval(seg) {
				var heads []string
				for _, t := range seg.Tokens[:min(seg.Cursor+1, len(seg.Tokens))] {
					heads = append(heads, t.Value)
				}
				s.allowed = append(s.allowed, allowedRm{depth, i, seg.Raw, heads})
			} else {
				s.add("fs", seg.Raw)
			}
		case "trap": // its action runs later: on a signal or at exit
			if len(args) > 0 && args[0] == "--" {
				args = args[1:]
			}
			if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
				s.noAllow++
				s.recognize(args[0], depth+1, true)
				s.noAllow--
			}
		case "chmod", "chown", "chgrp":
			if slices.ContainsFunc(args, func(a string) bool { return a == "--recursive" || shortFlag(a, "R") }) &&
				slices.ContainsFunc(seg.ArgTokens(), func(t shell.Token) bool { n := normTarget(t, s.home, s.user); return n == "/" || n == "~" }) {
				s.add("fs", seg.Raw)
			}
		case "dd":
			if slices.ContainsFunc(args, func(a string) bool {
				return strings.HasPrefix(a, "of=/dev/") && !slices.Contains([]string{"of=/dev/null", "of=/dev/stdout", "of=/dev/stderr"}, a)
			}) {
				s.add("fs", seg.Raw)
			}
		case "find":
			if slices.Contains(args, "-delete") {
				s.add("fs", seg.Raw)
			}
			at := seg.ArgTokens()
			for k := 0; k < len(at); k++ {
				if !slices.Contains([]string{"-exec", "-execdir", "-ok", "-okdir"}, at[k].Value) {
					continue
				}
				inv := at[k+1:]
				end := slices.IndexFunc(inv, func(t shell.Token) bool { return t.Value == ";" || t.Value == "+" })
				if end < 0 {
					end = len(inv)
				}
				raws := make([]string, end)
				for j, t := range inv[:end] {
					raws[j] = t.Raw
				}
				s.noAllow++ // once per file found
				s.recognize(strings.Join(raws, " "), depth+1, true)
				s.noAllow--
				k += end + 1
			}
		case "git":
			var allow []string
			if s.in.AgentID == "" {
				allow = s.c.Git.AllowActions
			}
			if cat := gitDestroys(args, allow); cat != "" {
				s.add(cat, seg.Raw)
			}
			if cat, why := s.gitProtected(args, xargs); cat != "" {
				s.add(cat, why+": "+seg.Raw)
			}
		}
		s.magento(seg, name)
		if xargs {
			s.noAllow--
		}
	}
	s.ran = s.ran || unsafe
	// Backtick substitutions run like `$(...)`, also inside double quotes,
	// in a directory the scan no longer tracks.
	s.dir = ""
	for _, b := range shell.BacktickBodies(command) {
		s.recognize(b.Body, depth+1, false)
	}
}

// safeHeads cannot create a link or move data into a directory, which a
// later rm target would then follow to what the hook cannot see. Only these
// (and assignments) may run before an allowed rm: any other command, a
// wrapper or an interpreter, turns the allow paths off (an allowlist, so an
// unknown linker asks). for, select, done, fi and } close or open lists.
// ponytail: cd, pushd and popd count as the builtins even when the shell
// starts with functions that wrap them.
var (
	safeHeads = []string{"rm", "rmdir", "mkdir", "cd", "pushd", "popd", "echo", "printf", "test", "[", "[[", "true", "false",
		":", "ls", "pwd", "set", "export", "unset", "local", "mktemp", "cat", "touch", "for", "select", "done", "fi", "}"}
	// subscriptHeads are safe heads that evaluate an argument's array
	// subscript. ponytail: any `[` in an argument counts.
	subscriptHeads = []string{"unset", "export", "local", "set", "test", "[", "[["}
	headPrefix     = []string{"!", "{", "if", "then", "else", "elif", "do", "while", "until"}
	// shellWords: bash 5.3 builtins and reserved words (compgen -b, -k)
	shellWords = strings.Fields(`. : [ alias bg bind break builtin caller cd command compgen complete compopt continue
		declare dirs disown echo enable eval exec exit export false fc fg getopts hash help history jobs kill let local
		logout mapfile popd printf pushd pwd read readarray readonly return set shift shopt source suspend test times trap
		true type typeset ulimit umask unalias unset wait
		if then else elif fi case esac for select while until do done in function time { } ! [[ ]] coproc`)
	// deferWords run a body later, again or on a call: its rm may follow code
	// written after it.
	deferWords  = []string{"for", "select", "while", "until", "function"}
	plainMktemp = regexp.MustCompile(`^\$\(mktemp((?: +[A-Za-z0-9_./%+=:,@-]+)*) *\)`)
	mktempFlag  = regexp.MustCompile(`^(?:-[dqt]+|--directory|--quiet|--tmpdir(?:=.*)?|--suffix=.*)$`)
)

// safeSeg: seg runs nothing but a safeHeads command (or only assignments),
// with no wrapper before it.
func safeSeg(seg shell.Segment) bool {
	for k := 0; k < seg.Cursor && k < len(seg.Tokens); k++ {
		switch t := seg.Tokens[k]; {
		case t.Redirect:
			if k+1 < len(seg.Tokens) && !seg.Tokens[k+1].Redirect {
				k++ // its target
			}
		case assignWord.MatchString(t.Raw), slices.Contains(headPrefix, t.Raw):
		default:
			return false // sudo, env, xargs, nice, function ...
		}
	}
	head, ok := seg.Head()
	if ok && slices.Contains(subscriptHeads, seg.Name()) && slices.ContainsFunc(seg.Args(), func(a string) bool {
		return strings.Contains(a, "[")
	}) {
		return false // unset 'a[V]' evaluates V's value as a subscript, $( included
	}
	// a head with a slash is a file, whatever its name
	return !ok || !strings.Contains(head.Value, "/") && slices.Contains(safeHeads, seg.Name())
}

// concurrent: a & or | runs a job beside the rms the allow paths passed,
// so once any segment anywhere is unsafe they ask after all. Kept: a
// top-level rm that a chain of && and | joins to every top-level pipe
// after it, with no & and nothing concurrent nested: && makes the rm
// finish before any pipe stage starts (rm -rf D && git archive X | tar -x -C D).
//
// Any rm asks when rm, or a word the scan follows, may not be what it
// reads: see dScan.shadowed and funcs, known once the whole command is
// scanned.
func (s *dScan) concurrent() {
	conc := s.unsafeAny && (s.concNested || s.amp || s.pipes[0] != 0)
	brk := -1 // the last segment before the last pipe that ends the && and | chain
	for k := s.pipes[1] - 2; k >= 0 && brk < 0; k-- {
		if sep := s.top[k].Separator; sep != "&&" && sep != "|" {
			brk = k
		}
	}
	for _, r := range s.allowed {
		switch {
		case s.shadowed || slices.ContainsFunc(r.heads, func(h string) bool { return s.funcs[h] }):
		case !conc:
			continue
		// before the first pipe and after brk: its own separator is &&
		case !s.concNested && !s.amp && r.depth == 0 && r.idx > brk && r.idx < s.pipes[0]-1:
			continue
		}
		s.add("fs", r.raw)
	}
}

// shadows records what segs[i] holds that may run in place of a later or
// repeated rm: a function definition (its name), alias or enable, or a
// command word bash expands, which may be either.
func (s *dScan) shadows(segs []shell.Segment, i int) {
	seg := segs[i]
	define := func(name string) {
		if s.funcs == nil {
			s.funcs = map[string]bool{}
		}
		s.funcs[name] = true
		// a function named like a word the scan follows: cd, rm, echo ...
		s.shadowed = s.shadowed || slices.Contains(shellWords, name) || slices.Contains(safeHeads, name)
	}
	if n := len(seg.Tokens); n > 0 && seg.Separator == "(" && i+1 < len(segs) && len(segs[i+1].Tokens) == 0 && segs[i+1].Separator == ")" {
		define(seg.Tokens[n-1].Value) // f()
	}
	for k, t := range seg.Tokens[:max(len(seg.Tokens)-1, 0)] {
		if t.Bare() == "function" {
			define(seg.Tokens[k+1].Value)
		}
	}
	h, ok := seg.Head()
	s.shadowed = s.shadowed || ok && expandedWord(h.Raw) || slices.Contains([]string{"alias", "enable", "hash"}, seg.Name())
}

// deferred: a loop or function definition in segs.
func deferred(segs []shell.Segment) bool {
	for k, seg := range segs {
		if seg.Separator == "(" && k+1 < len(segs) && len(segs[k+1].Tokens) == 0 && segs[k+1].Separator == ")" && len(seg.Tokens) > 0 {
			return true // f()
		}
		for _, t := range seg.Tokens[:min(seg.Cursor+1, len(seg.Tokens))] {
			if slices.Contains(deferWords, t.Bare()) {
				return true
			}
		}
	}
	return false
}

// badSubst is the offset of the first command substitution, process
// substitution, function substitution (`${ cmd; }`, shell.FunSubst: the scan
// never reads its body as a command) or backtick in text that is not a plain
// `$(mktemp ...)` (mktempArgs); -1 when there is none.
//
// ponytail: raw text, quotes and heredoc bodies included: a quoted `$(`
// asks too.
func badSubst(text string) int {
	for i := 0; i < len(text); i++ {
		switch {
		case text[i] == '`', strings.HasPrefix(text[i:], "<("), strings.HasPrefix(text[i:], ">("):
			return i
		case strings.HasPrefix(text[i:], "$("):
			m := plainMktemp.FindStringSubmatch(text[i:])
			if m == nil || !mktempArgs(strings.Fields(m[1])) {
				return i
			}
			i += len(m[0]) - 1
		case text[i] == '$' && shell.FunSubst(text[i+1:]):
			return i
		}
	}
	return -1
}

// mktempArgs: every argument is an allowed option (-d, -q, -t, -p DIR,
// --directory, --quiet, --tmpdir[=DIR], --suffix=X) or a template, all
// plain words; --help, -u and the like create no directory.
func mktempArgs(args []string) bool {
	for k := 0; k < len(args); k++ {
		switch a := args[k]; {
		case !plainWord.MatchString(a):
			return false
		case a == "-p":
			if k++; k == len(args) || !plainWord.MatchString(args[k]) {
				return false
			}
		case mktempFlag.MatchString(a), !strings.HasPrefix(a, "-"):
		default:
			return false
		}
	}
	return true
}

func rawArgs(toks []shell.Token) []string {
	raws := make([]string, len(toks))
	for k, t := range toks {
		raws[k] = t.Raw
	}
	return raws
}

// dynamic: a head built by an expansion runs a command the scan cannot
// name; with arguments it is unresolved (a lone `$cmd` or `$(...)` word is
// not: eval "$cmd", eval "$(ssh-agent -s)"). The arguments of a `$(...)`
// head follow its closing parenthesis, in the segment after closing[i].
func (s *dScan) dynamic(command string, segs []shell.Segment, i int, closing map[int]int) {
	seg := segs[i]
	n, end := len(seg.ArgTokens()), seg.End
	if k, ok := closing[i]; ok && n == 0 && k+1 < len(segs) {
		n, end = len(segs[k+1].Tokens), segs[k+1].End
	}
	if h, ok := seg.Head(); n > 0 || ok && braceWord(h.Raw) { // a brace head expands to several words
		s.add("unresolved", command[seg.Start:end])
	}
}

// closingSegments maps each segment ending in "(" to the segment ending in
// its matching ")" (one pass).
func closingSegments(segs []shell.Segment) map[int]int {
	m := map[int]int{}
	var open []int
	for k, seg := range segs {
		switch seg.Separator {
		case "(":
			open = append(open, k)
		case ")":
			if len(open) > 0 {
				m[open[len(open)-1]] = k
				open = open[:len(open)-1]
			}
		}
	}
	return m
}

// shell: a shell runs its -c command string (the first operand after its
// options), else a script operand (not inspected), else its standard input
// (see stdin), which is unresolved when unknown, like process substitution
// (`bash <(...)`).
func (s *dScan) shell(segs []shell.Segment, i int, heredoc func(shell.Segment) (string, bool), depth int) {
	seg := segs[i]
	args := seg.Args()
	command, stdin, options := false, false, true
operands:
	for k := 0; k < len(args); k++ {
		switch a := args[k]; {
		case a == "<" || a == ">":
			s.add("unresolved", seg.Raw)
			return
		case options && a == "--":
			options = false
		case options && a == "-":
			stdin = true
			break operands
		case options && strings.HasPrefix(a, "--"):
			if a == "--rcfile" || a == "--init-file" {
				k++
			}
		case options && len(a) > 1 && (a[0] == '-' || a[0] == '+'):
			command = command || strings.ContainsRune(a, 'c')
			stdin = stdin || strings.ContainsRune(a, 's')
			if c := a[len(a)-1]; c == 'o' || c == 'O' {
				k++
			}
		case command:
			s.recognize(a, depth+1, true)
			return
		case stdin:
			break operands
		default:
			return // a script file is not inspected
		}
	}
	if command {
		return // -c without a command string fails
	}
	texts, unknown := s.stdin(segs, i, heredoc)
	if unknown != "" {
		s.add("unresolved", seg.Raw)
	}
	for _, t := range texts {
		s.recognize(t, depth+1, true)
	}
}

// stdin is what segment i reads on standard input when the scan can tell:
// its heredoc body or here-string, a file redirected into it, or an echo
// (-n/-e/-E stripped), printf '%s' or '%s\n', or cat (of a heredoc or
// files) feeding it through a pipe. A file
// is read when it is a literal regular file of at most maxSQLFile bytes;
// unknown is "file" for one that is not, "pipe" for another producer.
func (s *dScan) stdin(segs []shell.Segment, i int, heredoc func(shell.Segment) (string, bool)) (texts []string, unknown string) {
	file := func(name string) {
		if b, ok := s.readFile(name); ok {
			texts = append(texts, b)
		} else {
			unknown = "file"
		}
	}
	seg := segs[i]
	if body, ok := heredoc(seg); ok {
		texts = append(texts, body)
	}
	for k := 0; k+1 < len(seg.Tokens); k++ {
		switch t := seg.Tokens[k]; {
		case !t.Redirect:
		case t.Value == "<<<" || t.Value == "0<<<":
			texts = append(texts, seg.Tokens[k+1].Value)
		case t.Value == "<" || t.Value == "0<":
			file(seg.Tokens[k+1].Value)
		}
	}
	if i == 0 || segs[i-1].Separator != "|" {
		return texts, unknown
	}
	prev := segs[i-1]
	switch args := prev.Args(); prev.Name() {
	case "echo":
		escapes := false
		for len(args) > 0 && echoFlags.MatchString(args[0]) {
			escapes = escapes || strings.ContainsRune(args[0], 'e')
			args = args[1:]
		}
		text := strings.Join(args, " ")
		if escapes && strings.Contains(text, `\`) && unknown == "" {
			unknown = "pipe"
		}
		return append(texts, text), unknown
	case "printf":
		if len(args) > 0 && args[0] == "--" {
			args = args[1:]
		}
		if len(args) > 0 && (args[0] == "%s" || args[0] == `%s\n`) {
			sep := "" // the format repeats per argument
			if args[0] != "%s" {
				sep = "\n"
			}
			return append(texts, strings.Join(args[1:], sep)), unknown
		}
		if unknown == "" {
			unknown = "pipe" // another format: what runs is unknown; the words still count for SQL
		}
		return append(texts, strings.Join(args, " ")), unknown
	case "cat":
		body, ok := heredoc(prev)
		if ok {
			texts = append(texts, body)
		}
		for _, a := range prev.Args() {
			if !strings.HasPrefix(a, "-") {
				ok = true
				file(a)
			}
		}
		if ok {
			return texts, unknown
		}
	}
	if unknown == "" {
		unknown = "pipe"
	}
	return texts, unknown
}

// readFile reads a literal regular file (relative to cwd) of at most
// maxSQLFile bytes; /dev/null is empty.
func (s *dScan) readFile(name string) (string, bool) {
	if name == "/dev/null" {
		return "", true
	}
	if name == "" || strings.ContainsAny(name, "$*?[{`~") || !filepath.IsAbs(name) && s.in.Cwd == "" {
		return "", false
	}
	if !filepath.IsAbs(name) {
		name = filepath.Join(s.in.Cwd, name)
	}
	if fi, err := os.Stat(name); err != nil || !fi.Mode().IsRegular() || fi.Size() > maxSQLFile {
		return "", false // a FIFO would block
	}
	b, err := os.ReadFile(name)
	return string(b), err == nil && len(b) <= maxSQLFile
}

// shortFlag is /^-[^-]*[chars]/: a short option cluster holding one of chars.
func shortFlag(a, chars string) bool {
	if len(a) < 2 || a[0] != '-' {
		return false
	}
	a = a[1:]
	if i := strings.IndexByte(a, '-'); i >= 0 {
		a = a[:i]
	}
	return strings.ContainsAny(a, chars)
}

var gitForce = regexp.MustCompile(`^--force(?:-with-lease|=|$)`)

// gitDestroys is "git" for push --force/-f/--force-with-lease/+refspec,
// clean or rebase (as the TS), a reset or restore that may touch the work
// tree (see gitResetKeeps), checkout -f, with -- or
// of ., branch -D, stash drop/clear; "unresolved" for an alias defined on
// the command line (`git -c alias.p='push --force' p`); else "". An action
// in allow (git.allow_actions) is not reported, except a rebase that runs a
// command or an editor: -x/--exec, -i/--interactive, --edit-todo (and their
// abbreviations), or any -c/--config-env (sequence.editor) or --exec-path=.
// ponytail: config through the environment (GIT_CONFIG_COUNT, as for every
// other git command) and a custom -s strategy on PATH are not seen.
func gitDestroys(args, allow []string) string {
	i, cfgOpt := 0, false
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		f := args[i]
		i++
		cfgOpt = cfgOpt || f == "-c" || strings.HasPrefix(f, "--config-env") || strings.HasPrefix(f, "--exec-path=")
		if v, ok := strings.CutPrefix(f, "--config-env="); ok && strings.HasPrefix(strings.ToLower(v), "alias.") {
			return "unresolved"
		}
		if gitValueOpts[f] {
			if (f == "-c" || f == "--config-env") && i < len(args) && strings.HasPrefix(strings.ToLower(args[i]), "alias.") {
				return "unresolved"
			}
			i++
		}
	}
	if i >= len(args) {
		return ""
	}
	action, flags := args[i], args[i+1:]
	if expandedWord(action) { // `git $X`, `git {$B,}x`: a subcommand the scan cannot name
		return "unresolved"
	}
	force := slices.ContainsFunc(flags, func(a string) bool { return gitForce.MatchString(a) || shortFlag(a, "f") })
	var hit bool
	switch action {
	case "push":
		hit = force || slices.ContainsFunc(flags, func(a string) bool { return strings.HasPrefix(a, "+") })
	case "reset":
		hit = !gitOptionsIn(flags, gitResetKeeps, false)
	case "restore":
		hit = !slices.ContainsFunc(flags, func(a string) bool { return a == "-S" || a == "--staged" }) ||
			!gitOptionsIn(flags, gitRestoreKeeps, true)
	case "clean", "rebase":
		hit = true
	case "checkout":
		hit = force || slices.Contains(flags, "--") || slices.Contains(flags, ".")
	case "branch":
		hit = slices.ContainsFunc(flags, func(a string) bool { return shortFlag(a, "D") }) ||
			force && slices.ContainsFunc(flags, func(a string) bool { return a == "--delete" || shortFlag(a, "d") })
	case "stash":
		hit = len(flags) > 0 && (flags[0] == "drop" || flags[0] == "clear")
	}
	runs := action == "rebase" && (cfgOpt || slices.ContainsFunc(flags, func(a string) bool {
		return shortFlag(a, "xi") || strings.HasPrefix(a, "--ex") || strings.HasPrefix(a, "--in") || strings.HasPrefix(a, "--ed")
	}))
	if hit && (runs || !slices.Contains(allow, action)) {
		return "git"
	}
	return ""
}

// gitResetKeeps are the reset options that leave the work tree alone
// (--keep refuses to lose local changes); gitRestoreKeeps, with --staged,
// those that write only the index. Anything else, an abbreviation or a
// short cluster included, is destructive.
var (
	gitResetKeeps   = []string{"-q", "--quiet", "--soft", "--mixed", "--keep", "-N", "--intent-to-add", "-p", "--patch", "--refresh", "--no-refresh"}
	gitRestoreKeeps = []string{"-S", "--staged", "-q", "--quiet", "-p", "--patch", "--progress", "--no-progress"}
)

// gitOptionsIn: every option before `--` is in keeps; source also accepts
// restore's -s/--source TREE.
func gitOptionsIn(flags, keeps []string, source bool) bool {
	for k := 0; k < len(flags); k++ {
		switch f := flags[k]; {
		case f == "--":
			return true
		case !strings.HasPrefix(f, "-") || f == "-" || slices.Contains(keeps, f):
		case source && (f == "-s" || f == "--source"):
			k++
		case source && (strings.HasPrefix(f, "--source=") || strings.HasPrefix(f, "-s")):
		default:
			return false
		}
	}
	return true
}

var (
	echoFlags = regexp.MustCompile(`^-[neE]+$`)
	// sqlNoise: comments and strings go, quoted identifiers become an atom,
	// so a table named "where" is no predicate or statement boundary.
	sqlNoise    = regexp.MustCompile("--[^\\n]*|/\\*[\\s\\S]*?\\*/|'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"|`(?:``|[^`])*`|\\[(?:\\]\\]|[^\\]])*\\]")
	sqlDrop     = regexp.MustCompile(`(?i)^\s*(?:DROP\s+(?:TABLE|DATABASE|SCHEMA|INDEX|VIEW)\b|TRUNCATE\s+(?:TABLE\s+)?\S)`)
	sqlDelete   = regexp.MustCompile(`(?i)^\s*DELETE\s+FROM\s+\S`)
	sqlWhere    = regexp.MustCompile(`(?i)\bWHERE\b`)
	sqlWhereAll = regexp.MustCompile(`(?i)\bWHERE\s+(?:1\s*=\s*1|TRUE)\s*$`)
)

// sqlDestroys: DROP, TRUNCATE, or DELETE FROM without a real WHERE.
func sqlDestroys(sql string) bool {
	code := sqlNoise.ReplaceAllStringFunc(sql, func(raw string) string {
		if strings.ContainsAny(raw[:1], "\"`[") {
			return "identifier"
		}
		return " "
	})
	for _, st := range strings.Split(code, ";") {
		if sqlDrop.MatchString(st) {
			return true
		}
		if sqlDelete.MatchString(st) && (!sqlWhere.MatchString(st) || sqlWhereAll.MatchString(strings.TrimSpace(st))) {
			return true
		}
	}
	return false
}

// heredocEscapes are the backslashes bash removes from the body of a heredoc
// with an unquoted delimiter.
var heredocEscapes = strings.NewReplacer(`\\`, `\`, `\$`, `$`, "\\`", "`", "\\\n", "")

// caseWord: a `case` in a substitution body, whose patterns end in `)`.
var caseWord = regexp.MustCompile(`(?:^|[\s;&|(])case\s`)

// dqSubstitutions are the bodies of `$(...)` inside double quotes of a raw
// word (an unquoted `$(` already splits into segments; single quotes and
// $'...' are literal: shell.Quoting). A body ends at its `)` (shell.SubstEnd);
// an unterminated one, or one with a `case` (its patterns end in `)`), runs to
// the end of the word.
func dqSubstitutions(raw string) []string {
	if !strings.Contains(raw, "$(") {
		return nil
	}
	var bodies []string
	var q shell.Quoting
	for i := 0; i < len(raw); i++ {
		if n := q.Skip(raw, i); n > 0 {
			i += n - 1
			continue
		}
		if !strings.HasPrefix(raw[i:], "$(") {
			continue
		}
		end := shell.SubstEnd(raw, i+2)
		if caseWord.MatchString(strings.ReplaceAll(raw[i+2:end], "\\\n", "")) {
			end = len(raw)
		}
		bodies = append(bodies, raw[i+2:end])
		i = end
	}
	return bodies
}

// expand resolves an allow_roots entry: $scratchpad_dir (skipped when
// unknown) and ~, cleaned; "" when it is not an absolute literal path.
func (s *dScan) expand(r string) string {
	switch {
	case strings.HasPrefix(r, "$scratchpad_dir"):
		if s.in.ScratchpadDir == "" {
			return ""
		}
		r = s.in.ScratchpadDir + strings.TrimPrefix(r, "$scratchpad_dir")
	case r == "~" || strings.HasPrefix(r, "~/"):
		if s.home == "" {
			return ""
		}
		r = s.home + r[1:]
	}
	if !filepath.IsAbs(r) || strings.ContainsAny(r, "$*?[{`") {
		return ""
	}
	return filepath.Clean(r)
}

// allowedRemoval: a recursive rm whose every literal target lies strictly
// inside an allow_roots entry, both with the symlinks of their longest
// existing prefix resolved, at or under a `$(mktemp)` directory, or matches
// a regenerable glob, and nothing before it may have linked or moved data
// (s.ran). xargs appends targets the scan cannot see; a target
// with an expansion, glob (but a regenerable DIR/*), ~user or a `..`
// component is outside; a
// quoted ~ is a relative name, and a relative name after a scanned
// cd/pushd/popd is outside unless a `cd DIR &&` chain names the directory.
func (s *dScan) allowedRemoval(seg shell.Segment) bool {
	// A "(" that ends the rm's words is a substitution among them or an
	// extended glob the scan split: DIR/@(a)/../.. names what it cannot read.
	if s.noAllow > 0 || seg.Separator == "(" {
		return false
	}
	var targets []shell.Token
	options := true
	for _, t := range seg.ArgTokens() {
		switch a := longOpt("rm", t.Value); {
		case a == "--no-preserve-root":
			return false
		case options && a == "--":
			options = false
		case options && strings.HasPrefix(a, "-"):
		default:
			targets = append(targets, t)
		}
	}
	if len(targets) == 0 {
		return false
	}
	for _, tok := range targets {
		t, star := strings.CutSuffix(tok.Value, "/*")
		if slices.Contains(strings.Split(t, "/"), "..") {
			return false // the kernel resolves .. after symlinks; path cleans it before
		}
		t = s.path(t, tok.Raw)
		switch {
		case t == "":
			return false
		case star:
			if s.reglobbed || !s.regenerable(t, true) {
				return false
			}
		case t == mktempRoot || strings.HasPrefix(t, mktempRoot+"/"),
			slices.ContainsFunc(s.roots, func(r string) bool { return strings.HasPrefix(t, r+"/") }),
			s.regenerable(t, false):
		default:
			return false
		}
	}
	// With no wrapper that may run rm elsewhere (env -C, sudo -D, sudo -R).
	return !s.ran && safeSeg(seg)
}

// path is a literal target as an absolute clean path with the symlinks of
// its longest existing prefix resolved; "" when it has an expansion, glob or
// ~user, or is relative to an unknown directory.
func (s *dScan) path(t, raw string) string {
	if t == "" || strings.ContainsAny(t, "$*?[{`") {
		return ""
	}
	if t[0] == '~' && raw[0] == '~' {
		if s.home == "" || s.rehomed || t != "~" && !strings.HasPrefix(t, "~/") {
			return ""
		}
		t = s.home + t[1:]
	}
	if !filepath.IsAbs(t) {
		base := s.base()
		if base == "" {
			return ""
		}
		t = filepath.Join(base, t)
	}
	t = filepath.Clean(t)
	// per-process views: /proc/self/cwd is the hook's directory here, the
	// shell's (or sudo's) when rm runs
	if strings.HasPrefix(t, "/proc/") || strings.HasPrefix(t, "/dev/") {
		return ""
	}
	return resolved(t)
}

// base is the directory relative names resolve against: the cd chain's,
// else Cwd while no cd/pushd/popd was scanned; "" when unknown.
func (s *dScan) base() string {
	switch {
	case s.dir != "":
		return s.dir
	case s.cd || !filepath.IsAbs(s.in.Cwd):
		return ""
	}
	return filepath.Clean(s.in.Cwd)
}

// cdTarget is the directory of `cd DIR`: DIR absolute (after ~), or
// starting with ./ (CDPATH is not consulted), cleaned; "" otherwise or when
// DIR has a `..` component, which bash may resolve after a symlink (set -P).
func (s *dScan) cdTarget(seg shell.Segment) string {
	args := seg.ArgTokens()
	if len(args) != 1 {
		return ""
	}
	t, raw := args[0].Value, args[0].Raw
	if strings.ContainsAny(t, "$*?[{`") || slices.Contains(strings.Split(t, "/"), "..") ||
		!filepath.IsAbs(t) && t != "." && !strings.HasPrefix(t, "./") && !strings.HasPrefix(raw, "~") {
		return ""
	}
	if t = s.path(t, raw); t == "" {
		return ""
	}
	return t
}

// regenerable: p (absolute, resolved; DIR/* when star) lies in the nearest
// project root above it (a .git entry or a Magento bin/magento, p itself
// included, below / and the HOME and passwd home directories, at least one
// known) and matches a regenerable glob relative to it.
//
// ponytail: DIR/* is matched as the literal name `*`, sound for globs whose
// classes do not exclude `*` (the defaults); dotfiles are left out by bash.
func (s *dScan) regenerable(p string, star bool) bool {
	if len(s.c.FS.Regenerable) == 0 {
		return false
	}
	var homes []string // HOME and the passwd home, as given and resolved
	for _, h := range []string{s.home, s.pwHome} {
		if h != "" {
			homes = append(homes, h, resolved(h))
		}
	}
	if len(homes) == 0 {
		return false // no home to stop the walk at
	}
	for d := p; ; d = filepath.Dir(d) {
		if d == "/" || d == "." || slices.Contains(homes, d) {
			return false // a bin/magento wrapper or dotfiles repo there is no project
		}
		_, err := os.Lstat(filepath.Join(d, ".git"))
		if err != nil {
			_, err = os.Lstat(filepath.Join(d, "bin", "magento"))
		}
		if err == nil {
			rel, _ := filepath.Rel(d, p)
			if star {
				rel = strings.TrimPrefix(rel+"/*", "./")
			}
			return slices.ContainsFunc(s.c.FS.Regenerable, func(g string) bool {
				ok, _ := doublestar.Match(g, rel)
				return ok
			})
		}
	}
}

// resolved is the absolute path p with the symlinks of its longest existing
// prefix resolved.
func resolved(p string) string {
	for d := p; ; d = filepath.Dir(d) {
		if r, err := filepath.EvalSymlinks(d); err == nil {
			return filepath.Join(r, strings.TrimPrefix(p, d))
		}
		if d == "/" || d == "." {
			return p
		}
	}
}

// longOpts are GNU long options whose unique abbreviations (`--recur`) the
// commands accept.
var longOpts = func() map[string][]string {
	own := []string{"--changes", "--dereference", "--no-dereference", "--from", "--silent", "--quiet", "--verbose",
		"--no-preserve-root", "--preserve-root", "--reference", "--recursive", "--help", "--version"}
	return map[string][]string{
		"rm": {"--force", "--interactive", "--one-file-system", "--no-preserve-root", "--preserve-root", "--recursive",
			"--dir", "--verbose", "--help", "--version"},
		"chmod": own, "chown": own, "chgrp": own,
	}
}()

// longOpt spells out a unique abbreviation of one of name's long options.
func longOpt(name, a string) string {
	opt, val, eq := strings.Cut(a, "=")
	if len(opt) < 3 || !strings.HasPrefix(opt, "--") {
		return a
	}
	match := ""
	for _, o := range longOpts[name] {
		if o == opt {
			return a
		}
		if strings.HasPrefix(o, opt) {
			if match != "" {
				return a // ambiguous
			}
			match = o
		}
	}
	if match == "" {
		return a
	}
	if eq {
		return match + "=" + val
	}
	return match
}

var magentoBins = map[string]bool{"magento": true, "n98-magerun2": true, "n98-magerun2.phar": true}

// magento: a magento word in command position or as an argument of a
// launcher (php, docker compose exec, ddev …), then its subcommand.
func (s *dScan) magento(seg shell.Segment, name string) {
	if shell.DataCommands[name] {
		return
	}
	words := append([]string{name}, seg.Args()...)
	k := slices.IndexFunc(words, func(w string) bool { return magentoBins[shell.Executable(w)] })
	if k < 0 {
		return
	}
	for _, sub := range words[k+1:] {
		if strings.HasPrefix(sub, "-") {
			continue
		}
		if slices.ContainsFunc(s.c.Magento.Globs, func(g string) bool { return magentoMatch(g, sub) }) {
			s.add("magento", seg.Raw)
		}
		return
	}
}

// magentoMatch: sub matches glob g, or abbreviates it as Symfony resolves
// commands: each colon part a prefix of g's part (of its literal prefix
// before a wildcard), or already matching it.
func magentoMatch(g, sub string) bool {
	if ok, _ := path.Match(g, sub); ok {
		return true
	}
	gp, sp := strings.Split(g, ":"), strings.Split(sub, ":")
	if len(gp) != len(sp) {
		return false
	}
	for k, p := range sp {
		lit := gp[k][:strings.IndexAny(gp[k]+"*", "*?[")]
		if ok, _ := path.Match(gp[k], p); !ok && (p == "" || !strings.HasPrefix(lit, p)) {
			return false
		}
	}
	return true
}

// hardEntry is a parsed hard_deny entry: a lone flag (any segment passing
// it unquoted), a lone command (that head or head.*), or a head with flags
// that must all be present and operands that must all be targets.
type hardEntry struct {
	entry, flag, head string
	flags, operands   []string
}

func parseHardEntry(e string) (hardEntry, bool) {
	var words []shell.Token
	for _, t := range shell.Tokenize(e, false) {
		if !t.Operator {
			words = append(words, t)
		}
	}
	h := hardEntry{entry: e}
	switch {
	case len(words) == 0:
		return h, false
	case len(words) == 1 && strings.HasPrefix(words[0].Value, "-"):
		h.flag = words[0].Value
	default:
		h.head = shell.Executable(words[0].Value)
		h.flags, h.operands = optionsAndTargets(h.head, words[1:], "", "")
	}
	return h, true
}

// rmAliases maps rm's long options and -R onto their short twins.
var rmAliases = map[string]string{"-R": "-r", "--recursive": "-r", "--force": "-f"}

// optionsAndTargets splits arguments into option keys (one per letter of a
// short cluster, a spelled-out long option without =value) and targets
// normalised by normTarget.
func optionsAndTargets(head string, args []shell.Token, home, user string) (flags, targets []string) {
	options := true
	for _, t := range args {
		switch a := longOpt(head, t.Value); {
		case options && a == "--":
			options = false
		case options && strings.HasPrefix(a, "--"):
			flags = append(flags, strings.SplitN(a, "=", 2)[0])
		case options && len(a) > 1 && a[0] == '-':
			for _, c := range a[1:] {
				flags = append(flags, "-"+string(c))
			}
		default:
			targets = append(targets, normTarget(t, home, user))
		}
	}
	if head == "rm" {
		for i, f := range flags {
			if a, ok := rmAliases[f]; ok {
				flags[i] = a
			}
		}
	}
	return flags, targets
}

// normTarget: an unquoted ~ or ~user (the current user), $HOME and ${HOME}
// outside single quotes, and the home directory itself are ~; a trailing /*
// names its directory, and the path is cleaned (~/ is ~, // is /). A quoted
// ~ is a literal name: ./~.
func normTarget(t shell.Token, home, user string) string {
	v := t.Value
	literal := strings.HasPrefix(v, "~") && !strings.HasPrefix(t.Raw, "~")
	if !literal && user != "" && (v == "~"+user || strings.HasPrefix(v, "~"+user+"/")) {
		v = "~" + v[1+len(user):]
	}
	for _, h := range []string{"${HOME}", "$HOME"} {
		if (v == h || strings.HasPrefix(v, h+"/")) && !strings.HasPrefix(t.Raw, "'") && !strings.HasPrefix(t.Raw, `\`) {
			v = "~" + v[len(h):]
			break
		}
	}
	if strings.HasSuffix(v, "/*") {
		v = v[:len(v)-1]
	}
	v = path.Clean(v)
	switch {
	case literal:
		return "./" + v
	case home != "" && v == home:
		return "~"
	case home != "" && strings.HasPrefix(v, home+"/"):
		return "~" + v[len(home):]
	}
	return v
}

func (s *dScan) hardDeny(seg shell.Segment) {
	name, args := seg.Name(), seg.ArgTokens()
	for _, h := range s.hard {
		var hit bool
		switch {
		case h.flag != "":
			// a quoted flag is data here: git commit -m "--no-preserve-root"
			hit = !shell.DataCommands[name] && slices.ContainsFunc(args, func(t shell.Token) bool {
				return t.Raw == t.Value && longOpt(name, t.Value) == h.flag
			})
		case len(h.flags) == 0 && len(h.operands) == 0:
			hit = name == h.head || strings.HasPrefix(name, h.head+".")
		case name == h.head:
			flags, targets := optionsAndTargets(name, args, s.home, s.user)
			hit = !slices.ContainsFunc(h.flags, func(f string) bool { return !slices.Contains(flags, f) }) &&
				!slices.ContainsFunc(h.operands, func(o string) bool { return !slices.Contains(targets, o) })
		}
		if hit {
			s.found = append(s.found, dFinding{text: clip(seg.Raw), hard: h.entry})
			return
		}
	}
}
