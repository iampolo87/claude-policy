package rules

import (
	"cmp"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Protected refs (rules.destructive.git.protected_refs), in the git
// category: a push that reaches one, and a command that makes one the
// upstream of a local branch with another name, which a later plain push
// sends there (an IDE's included, which this hook never sees). Not exempted
// by allow_actions.
//
// ponytail: a push.default, remote.*.push or remote.*.mirror set before the
// session is seen only by a plain push, which reads the repository;
// branch.autoSetupMerge=inherit, a start point naming a remote alone
// (`checkout -b x origin`), a remote whose name has a / and an alias defined
// in a config file are not seen.

// gitWait bounds one git call, well inside the rule's deadline: a config
// can include a FIFO. gitRun runs git in dir; tests replace it.
const gitWait = 40 * time.Millisecond

var gitRun = func(ctx context.Context, dir string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, gitWait)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	cmd.WaitDelay = 10 * time.Millisecond
	out, err := cmd.Output()
	return string(out), err
}

// gitRepo is what a scan read from one repository; branch is "" when
// detached or unread, cfg nil until read or when unread.
type gitRepo struct {
	branch  string
	cfg     map[string][]string
	cfgRead bool
}

type gitRefs struct {
	s    *dScan
	refs []string
	dir  string // where git runs; "" when unknown
	// foreign: -c (on push, remote, branch or include keys), --git-dir,
	// --work-tree, --namespace, --config-env or a GIT_ variable in the text:
	// what the hook reads may not be what git uses
	foreign bool
}

// gitProtected is "git" and why when git's args push to a protected ref or
// set one as an upstream, or push where only an unreadable repository
// says; "unresolved" when the target is an expansion or xargs appends it;
// else "".
func (s *dScan) gitProtected(args []string, appended bool) (cat, why string) {
	g := gitRefs{s: s, refs: s.c.Git.ProtectedRefs, dir: s.base(), foreign: s.gitEnv}
	if len(g.refs) == 0 {
		return "", ""
	}
	i := 0
	for ; i < len(args) && strings.HasPrefix(args[i], "-"); i++ {
		switch f := args[i]; {
		case f == "-C" && i+1 < len(args):
			i++
			g.dir = subdir(g.dir, args[i])
		case f == "-c" && i+1 < len(args):
			i++
			k := strings.ToLower(args[i])
			g.foreign = g.foreign || slices.ContainsFunc([]string{"push.", "remote.", "branch.", "include"}, func(p string) bool { return strings.HasPrefix(k, p) })
		case gitValueOpts[f]: // --attr-source, --exec-path, --super-prefix take one too
			i++
			g.foreign = g.foreign || f != "--attr-source" && f != "--exec-path" && f != "--super-prefix"
		case strings.HasPrefix(f, "--git-dir=") || strings.HasPrefix(f, "--work-tree=") ||
			strings.HasPrefix(f, "--namespace=") || strings.HasPrefix(f, "--config-env="):
			g.foreign = true
		}
	}
	if i >= len(args) {
		return "", ""
	}
	action, flags := args[i], args[i+1:]
	if appended && slices.Contains([]string{"push", "checkout", "switch", "branch", "worktree", "config", "remote"}, action) {
		return "unresolved", "xargs appends to git " + action
	}
	switch action {
	case "push":
		return g.push(flags)
	case "checkout":
		o := gitOptions(flags, gitSyntax{letters: "bB", valued: []string{"--conflict", "--orphan", "--pathspec-from-file"}})
		return g.create(o, at(o.pos, 0))
	case "switch":
		o := gitOptions(flags, gitSyntax{letters: "cC", create: []string{"--create", "--force-create"},
			valued: []string{"--conflict", "--orphan"}, dashArgs: true})
		return g.create(o, at(o.pos, 0))
	case "worktree":
		if len(flags) > 0 && flags[0] == "add" {
			o := gitOptions(flags[1:], gitSyntax{letters: "bB", valued: []string{"--reason"}, dashArgs: true})
			return g.create(o, at(o.pos, 1))
		}
	case "branch":
		return g.branch(gitOptions(flags, gitSyntax{up: true, dashArgs: true,
			valued: []string{"--format", "--sort", "--contains", "--no-contains", "--merged", "--no-merged", "--points-at"}}))
	case "config":
		return g.config(gitOptions(flags, gitSyntax{dashArgs: true}).pos)
	case "remote":
		if len(flags) > 0 && flags[0] == "add" && slices.ContainsFunc(flags[1:], func(f string) bool {
			opt, _, _ := strings.Cut(f, "=")
			return abbrev(opt, "--mirror", 4)
		}) {
			return "git", "mirror remote pushes every branch"
		}
	}
	return "", ""
}

func at(a []string, i int) string {
	if i < len(a) {
		return a[i]
	}
	return ""
}

// subdir is `git -C v` from base; "" when unknown.
func subdir(base, v string) string {
	switch {
	case expandedWord(v) || strings.HasPrefix(v, "~"):
		return ""
	case filepath.IsAbs(v):
		return filepath.Clean(v)
	case base == "":
		return ""
	}
	return filepath.Join(base, v)
}

// gitSyntax describes a subcommand for gitOptions: letters and create are
// the short and long options naming a new branch, up reads branch's -u,
// valued are the other long options taking a separate value (whose value
// would otherwise shift the positionals), dashArgs keeps the words after
// -- (checkout reads paths there).
type gitSyntax struct {
	letters  string
	create   []string
	up       bool
	valued   []string
	dashArgs bool
}

type gitOpts struct {
	creates  bool   // a branch-creating option was given
	name     string // its value
	track    string // "direct", "inherit" or ""
	noTrack  bool
	setsUp   bool // branch -u / --set-upstream-to
	upstream string
	short    string   // short option letters seen, values excluded
	long     []string // long options seen, without =value
	pos      []string
}

// abbrev: opt is full or a unique abbreviation git accepts, approximated by
// a prefix of at least min bytes.
func abbrev(opt, full string, min int) bool {
	return len(opt) >= min && strings.HasPrefix(full, opt)
}

func gitOptions(flags []string, sx gitSyntax) gitOpts {
	var o gitOpts
	for k := 0; k < len(flags); k++ {
		f := flags[k]
		next := func() string {
			if k+1 < len(flags) {
				k++
				return flags[k]
			}
			return ""
		}
		switch {
		case f == "--":
			if sx.dashArgs {
				o.pos = append(o.pos, flags[k+1:]...)
			}
			return o
		case !strings.HasPrefix(f, "-") || f == "-":
			o.pos = append(o.pos, f)
		case strings.HasPrefix(f, "--"):
			opt, val, eq := strings.Cut(f, "=")
			o.long = append(o.long, opt)
			value := func() string {
				if eq {
					return val
				}
				return next()
			}
			switch {
			case abbrev(opt, "--track", 4):
				o.track, o.noTrack = "direct", false
				if eq {
					o.track = val
				}
			case abbrev(opt, "--no-track", 6):
				o.track, o.noTrack = "", true
			case slices.ContainsFunc(sx.create, func(l string) bool { return abbrev(opt, l, 4) && (l != "--force-create" || len(opt) > len("--force")) }):
				o.creates, o.name = true, value()
			case sx.up && abbrev(opt, "--set-upstream-to", 5) && opt != "--set-upstream":
				o.setsUp, o.upstream = true, value()
			case slices.ContainsFunc(sx.valued, func(l string) bool { return abbrev(opt, l, 4) }):
				value()
			}
		default:
			for j := 1; j < len(f); j++ {
				c := f[j]
				if strings.IndexByte(sx.letters, c) >= 0 || sx.up && c == 'u' {
					v := f[j+1:]
					if v == "" {
						v = next()
					}
					if c == 'u' {
						o.setsUp, o.upstream = true, v
					} else {
						o.creates, o.name = true, v
					}
					break
				}
				o.short += string(c)
				if c == 't' {
					o.track, o.noTrack = "direct", false
				}
			}
		}
	}
	return o
}

// remote is p when ref names protected p, or HEAD (whichever branch that
// is), on a remote: R/p, remotes/R/p, refs/remotes/R/p.
func (g gitRefs) remote(ref string) (string, bool) {
	if strings.HasPrefix(ref, "refs/heads/") || strings.HasPrefix(ref, "heads/") {
		return "", false
	}
	ref = strings.TrimPrefix(strings.TrimPrefix(ref, "refs/"), "remotes/")
	r, p, ok := strings.Cut(ref, "/")
	return p, ok && r != "" && (p == "HEAD" || slices.Contains(g.refs, p))
}

// local is p when ref is protected branch p (p, heads/p, refs/heads/p: git
// completes a push destination without refs/ the same way).
func (g gitRefs) local(ref string) (string, bool) {
	p := strings.TrimPrefix(strings.TrimPrefix(ref, "refs/"), "heads/")
	return p, slices.Contains(g.refs, p)
}

// repo reads g.dir once per scan, and only one directory per scan (each
// read may take gitWait); nil when it cannot or may not be read.
func (g gitRefs) repo() *gitRepo {
	if g.foreign || g.dir == "" {
		return nil
	}
	if r, ok := g.s.repos[g.dir]; ok {
		return r
	}
	if len(g.s.repos) > 0 {
		return nil
	}
	out, err := gitRun(g.s.ctx, g.dir, "symbolic-ref", "--short", "-q", "HEAD")
	r := &gitRepo{}
	if err == nil {
		r.branch = strings.TrimSpace(out)
	}
	g.s.repos = map[string]*gitRepo{g.dir: r}
	return r
}

// current is the checked-out branch; ok is false when detached or unread.
func (g gitRefs) current() (string, bool) {
	if r := g.repo(); r != nil && r.branch != "" {
		return r.branch, true
	}
	return "", false
}

// settings is `git config --list` as key -> values; nil when unread.
func (g gitRefs) settings() map[string][]string {
	r := g.repo()
	if r == nil || r.branch == "" {
		return nil
	}
	if !r.cfgRead {
		r.cfgRead = true
		if out, err := gitRun(g.s.ctx, g.dir, "config", "--list", "-z"); err == nil {
			r.cfg = map[string][]string{}
			for _, e := range strings.Split(out, "\x00") {
				if k, v, ok := strings.Cut(e, "\n"); ok {
					r.cfg[k] = append(r.cfg[k], v)
				}
			}
		}
	}
	return r.cfg
}

// create: checkout -b, switch -c or worktree add -b NAME from start.
func (g gitRefs) create(o gitOpts, start string) (string, string) {
	if !o.creates || o.noTrack {
		return "", ""
	}
	if expandedWord(start) {
		return "unresolved", "start point " + start
	}
	if p, ok := g.remote(start); ok && o.name != p {
		return "git", fmt.Sprintf("upstream %s for %s, add --no-track", start, o.name)
	}
	if o.track == "inherit" {
		if start == "" || start == "HEAD" || start == "@" {
			start, _ = g.current()
		}
		if p, ok := g.local(start); ok && o.name != p {
			return "git", fmt.Sprintf("upstream inherited from %s for %s, add --no-track", p, o.name)
		}
	}
	return "", ""
}

// branch: -u/--set-upstream-to, or creating NAME START; any other mode
// (delete, move, copy, list) creates nothing.
func (g gitRefs) branch(o gitOpts) (string, string) {
	if o.setsUp {
		if expandedWord(o.upstream) {
			return "unresolved", "upstream " + o.upstream
		}
		p, ok := g.remote(o.upstream)
		if !ok {
			return "", ""
		}
		b := at(o.pos, 0)
		if b == "" {
			b, _ = g.current()
		}
		if b != p {
			return "git", fmt.Sprintf("upstream %s for %s", o.upstream, b)
		}
		return "", ""
	}
	long := func(modes ...string) bool {
		return slices.ContainsFunc(o.long, func(l string) bool {
			return slices.ContainsFunc(modes, func(m string) bool { return abbrev(l, m, 5) })
		})
	}
	// copy and rename carry the old branch's upstream to the new name:
	// -c|-m [OLD] NEW, OLD being the current branch when left out
	if strings.ContainsAny(o.short, "mMcC") || long("--move", "--copy") {
		old, dst := at(o.pos, 0), at(o.pos, 1)
		if len(o.pos) == 1 {
			old, _ = g.current()
			dst = o.pos[0]
		}
		if expandedWord(old) || expandedWord(dst) {
			return "unresolved", "branch copy or rename " + old + " " + dst
		}
		p, ok := g.local(old)
		if cfg := g.settings(); !ok && cfg != nil {
			if m := cfg["branch."+old+".merge"]; len(m) > 0 {
				p, ok = g.local(m[len(m)-1])
			}
		}
		if ok && dst != p && len(o.pos) > 0 {
			return "git", fmt.Sprintf("branch %s copied or renamed to %s keeps upstream %s", old, dst, p)
		}
		return "", ""
	}
	// delete and list modes create nothing; -v, --format and --sort do not
	// stop a creation
	if strings.ContainsAny(o.short, "dDlar") || len(o.pos) == 0 || len(o.pos) > 2 || long("--delete", "--list", "--all", "--remotes",
		"--contains", "--no-contains", "--merged", "--no-merged", "--points-at", "--show-current", "--edit-description", "--unset-upstream") {
		return "", ""
	}
	o.creates, o.name = true, o.pos[0]
	return g.create(o, at(o.pos, 1))
}

// config: branch.X.merge P (X is not P), remote.R.push reaching P,
// remote.R.mirror true, push.default matching.
func (g gitRefs) config(pos []string) (string, string) {
	for k := 0; k+1 < len(pos); k++ {
		key, val := strings.ToLower(pos[k]), pos[k+1]
		merge := strings.HasPrefix(key, "branch.") && strings.HasSuffix(key, ".merge") && len(key) > len("branch..merge")
		push := strings.HasPrefix(key, "remote.") && strings.HasSuffix(key, ".push")
		mirror := strings.HasPrefix(key, "remote.") && strings.HasSuffix(key, ".mirror")
		if !merge && !push && !mirror && key != "push.default" {
			continue
		}
		if strings.ContainsAny(val, "$`{") {
			return "unresolved", pos[k] + " " + val
		}
		switch {
		case merge:
			if p, ok := g.local(val); ok && pos[k][len("branch."):len(pos[k])-len(".merge")] != p {
				return "git", fmt.Sprintf("%s %s", pos[k], p)
			}
		case push:
			if cat, why := g.refspec(val, "HEAD"); cat != "" {
				return cat, pos[k] + " " + why
			}
		case mirror && gitTrue(val), key == "push.default" && strings.EqualFold(val, "matching"):
			return "git", pos[k] + " " + val + " pushes every branch"
		}
	}
	return "", ""
}

func gitTrue(v string) bool {
	return slices.Contains([]string{"true", "yes", "on", "1"}, strings.ToLower(v))
}

// refspec: cat and why when spec, pushed from branch head, reaches a
// protected ref. head is resolved only when spec names HEAD.
func (g gitRefs) refspec(spec, head string) (string, string) {
	if strings.ContainsAny(spec, "$`{") {
		return "unresolved", "refspec " + spec
	}
	spec = strings.TrimPrefix(spec, "+")
	if spec == ":" {
		return "git", "push of matching branches"
	}
	if strings.HasPrefix(spec, "^") {
		return "", ""
	}
	src, dst, colon := strings.Cut(spec, ":")
	if !colon || dst == "" {
		dst = src
	}
	if strings.ContainsAny(dst, "*?[") {
		return "git", "push to pattern " + dst
	}
	if dst == "HEAD" || dst == "@" {
		if head == "HEAD" {
			b, ok := g.current()
			if !ok {
				return "git", "push of HEAD, branch unknown"
			}
			head = b
		}
		dst = head
	}
	if p, ok := g.local(dst); ok {
		return "git", "push to protected " + p
	}
	return "", ""
}

func (g gitRefs) push(flags []string) (string, string) {
	var pos []string
	repo := ""
	valued := []string{"--push-option", "--receive-pack", "--exec", "--recurse-submodules"}
	for k := 0; k < len(flags); k++ {
		f := flags[k]
		opt, val, eq := strings.Cut(f, "=")
		switch {
		case f == "--":
			pos = append(pos, flags[k+1:]...)
			k = len(flags)
		case !strings.HasPrefix(f, "-") || f == "-":
			pos = append(pos, f)
		case abbrev(opt, "--all", 3) || abbrev(opt, "--mirror", 3) || abbrev(opt, "--branches", 3):
			return "git", "push of every branch"
		case abbrev(opt, "--repo", 5):
			repo = val
			if !eq && k+1 < len(flags) {
				k++
				repo = flags[k]
			}
		case strings.HasPrefix(f, "--"):
			if !eq && slices.ContainsFunc(valued, func(l string) bool { return abbrev(opt, l, 4) }) {
				k++
			}
		case strings.HasSuffix(f, "o"): // -o VALUE, -uo VALUE
			if i := strings.IndexByte(f, 'o'); i == len(f)-1 {
				k++
			}
		}
	}
	// every positional is read as a refspec, the repository's included:
	// a value read as one can only add a finding
	for _, spec := range pos {
		if cat, why := g.refspec(spec, "HEAD"); cat != "" {
			return cat, why
		}
	}
	if len(pos) > 0 { // the positional repository wins over --repo
		repo, pos = pos[0], pos[1:]
	}
	if len(pos) > 0 {
		return "", ""
	}
	return g.plainPush(repo)
}

// plainPush: a push without refspecs goes where the repository's config
// sends the current branch: remote.R.mirror (every branch), remote.R.push,
// else push.default (simple and current: its own name; upstream:
// branch.B.merge; matching: every branch).
func (g gitRefs) plainPush(repo string) (string, string) {
	b, ok := g.current()
	cfg := g.settings()
	if !ok || cfg == nil {
		return "git", "plain push, repository or branch unknown"
	}
	last := func(k string) string {
		if v := cfg[k]; len(v) > 0 {
			return v[len(v)-1]
		}
		return ""
	}
	if repo == "" {
		repo = cmp.Or(last("branch."+b+".pushremote"), last("remote.pushdefault"), last("branch."+b+".remote"), "origin")
	}
	if gitTrue(last("remote." + repo + ".mirror")) {
		return "git", "plain push to mirror remote " + repo
	}
	if specs := cfg["remote."+repo+".push"]; len(specs) > 0 {
		for _, spec := range specs {
			if cat, why := g.refspec(spec, b); cat != "" {
				return cat, "plain " + why
			}
		}
		return "", ""
	}
	dst := b
	switch strings.ToLower(last("push.default")) {
	case "matching":
		return "git", "plain push of matching branches"
	case "upstream", "tracking":
		dst = last("branch." + b + ".merge")
	case "nothing":
		return "", ""
	}
	if p, ok := g.local(dst); ok {
		return "git", "plain push to protected " + p
	}
	return "", ""
}
