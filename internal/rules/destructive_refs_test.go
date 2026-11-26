package rules

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// stubGit answers gitRun as a repository on branch (detached when "") with
// the `git config --list -z` entries cfg, and records the directories asked.
func stubGit(t *testing.T, branch string, cfg map[string]string) *[]string {
	t.Helper()
	var dirs []string
	old := gitRun
	t.Cleanup(func() { gitRun = old })
	gitRun = func(_ context.Context, dir string, args ...string) (string, error) {
		dirs = append(dirs, dir)
		switch args[0] {
		case "symbolic-ref":
			if branch == "" {
				return "", errors.New("detached")
			}
			return branch + "\n", nil
		case "config":
			var b strings.Builder
			for k, v := range cfg {
				b.WriteString(k + "\n" + v + "\x00")
			}
			return b.String(), nil
		}
		return "", errors.New("unexpected git " + strings.Join(args, " "))
	}
	return &dirs
}

func TestDestructiveProtectedPush(t *testing.T) {
	stubGit(t, "feat", nil)
	dCheck(t, suiteCfg(), "/work/u/repo", map[string]string{
		`git push origin main`:                                   "git",
		`git push origin HEAD:production`:                        "git",
		`git push origin HEAD:refs/heads/staging`:                "git",
		`git push origin feat:master`:                            "git",
		`git push -u origin feat:production`:                     "git",
		`git push origin :production`:                            "git",
		`git push --delete origin staging`:                       "git",
		`git push -d origin staging`:                             "git",
		`git push origin refs/heads/main`:                        "git",
		`git push origin feat main`:                              "git",
		`git push --all origin`:                                  "git",
		`git push --mirror`:                                      "git",
		`git push --branches origin`:                             "git",
		`git push --al origin`:                                   "git",
		`git push origin :`:                                      "git",
		`git push --repo=origin main`:                            "git",
		`git push --repo origin main`:                            "git",
		`git push origin -- main`:                                "git",
		`git -C /x push origin main`:                             "git",
		`sh -c 'git push origin main'`:                           "git",
		`git push origin feat:main && echo ok`:                   "git",
		`git push https://example.invalid/r.git HEAD:production`: "git",
		// not protected
		`git push origin feat`:                   "",
		`git push -u origin feat`:                "",
		`git push origin HEAD`:                   "",
		`git push origin HEAD:feat`:              "",
		`git push origin production-fix`:         "",
		`git push origin HEAD:origin/production`: "", // a branch named origin/production
		`git push --repo origin feat`:            "",
		`git push -o ci.skip origin feat`:        "",
		`git push --tags origin`:                 "",
		`git push origin v1.0`:                   "",
		`git push origin ^refs/heads/main`:       "", // a negative refspec pushes nothing
		// a target the scan cannot read
		`git push origin $BR`:         "unresolved",
		`git push origin "HEAD:$B"`:   "unresolved",
		`git push origin {feat,main}`: "unresolved",
	})
}

func TestDestructiveProtectedPushOnMain(t *testing.T) {
	stubGit(t, "main", nil)
	dCheck(t, suiteCfg(), "/work/u/repo", map[string]string{
		`git push`:             "git",
		`git push -u`:          "git",
		`git push origin`:      "git",
		`git push origin HEAD`: "git",
		`git push origin @`:    "git",
		`git push origin feat`: "",
	})
}

func TestDestructivePlainPushResolution(t *testing.T) {
	for _, c := range []struct {
		name, branch string
		cfg          map[string]string
		cmd, want    string
	}{
		{"feature branch", "feat", nil, `git push`, ""},
		{"simple refuses a renamed upstream", "feat", map[string]string{"branch.feat.merge": "refs/heads/production"}, `git push`, ""},
		{"upstream mode follows merge", "feat", map[string]string{"branch.feat.merge": "refs/heads/production", "push.default": "upstream"}, `git push`, "git"},
		{"tracking is upstream", "feat", map[string]string{"branch.feat.merge": "refs/heads/staging", "push.default": "Tracking"}, `git push`, "git"},
		{"matching", "feat", map[string]string{"push.default": "matching"}, `git push`, "git"},
		{"remote push refspec", "feat", map[string]string{"remote.origin.push": "HEAD:production"}, `git push`, "git"},
		{"remote push refspec, named remote", "feat", map[string]string{"remote.origin.push": "refs/heads/feat:refs/heads/main"}, `git push origin`, "git"},
		{"other remote's refspec", "feat", map[string]string{"remote.up.push": "HEAD:main"}, `git push origin`, ""},
		{"pushRemote's refspec", "feat", map[string]string{"branch.feat.pushremote": "up", "remote.up.push": "HEAD:main"}, `git push`, "git"},
		{"pushDefault's refspec", "feat", map[string]string{"remote.pushdefault": "up", "remote.up.push": "HEAD:main"}, `git push`, "git"},
		{"branch remote's refspec", "feat", map[string]string{"branch.feat.remote": "up", "remote.up.push": "HEAD:main"}, `git push`, "git"},
		{"matching refspec", "feat", map[string]string{"remote.origin.push": ":"}, `git push`, "git"},
		{"detached HEAD", "", nil, `git push`, "git"},
		{"other git dir", "feat", nil, `git --git-dir=/x/.git push`, "git"},
		{"config on the command line", "feat", nil, `git -c push.default=upstream push`, "git"},
		{"unrelated config on the command line", "feat", nil, `git -c color.ui=false push`, ""},
		{"GIT_DIR", "feat", nil, `GIT_DIR=/srv/main/.git git push`, "git"},
		{"exported GIT_CONFIG", "feat", nil, `export GIT_CONFIG_COUNT=1; git push`, "git"},
		{"mirror remote", "feat", map[string]string{"remote.origin.mirror": "true"}, `git push`, "git"},
		{"other mirror remote", "feat", map[string]string{"remote.up.mirror": "true"}, `git push`, ""},
		{"--repo alone", "main", nil, `git push --repo=origin`, "git"},
		{"--repo VALUE alone", "main", nil, `git push --repo origin`, "git"},
		{"-uo value", "main", nil, `git push -uo ci.skip origin`, "git"},
		{"abbreviated push option", "main", nil, `git push --push-opt x origin`, "git"},
		{"recurse-submodules value", "main", nil, `git push --recurse-submodules check origin`, "git"},
		{"-o value on a feature branch", "feat", nil, `git push -o ci.skip origin`, ""},
		{"unknown directory", "feat", nil, `cd "$D" && git push`, "git"},
	} {
		t.Run(c.name, func(t *testing.T) {
			stubGit(t, c.branch, c.cfg)
			dCheck(t, suiteCfg(), "/work/u/repo", map[string]string{c.cmd: c.want})
		})
	}
}

func TestDestructivePlainPushDirectory(t *testing.T) {
	dirs := stubGit(t, "feat", nil)
	for _, c := range []struct{ cmd, want string }{
		{`git push`, "/work/u/repo"},
		{`cd /srv/app && git push`, "/srv/app"},
		{`git -C sub push`, "/work/u/repo/sub"},
		{`git -C /srv/app push`, "/srv/app"},
	} {
		*dirs = nil
		dApply(suiteCfg(), c.cmd, "")
		if len(*dirs) == 0 || (*dirs)[0] != c.want {
			t.Errorf("%q: git ran in %v, want %s", c.cmd, *dirs, c.want)
		}
	}
}

func TestDestructiveProtectedUpstream(t *testing.T) {
	stubGit(t, "feat", nil)
	dCheck(t, suiteCfg(), "/work/u/repo", map[string]string{
		`git checkout -b PROJ-110-stg origin/staging`:                   "git",
		`git checkout -b x --track origin/production`:                   "git",
		`git checkout -b x -t origin/production`:                        "git",
		`git checkout -tb x origin/main`:                                "git",
		`git checkout -bx refs/remotes/origin/master`:                   "git",
		`git checkout -B x origin/main`:                                 "git",
		`git checkout --no-track --track -b x origin/main`:              "git",
		`git switch -c x origin/production`:                             "git",
		`git switch -C x origin/production`:                             "git",
		`git switch --create=x origin/production`:                       "git",
		`git switch --create x origin/production`:                       "git",
		`git switch --cr x origin/production`:                           "git",
		`git switch --force-create x origin/production`:                 "git",
		`git branch x origin/staging`:                                   "git",
		`git branch --track x origin/staging`:                           "git",
		`git branch -f x origin/staging`:                                "git",
		`git branch -u origin/production`:                               "git",
		`git branch -u origin/production other`:                         "git",
		`git branch --set-upstream-to=origin/main x`:                    "git",
		`git branch --set-upstream-to origin/main`:                      "git",
		`git branch --set-u=origin/main`:                                "git",
		`git branch -uorigin/main`:                                      "git",
		`git branch -qu origin/main`:                                    "git",
		`git worktree add -b x ../wt origin/production`:                 "git",
		`git worktree add -B x ../wt origin/production`:                 "git",
		`git config branch.feat.merge refs/heads/production`:            "git",
		`git config branch.feat.merge production`:                       "git",
		`git config set branch.feat.merge production`:                   "git",
		`git config --local Branch.feat.Merge production`:               "git",
		`git config remote.origin.push HEAD:production`:                 "git",
		`git config --add remote.origin.push refs/heads/*:refs/heads/*`: "git",
		`git checkout -b x --track=inherit main`:                        "git",
		`git checkout -b x --track=inherit refs/heads/main`:             "git",
		`git -C /srv/app checkout -b x origin/main`:                     "git",
		// no upstream, or the same name
		`git checkout -b x origin/production --no-track`:     "",
		`git checkout --no-track -b x origin/production`:     "",
		`git switch -c x --no-track origin/main`:             "",
		`git branch --no-track x origin/main`:                "",
		`git worktree add --no-track -b x ../wt origin/main`: "",
		`git checkout -b production origin/production`:       "",
		`git checkout --track origin/production`:             "",
		`git checkout -t origin/production`:                  "",
		`git switch production`:                              "",
		`git checkout -b x main`:                             "",
		`git checkout -b x --track main`:                     "",
		`git checkout -b x origin/feature`:                   "",
		`git checkout -b x`:                                  "",
		`git checkout origin/main`:                           "",
		`git checkout -b x origin/main~1`:                    "",
		`git branch -u origin/feat`:                          "",
		`git branch -u origin/main main`:                     "",
		`git branch -u main x`:                               "", // a local upstream pushes nowhere
		`git branch -m x origin/main`:                        "",
		`git branch -c x origin/main`:                        "",
		`git branch -d x origin/main`:                        "",
		`git branch --move x origin/main`:                    "",
		`git branch x main`:                                  "",
		`git branch x`:                                       "",
		`git worktree add ../wt origin/production`:           "",
		`git worktree add -b x ../wt main`:                   "",
		`git worktree list`:                                  "",
		`git config branch.main.merge refs/heads/main`:       "",
		`git config branch.feat.merge refs/heads/feat`:       "",
		`git config --unset branch.feat.merge`:               "",
		`git config branch.feat.merge`:                       "",
		`git config remote.origin.push HEAD:feat`:            "",
		// a name the scan cannot read
		`git checkout -b x $START`:        "unresolved",
		`git branch -u "$UP"`:             "unresolved",
		`git config branch.feat.merge $M`: "unresolved",
	})
}

func TestDestructiveProtectedUpstreamCurrentBranch(t *testing.T) {
	stubGit(t, "main", nil)
	dCheck(t, suiteCfg(), "/work/u/repo", map[string]string{
		`git branch -u origin/main`:              "",
		`git branch -u origin/staging`:           "git",
		`git checkout -b x --track=inherit`:      "git",
		`git checkout -b x --track=inherit HEAD`: "git",
	})
	stubGit(t, "", nil)
	dCheck(t, suiteCfg(), "/work/u/repo", map[string]string{
		`git branch -u origin/main`: "git", // detached: no branch is called main
	})
}

func TestDestructiveProtectedRefsReason(t *testing.T) {
	stubGit(t, "feat", nil)
	for cmd, want := range map[string]string{
		`git checkout -b PROJ-110-stg origin/staging`: "destructive: git ask (main): upstream origin/staging for PROJ-110-stg, add --no-track: git checkout -b PROJ-110-stg origin/staging",
		`git push origin HEAD:production`:             "destructive: git ask (main): push to protected production: git push origin HEAD:production",
	} {
		if d := dApply(suiteCfg(), cmd, ""); d == nil || d.Reason != want {
			t.Errorf("%q: got %+v\nwant %s", cmd, d, want)
		}
	}
}

func TestDestructiveProtectedRefsConfig(t *testing.T) {
	stubGit(t, "main", nil)
	cfg := suiteCfg()
	cfg.Rules.Destructive.Git.ProtectedRefs = nil
	dCheck(t, cfg, "/work/u/repo", map[string]string{`git push`: "", `git checkout -b x origin/main`: "", `git push origin main`: ""})
	cfg = suiteCfg()
	cfg.Rules.Destructive.Git.ProtectedRefs = []string{"release/1.x"}
	dCheck(t, cfg, "/work/u/repo", map[string]string{
		`git push origin HEAD:release/1.x`:     "git",
		`git checkout -b x origin/release/1.x`: "git",
		`git push origin main`:                 "",
	})
	// allow_actions never exempts a protected target
	cfg = suiteCfg()
	cfg.Rules.Destructive.Git.AllowActions = []string{"push", "checkout", "branch"}
	if d := dApply(cfg, `git push origin main`, ""); dVerdict(d) != "git" {
		t.Errorf("allow_actions push: got %+v", d)
	}
	if d := dApply(cfg, `git checkout -b x origin/main`, ""); dVerdict(d) != "git" {
		t.Errorf("allow_actions checkout: got %+v", d)
	}
}

// The resolution against a real repository and git binary.
func TestDestructiveProtectedReview(t *testing.T) {
	stubGit(t, "feat", nil)
	dCheck(t, suiteCfg(), "/work/u/repo", map[string]string{
		// remote spellings
		`git checkout -b x remotes/origin/main`: "git",
		`git checkout -b x origin/HEAD`:         "git",
		`git checkout -b x refs/heads/main`:     "",
		`git checkout -b x heads/main`:          "",
		// destinations git completes with refs/
		`git push origin HEAD:heads/main`:     "git",
		`git push origin heads/main`:          "git",
		`git push origin HEAD:refs/tags/main`: "",
		// short abbreviations
		`git push --m origin`: "git",
		`git push --b origin`: "git",
		// option values that would shift the positionals
		`git switch --conflict diff3 -c x origin/main`:   "git",
		`git checkout --conflict diff3 -b x origin/main`: "git",
		`git branch --format short x origin/main`:        "git",
		`git branch --sort refname x origin/main`:        "git",
		`git branch -v x origin/main`:                    "git",
		`git branch --verbose x origin/main`:             "git",
		`git branch -r x origin/main`:                    "",
		`git branch --list x origin/main`:                "",
		`git branch -a x origin/main`:                    "",
		// words after --
		`git branch -- x origin/main`:                     "git",
		`git config -- branch.feat.merge refs/heads/main`: "git",
		`git worktree add -b x -- ../wt origin/main`:      "git",
		// xargs appends what the scan cannot see
		`echo main | xargs git push origin`:          "unresolved",
		`echo origin/main | xargs git checkout -b x`: "unresolved",
		`xargs git log < x`:                          "",
		// configuring a later push
		`git config remote.origin.mirror true`:                          "git",
		`git config remote.origin.mirror false`:                         "",
		`git config push.default matching`:                              "git",
		`git config push.default simple`:                                "",
		`git remote add --mirror=push bk https://example.invalid/r.git`: "git",
		`git remote add up https://example.invalid/r.git`:               "",
	})
}

// git runs once per directory and in one directory per scan: a long
// command cannot spend the rule's deadline on git.
func TestDestructiveProtectedReview2(t *testing.T) {
	stubGit(t, "main", map[string]string{"branch.PROJ-110-stg.merge": "refs/heads/production", "remote.up.mirror": "true"})
	dCheck(t, suiteCfg(), "/work/u/repo", map[string]string{
		// global options taking a value
		`git --attr-source HEAD push origin main`:          "git",
		`git --attr-source HEAD checkout -b x origin/main`: "git",
		`git --attr-source HEAD reset --hard`:              "git",
		`git --super-prefix x/ push origin main`:           "git",
		// the positional repository wins over --repo
		`git push --repo=nonexist origin`: "git",
		`git push --repo=x up`:            "git",
		// copy and rename keep the upstream
		`git branch -c main x`:         "git",
		`git branch -C main x`:         "git",
		`git branch -m main x`:         "git",
		`git branch -M main x`:         "git",
		`git branch --copy main x`:     "git",
		`git branch -m x`:              "git", // renames the current branch, main
		`git branch -c PROJ-110-stg x`: "git", // tracks production
		`git branch -m main main`:      "",
		`git branch -m feat x`:         "",
		`git branch -m $OLD x`:         "unresolved",
		// inherit with one positional
		`git branch --track=inherit x`: "git",
		`git branch --track x`:         "",
		`git branch x`:                 "",
	})
}

func TestDestructivePlainPushGitCalls(t *testing.T) {
	dirs := stubGit(t, "feat", nil)
	cmd := strings.Repeat("git push; ", 90) + "git push origin " + strings.Repeat("HEAD ", 150) + "feat"
	if d := dApply(suiteCfg(), cmd, ""); d != nil {
		t.Errorf("got %+v", d)
	}
	if len(*dirs) != 2 {
		t.Errorf("git ran %d times, want 2 (branch, config)", len(*dirs))
	}
	*dirs = nil
	if d := dApply(suiteCfg(), `git push; cd /srv/other && git push`, ""); dVerdict(d) != "git" {
		t.Errorf("a second directory is not read: got %+v", d)
	}
	if len(*dirs) != 2 {
		t.Errorf("git ran %d times, want 2", len(*dirs))
	}
	if d := dApply(suiteCfg(), strings.Repeat("git push; ", 90)+"rm -rf /", ""); d == nil || !d.Hard {
		t.Errorf("hard_deny must survive: got %+v", d)
	}
}

// A config that includes a FIFO hangs git; the verdict must still arrive
// inside the rule's deadline.
func TestDestructivePlainPushHangingGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	repo := t.TempDir()
	if out, err := exec.Command("git", "-C", repo, "init", "-q", "-b", "feat").CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	fifo := filepath.Join(repo, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip(err)
	}
	if out, err := exec.Command("git", "-C", repo, "config", "include.path", fifo).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	d := destructive{}.Apply(ctx, dIn(`git push; git push origin main; rm -rf /`, "", repo), suiteCfg(), nil)
	if d == nil || !d.Hard {
		t.Errorf("after %v: got %+v", time.Since(start), d)
	}
}

func TestDestructivePlainPushRealGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	repo := filepath.Join(t.TempDir(), "r")
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	git("init", "-q", "-b", "PROJ-110-stg")
	git("remote", "add", "origin", "https://example.invalid/r.git")
	git("config", "branch.PROJ-110-stg.remote", "origin")
	git("config", "branch.PROJ-110-stg.merge", "refs/heads/production")
	check := func(want string) {
		t.Helper()
		d := destructive{}.Apply(context.Background(), dIn(`git push`, "", repo), suiteCfg(), nil)
		if got := dVerdict(d); got != want {
			t.Errorf("want %q, got %+v", want, d)
		}
	}
	check("") // push.default simple refuses the renamed upstream
	git("config", "push.default", "upstream")
	check("git")
	git("config", "push.default", "simple")
	git("checkout", "-q", "-b", "main")
	check("git")
}
