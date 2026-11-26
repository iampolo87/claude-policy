package rules

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/iampolo87/claude-policy/internal/config"
	"github.com/iampolo87/claude-policy/internal/hook"
	"github.com/iampolo87/claude-policy/internal/state"
)

// lint checks an edited PHP or JavaScript file: syntax errors block,
// phpstan/phpcs (opt-in, run from the project's vendor/bin) only inform.
type lint struct{}

func init() { Registry = append(Registry, lint{}) }

func (lint) Name() string           { return "lint" }
func (lint) Events() []string       { return []string{"PostToolUse"} }
func (lint) Tools() []string        { return []string{"Edit", "Write", "MultiEdit"} }
func (lint) Timeout() time.Duration { return 45 * time.Second }

// maxLintOut keeps the reason under CC's 10k hook-value spill.
const maxLintOut = 4000

// lintWaitDelay stops an orphaned grandchild holding the pipe from outliving the deadline.
const lintWaitDelay = 2 * time.Second

func (lint) Apply(ctx context.Context, in *hook.Input, cfg *config.Config, _ *state.Store) *hook.Decision {
	var ti struct {
		FilePath string `json:"file_path"`
	}
	if json.Unmarshal(in.ToolInput, &ti) != nil || ti.FilePath == "" {
		return nil
	}
	file := ti.FilePath
	if !filepath.IsAbs(file) && in.Cwd != "" {
		file = filepath.Join(in.Cwd, file)
	}
	file, err := filepath.Abs(file)
	if err != nil {
		return nil
	}
	if fi, err := os.Stat(file); err != nil || !fi.Mode().IsRegular() {
		return nil
	}
	c := cfg.Rules.Lint
	switch strings.ToLower(filepath.Ext(file)) {
	case ".php", ".phtml":
		if !c.PHP {
			return nil
		}
		if out, ok := runLint(ctx, "php", "-l", file); !ok {
			return &hook.Decision{Block: true, Reason: "BLOCK: php -l failed: " + out}
		}
		return staticAnalysis(ctx, file, c)
	case ".js", ".mjs", ".cjs":
		if !c.Node {
			return nil
		}
		if out, ok := runLint(ctx, "node", "--check", file); !ok {
			return &hook.Decision{Block: true, Reason: "BLOCK: node --check failed: " + out}
		}
	}
	return nil
}

// runLint returns bounded combined output and ok=false only when the tool ran
// and exited non-zero. A missing binary or a cancelled ctx is ok (fail open).
func runLint(ctx context.Context, name string, args ...string) (string, bool) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = lintWaitDelay
	b, err := cmd.CombinedOutput()
	out := strings.TrimSpace(string(b))
	if len(out) > maxLintOut {
		out = out[:maxLintOut] + "\n...(truncated)"
	}
	var ee *exec.ExitError
	return out, !errors.As(err, &ee) || ctx.Err() != nil
}

func findProjectRoot(ctx context.Context, dir string) string {
	for d := dir; d != "/" && d != "."; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "composer.json")); err == nil {
			return d
		}
	}
	if out, err := exec.CommandContext(ctx, "git", "-C", dir, "rev-parse", "--show-toplevel").Output(); err == nil {
		return strings.TrimSpace(string(out))
	}
	return dir
}

func isExec(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func staticAnalysis(ctx context.Context, file string, c config.Lint) *hook.Decision {
	root := findProjectRoot(ctx, filepath.Dir(file))
	var parts []string
	stan := filepath.Join(root, "vendor/bin/phpstan")
	if c.PHPStan && isExec(stan) && (exists(filepath.Join(root, "phpstan.neon")) || exists(filepath.Join(root, "phpstan.neon.dist"))) {
		if out, ok := runLint(ctx, stan, "analyse", file, "--no-progress"); !ok {
			parts = append(parts, "[php-lint] phpstan warnings:\n"+out)
		}
	}
	if cs := filepath.Join(root, "vendor/bin/phpcs"); c.PHPCS && isExec(cs) {
		args := []string{file}
		if c.PHPCSStandard != "" {
			args = append(args, "--standard="+c.PHPCSStandard)
		}
		if out, ok := runLint(ctx, cs, args...); !ok {
			parts = append(parts, "[php-lint] phpcs warnings:\n"+out)
		}
	}
	if len(parts) == 0 {
		return nil
	}
	return &hook.Decision{AdditionalContext: strings.Join(parts, "\n")}
}
