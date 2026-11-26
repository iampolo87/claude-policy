package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/iampolo87/claude-policy/internal/config"
	"github.com/iampolo87/claude-policy/internal/state"
)

// Overridable from tests only.
var mineBackoff = 2 * time.Second

const (
	mineDeadline = 280 * time.Second // under the 300 s hook timeout
	mineAttempts = 3
)

// runMine mines the PreCompact transcript into its mempalace wing when
// [integrations.mempalace] mine is on; otherwise it only logs "skipped".
// Async hook: always exits 0, stdout stays empty.
func runMine(stdin io.Reader) (code int) {
	defer func() {
		if p := recover(); p != nil {
			code = 0
		}
	}()
	var env struct {
		SessionID      string `json:"session_id"`
		TranscriptPath string `json:"transcript_path"`
	}
	raw, _ := io.ReadAll(io.LimitReader(stdin, maxHookStdin))
	json.Unmarshal(raw, &env)

	cfg := config.Defaults()
	if p, err := config.Path(); err == nil {
		if c, err := config.Load(p); err == nil {
			cfg = c
		}
	}

	mp := cfg.Integrations.Mempalace
	wing := mp.Wing(env.TranscriptPath)
	attempts, result, tail := 0, "skipped", ""
	fi, _ := os.Stat(env.TranscriptPath)
	// ponytail: sessions started at projects_root itself (or outside it) have no project wing; skip.
	if wing != "" && fi != nil && fi.Mode().IsRegular() {
		ctx, cancel := context.WithTimeout(context.Background(), mineDeadline)
		defer cancel()
		for attempts < mineAttempts && ctx.Err() == nil {
			attempts++
			var eb bytes.Buffer
			cmd := exec.CommandContext(ctx, mp.Bin, "mine", env.TranscriptPath, "--mode", "convos", "--wing", wing, "--backend", "sqlite_exact", "--direct")
			cmd.Stderr = &eb
			err := cmd.Run()
			if err == nil {
				result, tail = "ok", ""
				break
			}
			result, tail = "error", strings.TrimSpace(eb.String())
			if tail == "" {
				tail = err.Error()
			}
			if len(tail) > 300 {
				tail = tail[len(tail)-300:]
			}
			if attempts == mineAttempts || !strings.Contains(eb.String(), "held by PID") {
				break
			}
			select {
			case <-time.After(mineBackoff * time.Duration(attempts)):
			case <-ctx.Done():
			}
		}
	}
	rec := map[string]any{
		"ts": time.Now().UTC().Format(time.RFC3339), "session_id": env.SessionID,
		"event": "PreCompact", "rule": "mine", "wing": wing, "attempts": attempts, "result": result,
	}
	if tail != "" {
		rec["stderr_tail"] = tail
	}
	root, _ := state.Root()
	state.New(root, env.SessionID, "").AppendDecision(rec) // best-effort
	return 0
}
