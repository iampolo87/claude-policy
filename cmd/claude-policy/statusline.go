package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/iampolo87/claude-policy/internal/config"
	"github.com/iampolo87/claude-policy/internal/state"
)

const (
	maxStatuslineStdin = 1 << 20
	rendererTimeout    = time.Second
	herdrDeadline      = 15 * time.Millisecond
	herdrStateFile     = "statusline.herdr"
)

// runStatusline is not a hook: Claude Code runs it on every redraw. It runs
// the renderer (args[0]) and, with [integrations.herdr] report on inside a
// herdr pane, concurrently reports metadata tokens when they changed.
// Always exits 0.
func runStatusline(args []string, stdin io.Reader, stdout io.Writer) int {
	raw, _ := io.ReadAll(io.LimitReader(stdin, maxStatuslineStdin))
	herdr := herdrReport()
	var wg sync.WaitGroup
	if herdr {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { recover() }()
			reportHerdr(raw)
		}()
	}
	if len(args) > 0 {
		func() {
			defer func() { recover() }()
			runRenderer(args[0], raw, stdout, herdr)
		}()
	}
	wg.Wait()
	return 0
}

// herdrReport: inside a herdr pane and the integration is on. The config is
// only read inside a pane, so a redraw elsewhere costs nothing.
func herdrReport() (on bool) {
	defer func() { recover() }()
	if os.Getenv("HERDR_PANE_ID") == "" {
		return false
	}
	p, err := config.Path()
	if err != nil {
		return false
	}
	c, err := config.Load(p)
	return err == nil && c.Integrations.Herdr.Report
}

func runRenderer(path string, raw []byte, stdout io.Writer, herdr bool) {
	ctx, cancel := context.WithTimeout(context.Background(), rendererTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path)
	cmd.Stdin = bytes.NewReader(raw)
	cmd.Stdout = stdout
	cmd.WaitDelay = 100 * time.Millisecond
	for _, kv := range os.Environ() {
		if !herdr || !strings.HasPrefix(kv, "HERDR_ENV=") { // reporting: claude-policy is the sole herdr reporter
			cmd.Env = append(cmd.Env, kv)
		}
	}
	_ = cmd.Run()
}

func herdrBin() string {
	if p := os.Getenv("HERDR_BIN_PATH"); p != "" {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return p
		}
	}
	p, _ := exec.LookPath("herdr")
	return p
}

func reportHerdr(raw []byte) {
	pane := os.Getenv("HERDR_PANE_ID")
	if pane == "" {
		return
	}
	var in struct {
		SessionID string `json:"session_id"`
		Model     struct {
			ID          string `json:"id"`
			DisplayName string `json:"display_name"`
		} `json:"model"`
		Effort struct {
			Level string `json:"level"`
		} `json:"effort"`
		Cost struct {
			Total *float64 `json:"total_cost_usd"`
		} `json:"cost"`
		Ctx struct {
			Size float64  `json:"context_window_size"`
			Used *float64 `json:"used_percentage"`
		} `json:"context_window"`
	}
	if json.Unmarshal(raw, &in) != nil {
		return
	}
	model := in.Model.DisplayName
	if model == "" {
		model = in.Model.ID
	}
	if model != "" && in.Ctx.Size >= 1000000 {
		model += "[1m]"
	}
	if model == "" {
		return // not a real status frame, and --clear-token is global in herdr
	}
	var ctx, cost string
	if in.Ctx.Used != nil {
		ctx = fmt.Sprintf("%d%%", int(math.Round(*in.Ctx.Used)))
	}
	if in.Cost.Total != nil {
		cost = fmt.Sprintf("$%.2f", *in.Cost.Total)
	}
	tokens := [][2]string{{"model", model}, {"effort", in.Effort.Level}, {"context", ctx}, {"cost", cost}}

	bin := herdrBin()
	if bin == "" {
		return
	}
	var set strings.Builder
	set.WriteString("pane=" + pane + "\n")
	argv := []string{"pane", "report-metadata", pane, "--source", "claude-policy", "--agent", "claude"}
	for _, t := range tokens {
		if t[1] == "" {
			argv = append(argv, "--clear-token", t[0])
		} else {
			argv = append(argv, "--token", t[0]+"="+t[1])
		}
		set.WriteString(t[0] + "=" + t[1] + "\n")
	}
	root, _ := state.Root()
	st := state.New(root, in.SessionID, "")
	// Known gaps: a global --clear-token by another source is not re-sent until a value
	// changes; overlapping redraws may leave one stale display until the next change.
	if old, err := st.Read(herdrStateFile); err == nil && string(old) == set.String() {
		return
	}

	ctxd, cancel := context.WithTimeout(context.Background(), herdrDeadline)
	defer cancel()
	cmd := exec.CommandContext(ctxd, bin, argv...)
	cmd.WaitDelay = 2 * time.Millisecond
	if cmd.Run() != nil {
		return // retried on the next redraw
	}
	_ = st.Update(herdrStateFile, func([]byte) []byte { return []byte(set.String()) })
}
