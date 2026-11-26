// Package state is the per-session scratch store under
// ~/.claude/state/policy/<session_id>/ plus the shared decisions.jsonl.
// Every operation fails open: a hook must never block or crash on state.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	LockTimeout = 100 * time.Millisecond
	MaxAge      = 24 * time.Hour
	// Invalid replaces a session/agent id that is unsafe as a path element.
	Invalid = "_invalid"
	// ProbeDir is the probe capture dir inside Root; never pruned as a session.
	ProbeDir = "probe"
	// MaxDecisionsBytes is the decisions.jsonl size at which Prune rotates it
	// to decisions.jsonl.1 (one old generation kept).
	MaxDecisionsBytes = 10 << 20
)

var errNoRoot = errors.New("state: no usable HOME")

// Root is ~/.claude/state/policy; HOME must be absolute.
func Root() (string, error) {
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(h) {
		return "", fmt.Errorf("HOME %q is not absolute", h)
	}
	return filepath.Join(h, ".claude", "state", "policy"), nil
}

// SafeName returns s when it is usable as a single path element, else
// fallback. s comes from hook stdin: this is a trust boundary.
func SafeName(s, fallback string) string {
	if s == "" || len(s) > 128 || s[0] == '.' || strings.ContainsAny(s, "/\\\x00") || strings.Contains(s, "..") {
		return fallback
	}
	return s
}

// Store is one session's state dir. Agent is the per-agent key ("main"
// outside subagents) for rules that keep per-agent files: name them
// st.Agent+".<what>".
type Store struct {
	Root    string
	Session string
	Dir     string
	Agent   string
}

// New never fails; with an empty root every operation returns an error.
func New(root, sessionID, agentID string) *Store {
	s := &Store{Root: root, Session: SafeName(sessionID, Invalid), Agent: "main"}
	if s.Session == ProbeDir || s.Session == "decisions.jsonl" || s.Session == "decisions.jsonl.1" || isMetricsName(s.Session) {
		s.Session = Invalid // names Root already uses
	}
	if agentID != "" {
		s.Agent = SafeName(agentID, Invalid)
		if s.Agent == "main" {
			s.Agent = Invalid // must not share the main agent's keys
		}
	}
	if root != "" {
		s.Dir = filepath.Join(root, s.Session)
	}
	return s
}

// isMetricsName matches metrics.jsonl and its rotated metrics.jsonl.<N> names.
func isMetricsName(n string) bool {
	if n == "metrics.jsonl" {
		return true
	}
	g, ok := strings.CutPrefix(n, "metrics.jsonl.")
	if !ok || g == "" {
		return false
	}
	return strings.Trim(g, "0123456789") == ""
}

func (s *Store) path(name string) (string, error) {
	if s.Dir == "" {
		return "", errNoRoot
	}
	if SafeName(name, "") == "" {
		return "", fmt.Errorf("state: unsafe name %q", name)
	}
	return filepath.Join(s.Dir, name), nil
}

// Read returns the file's bytes; a missing file is (nil, nil).
func (s *Store) Read(name string) ([]byte, error) {
	p, err := s.path(name)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

// Write replaces the file atomically (tmp file + rename in the same dir).
// ponytail: no fsync; state is advisory and a crash only loses a counter.
func (s *Store) Write(name string, data []byte) error {
	p, err := s.path(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(s.Dir, "."+name+".tmp-*") // 0600
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	cerr := f.Close()
	if err := errors.Join(werr, cerr); err != nil {
		os.Remove(f.Name())
		return err
	}
	if err := os.Rename(f.Name(), p); err != nil {
		os.Remove(f.Name())
		return err
	}
	return nil
}

// Update runs read-modify-write under the name's lock. fn gets nil for a
// missing file; returning nil skips the write. When the lock is not free
// within LockTimeout it proceeds unlocked (fail open: a lost update beats a
// stalled hook).
func (s *Store) Update(name string, fn func(old []byte) []byte) error {
	if _, err := s.path(name); err != nil {
		return err
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	defer s.lock(name)()
	old, err := s.Read(name)
	if err != nil {
		return err
	}
	if b := fn(old); b != nil {
		return s.Write(name, b)
	}
	return nil
}

// lock flocks <name>.lock (a separate file: rename swaps the data inode),
// polling until LockTimeout. It always returns a callable unlock.
func (s *Store) lock(name string) func() {
	noop := func() {}
	f, err := os.OpenFile(filepath.Join(s.Dir, name+".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return noop
	}
	fd := int(f.Fd())
	deadline := time.Now().Add(LockTimeout)
	for {
		err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { syscall.Flock(fd, syscall.LOCK_UN); f.Close() }
		}
		if (err != syscall.EWOULDBLOCK && err != syscall.EINTR) || time.Now().After(deadline) {
			f.Close()
			return noop
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// AppendDecision appends v as one JSON line to Root/decisions.jsonl with a
// single O_APPEND write, so concurrent hooks do not interleave lines.
func (s *Store) AppendDecision(v any) error { return s.appendLine("decisions.jsonl", v) }

// AppendMetric appends v as one JSON line to Root/metrics.jsonl, same way.
func (s *Store) AppendMetric(v any) error { return s.appendLine("metrics.jsonl", v) }

func (s *Store) appendLine(name string, v any) error {
	if s.Root == "" {
		return errNoRoot
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.Root, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(s.Root, name), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(append(b, '\n'))
	return errors.Join(werr, f.Close())
}

// Prune removes session dirs untouched for MaxAge, only on
// SessionStart(startup), never the current session, the probe dir, or
// anything that is not a real directory, and rotates an oversized
// decisions.jsonl. Errors are ignored.
func (s *Store) Prune(event, source string) {
	if event != "SessionStart" || source != "startup" || s.Root == "" {
		return
	}
	log := filepath.Join(s.Root, "decisions.jsonl")
	if fi, err := os.Lstat(log); err == nil && fi.Mode().IsRegular() && fi.Size() > MaxDecisionsBytes {
		os.Rename(log, log+".1") // a concurrent O_APPEND writer finishing into .1 is fine
	}
	ents, err := os.ReadDir(s.Root)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-MaxAge)
	for _, e := range ents {
		if !e.IsDir() || e.Name() == s.Session || e.Name() == ProbeDir {
			continue
		}
		if fi, err := e.Info(); err == nil && fi.ModTime().Before(cutoff) {
			os.RemoveAll(filepath.Join(s.Root, e.Name()))
		}
	}
}

// RotateMetrics, only on SessionStart(startup), shifts an oversized regular
// metrics.jsonl into .1 (older generations to .N, beyond keep removed).
// Errors are ignored. ponytail: unlocked; two startups racing past the size
// check shift twice, ageing one generation early.
func (s *Store) RotateMetrics(event, source string, keep int, maxBytes int64) {
	if event != "SessionStart" || source != "startup" || s.Root == "" {
		return
	}
	p := filepath.Join(s.Root, "metrics.jsonl")
	if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() || fi.Size() <= maxBytes {
		return
	}
	gen := func(n int) string {
		if n == 0 {
			return p
		}
		return p + "." + strconv.Itoa(n)
	}
	olds, _ := filepath.Glob(p + ".*")
	for _, o := range olds {
		if n, err := strconv.Atoi(strings.TrimPrefix(o, p+".")); err == nil && n > keep {
			os.Remove(o)
		}
	}
	if keep < 1 {
		os.Remove(p)
		return
	}
	for n := keep; n >= 1; n-- {
		os.Rename(gen(n-1), gen(n)) // a missing source is skipped
	}
}
