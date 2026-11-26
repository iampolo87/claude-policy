package state

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestSafeName(t *testing.T) {
	for in, want := range map[string]string{
		"abc-123_X":               "abc-123_X",
		"":                        "fb",
		"a/b":                     "fb",
		`a\b`:                     "fb",
		"..":                      "fb",
		"a..b":                    "fb",
		".hidden":                 "fb",
		"a\x00b":                  "fb",
		string(make([]byte, 200)): "fb",
	} {
		if got := SafeName(in, "fb"); got != want {
			t.Errorf("SafeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNewSanitizesKeys(t *testing.T) {
	root := t.TempDir()
	s := New(root, "../../etc", "")
	if s.Dir != filepath.Join(root, Invalid) || s.Agent != "main" {
		t.Fatalf("got dir=%q agent=%q", s.Dir, s.Agent)
	}
	s = New(root, "sess", "a/b")
	if s.Dir != filepath.Join(root, "sess") || s.Agent != Invalid {
		t.Fatalf("got dir=%q agent=%q", s.Dir, s.Agent)
	}
	for _, id := range []string{ProbeDir, "decisions.jsonl"} {
		if s := New(root, id, ""); s.Dir != filepath.Join(root, Invalid) {
			t.Fatalf("reserved session %q: got dir=%q", id, s.Dir)
		}
	}
	if s := New(root, "sess", "main"); s.Agent != Invalid {
		t.Fatalf("agent_id main must not alias the main agent, got %q", s.Agent)
	}
	if _, err := s.Read("../x"); err == nil {
		t.Fatal("unsafe file name must be rejected")
	}
	if err := New("", "s", "").Write("x", nil); err == nil {
		t.Fatal("store without root must refuse to write")
	}
}

func TestRootRequiresAbsoluteHome(t *testing.T) {
	h := t.TempDir()
	t.Setenv("HOME", h)
	if r, err := Root(); err != nil || r != filepath.Join(h, ".claude", "state", "policy") {
		t.Fatalf("Root() = %q, %v", r, err)
	}
	t.Setenv("HOME", "rel")
	if _, err := Root(); err == nil {
		t.Fatal("relative HOME must be rejected")
	}
}

func TestWriteReadAtomic(t *testing.T) {
	s := New(t.TempDir(), "sess", "")
	if b, err := s.Read("missing"); b != nil || err != nil {
		t.Fatalf("missing file: %q %v", b, err)
	}
	a, b := bytes.Repeat([]byte("a"), 1<<20), bytes.Repeat([]byte("b"), 1<<20)
	if err := s.Write("blob", a); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			got, err := s.Read("blob")
			if err != nil || !(bytes.Equal(got, a) || bytes.Equal(got, b)) {
				t.Errorf("torn read: len=%d err=%v", len(got), err)
				return
			}
		}
	}()
	for i := range 20 {
		if err := s.Write("blob", [][]byte{a, b}[i%2]); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()

	assertMode(t, s.Dir, 0o700|os.ModeDir)
	assertMode(t, filepath.Join(s.Dir, "blob"), 0o600)
	ents, _ := os.ReadDir(s.Dir)
	if len(ents) != 1 {
		t.Fatalf("tmp files left behind: %v", ents)
	}
}

func TestUpdateSerializes(t *testing.T) {
	s := New(t.TempDir(), "sess", "")
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.Update("n", func(old []byte) []byte {
				n, _ := strconv.Atoi(string(old))
				return []byte(strconv.Itoa(n + 1))
			})
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if got, _ := s.Read("n"); string(got) != "20" {
		t.Fatalf("lost updates: %s", got)
	}
}

func TestLockContentionFailsOpen(t *testing.T) {
	s := New(t.TempDir(), "sess", "")
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(s.Dir, "n.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err = s.Update("n", func([]byte) []byte { return []byte("x") })
	el := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if el < LockTimeout || el > LockTimeout+400*time.Millisecond {
		t.Fatalf("lock wait %v, want ~%v", el, LockTimeout)
	}
	if got, _ := s.Read("n"); string(got) != "x" {
		t.Fatal("update must proceed without the lock")
	}
}

func TestAppendDecision(t *testing.T) {
	root := t.TempDir()
	s := New(root, "sess", "")
	for i := range 3 {
		if err := s.AppendDecision(map[string]int{"i": i}); err != nil {
			t.Fatal(err)
		}
	}
	p := filepath.Join(root, "decisions.jsonl")
	assertMode(t, p, 0o600)
	f, _ := os.Open(p)
	defer f.Close()
	n := 0
	for sc := bufio.NewScanner(f); sc.Scan(); n++ {
		var v map[string]int
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil || v["i"] != n {
			t.Fatalf("line %d: %q %v", n, sc.Text(), err)
		}
	}
	if n != 3 {
		t.Fatalf("got %d lines", n)
	}
}

func TestPrune(t *testing.T) {
	root := t.TempDir()
	old := time.Now().Add(-25 * time.Hour)
	mk := func(name string, dir bool) string {
		p := filepath.Join(root, name)
		if dir {
			os.MkdirAll(p, 0o700)
		} else {
			os.WriteFile(p, nil, 0o600)
		}
		os.Chtimes(p, old, old)
		return p
	}
	stale := mk("stale", true)
	cur := mk("cur", true)
	probe := mk("probe", true)
	file := mk("decisions.jsonl", false)
	fresh := filepath.Join(root, "fresh")
	os.MkdirAll(fresh, 0o700)
	target := t.TempDir()
	os.Chtimes(target, old, old)
	link := filepath.Join(root, "link")
	os.Symlink(target, link)

	s := New(root, "cur", "")
	for _, src := range []string{"resume", "clear", "compact", ""} {
		s.Prune("SessionStart", src)
	}
	s.Prune("Stop", "startup")
	if _, err := os.Stat(stale); err != nil {
		t.Fatal("prune must only run on SessionStart(startup)")
	}
	s.Prune("SessionStart", "startup")
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("stale session dir must be removed")
	}
	for _, p := range []string{cur, probe, file, fresh, link, target} {
		if _, err := os.Lstat(p); err != nil {
			t.Fatalf("%s must survive: %v", p, err)
		}
	}
}

func assertMode(t *testing.T, p string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode() != want {
		t.Fatalf("%s mode %v, want %v", p, fi.Mode(), want)
	}
}

func TestPruneRotatesDecisions(t *testing.T) {
	root := t.TempDir()
	log := filepath.Join(root, "decisions.jsonl")
	s := New(root, "cur", "")

	os.WriteFile(log, []byte("small\n"), 0o600)
	s.Prune("SessionStart", "startup")
	if b, _ := os.ReadFile(log); string(b) != "small\n" {
		t.Fatal("a log under MaxDecisionsBytes must stay in place")
	}

	big := make([]byte, MaxDecisionsBytes+1)
	os.WriteFile(log, big, 0o600)
	os.WriteFile(log+".1", []byte("older generation"), 0o600)
	s.Prune("SessionStart", "resume")
	if fi, _ := os.Stat(log); fi.Size() != int64(len(big)) {
		t.Fatal("rotation must only run on SessionStart(startup)")
	}
	s.Prune("SessionStart", "startup")
	if _, err := os.Stat(log); !os.IsNotExist(err) {
		t.Fatalf("oversized log must be rotated away, stat err = %v", err)
	}
	if fi, err := os.Stat(log + ".1"); err != nil || fi.Size() != int64(len(big)) {
		t.Fatalf("rotated log must replace decisions.jsonl.1: %v", err)
	}
	if err := s.AppendDecision(map[string]int{"n": 1}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(log); string(b) != "{\"n\":1}\n" {
		t.Fatalf("append after rotation must start a fresh log, got %q", b)
	}
}

func TestNewReservesMetricsNames(t *testing.T) {
	for _, n := range []string{"metrics.jsonl", "metrics.jsonl.1", "metrics.jsonl.4", "metrics.jsonl.12"} {
		if got := New("/r", n, "").Session; got != Invalid {
			t.Errorf("%s -> %q", n, got)
		}
	}
	if New("/r", "metrics.jsonlx", "").Session != "metrics.jsonlx" {
		t.Error("over-reserved")
	}
}

func TestAppendMetric(t *testing.T) {
	root := t.TempDir()
	s := New(root, "sess", "")
	if err := s.AppendMetric(map[string]int{"a": 1}); err != nil {
		t.Fatal(err)
	}
	assertMode(t, filepath.Join(root, "metrics.jsonl"), 0o600)
	if err := New("", "s", "").AppendMetric(1); err == nil {
		t.Fatal("empty root must error")
	}
}

func TestRotateMetrics(t *testing.T) {
	put := func(root, name, body string) {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	get := func(root, name string) string {
		b, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			return "<missing>"
		}
		return string(b)
	}
	setup := func() (string, *Store) {
		root := t.TempDir()
		put(root, "metrics.jsonl", "cur-cur")
		put(root, "metrics.jsonl.1", "g1")
		put(root, "metrics.jsonl.2", "g2")
		return root, New(root, "s", "")
	}

	root, s := setup()
	s.RotateMetrics("SessionStart", "startup", 2, 5)
	if get(root, "metrics.jsonl") != "<missing>" || get(root, "metrics.jsonl.1") != "cur-cur" ||
		get(root, "metrics.jsonl.2") != "g1" || get(root, "metrics.jsonl.3") != "<missing>" {
		t.Fatal("keep=2 shift wrong")
	}

	for _, c := range []struct {
		ev, src string
		max     int64
	}{
		{"SessionStart", "resume", 5}, {"PreToolUse", "startup", 5}, {"SessionStart", "startup", 100},
	} {
		root, s := setup()
		s.RotateMetrics(c.ev, c.src, 2, c.max)
		if get(root, "metrics.jsonl") != "cur-cur" || get(root, "metrics.jsonl.1") != "g1" {
			t.Errorf("%+v rotated", c)
		}
	}

	root, s = setup()
	os.Remove(filepath.Join(root, "metrics.jsonl"))
	target := filepath.Join(t.TempDir(), "t")
	os.WriteFile(target, []byte("big-big-big"), 0o600)
	os.Symlink(target, filepath.Join(root, "metrics.jsonl"))
	s.RotateMetrics("SessionStart", "startup", 2, 5)
	if fi, err := os.Lstat(filepath.Join(root, "metrics.jsonl")); err != nil || fi.Mode()&os.ModeSymlink == 0 || get(root, "metrics.jsonl.1") != "g1" {
		t.Fatal("symlink must not rotate")
	}

	// keep=0 drops everything
	root, s = setup()
	s.RotateMetrics("SessionStart", "startup", 0, 5)
	if get(root, "metrics.jsonl") != "<missing>" || get(root, "metrics.jsonl.1") != "<missing>" || get(root, "metrics.jsonl.2") != "<missing>" {
		t.Fatal("keep=0")
	}
}
