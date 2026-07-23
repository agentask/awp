package store

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.etcd.io/bbolt"
)

const crashHelperEnv = "AWP_CRASH_HELPER"

// TestCrashHelperProcess is not a real test on its own — it is invoked as a
// subprocess (self-exec of the test binary, the standard Go pattern for
// exercising real process death) by TestKill9BetweenGate4And5. It opens the
// store, begins gate 4's `seen` write inside a transaction it deliberately
// never commits and never extends to gate 5's `inq` write, signals
// readiness on stdout, then blocks so the parent can SIGKILL it mid-flight.
func TestCrashHelperProcess(t *testing.T) {
	if os.Getenv(crashHelperEnv) != "1" {
		t.Skip("helper process, not a real test")
	}
	path := os.Getenv("AWP_CRASH_DB")
	id := os.Getenv("AWP_CRASH_ID")

	db, err := bbolt.Open(path, 0600, nil)
	if err != nil {
		fmt.Println("OPEN_ERROR", err)
		os.Exit(1)
	}
	err = db.Update(func(tx *bbolt.Tx) error {
		for _, b := range [][]byte{bucketMeta, bucketSeen, bucketInq} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		fmt.Println("INIT_ERROR", err)
		os.Exit(1)
	}

	key, err := idKey(id)
	if err != nil {
		fmt.Println("KEY_ERROR", err)
		os.Exit(1)
	}

	tx, err := db.Begin(true)
	if err != nil {
		fmt.Println("BEGIN_ERROR", err)
		os.Exit(1)
	}
	expBuf := make([]byte, 8)
	if err := tx.Bucket(bucketSeen).Put(key, expBuf); err != nil {
		fmt.Println("PUT_ERROR", err)
		os.Exit(1)
	}
	// Deliberately: no inq write, no Commit(). This is the exact crash
	// point core §2.2 gates 4/5 must be atomic against.
	fmt.Println("READY")
	select {} // block until SIGKILLed by the parent test
}

// TestKill9BetweenGate4And5 is the EARS gate: "WHEN the process dies
// between gate 4 and gate 5, restart SHALL show either both seen+inq
// written or neither." A real subprocess is killed with SIGKILL mid-
// transaction; the parent reopens the store and asserts neither write
// landed. (The complementary half — a successful AcceptInbound leaves
// both — is covered by TestAcceptInbound_WritesBothSeenAndInq.)
func TestKill9BetweenGate4And5(t *testing.T) {
	if os.Getenv(crashHelperEnv) == "1" {
		t.Skip("this is the helper invocation")
	}

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "crash.db")
	id := "01arz3ndektsv4rrffq69g5fav"

	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashHelperProcess$")
	cmd.Env = append(os.Environ(),
		crashHelperEnv+"=1",
		"AWP_CRASH_DB="+dbPath,
		"AWP_CRASH_ID="+id,
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}

	scanner := bufio.NewScanner(stdout)
	ready := false
	for scanner.Scan() {
		line := scanner.Text()
		if line == "READY" {
			ready = true
			break
		}
		if strings.Contains(line, "_ERROR") {
			_ = cmd.Process.Kill()
			t.Fatalf("helper reported error: %s", line)
		}
	}
	if !ready {
		_ = cmd.Process.Kill()
		t.Fatal("helper never signaled READY")
	}

	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("SIGKILL helper: %v", err)
	}
	_ = cmd.Wait() // expected to report the kill; not the point of the test

	// Reopen may race the OS releasing the killed process's file lock;
	// retry briefly rather than sleeping a fixed guess.
	var s *Store
	deadline := time.Now().Add(2 * time.Second)
	for {
		s, err = Open(dbPath)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("reopen after kill: %v", err)
		}
	}
	defer s.Close()

	seen, err := s.HasSeen(id)
	if err != nil {
		t.Fatalf("HasSeen: %v", err)
	}
	queued, err := s.HasQueued(id)
	if err != nil {
		t.Fatalf("HasQueued: %v", err)
	}
	if seen || queued {
		t.Fatalf("expected neither seen nor queued after mid-transaction kill; got seen=%v queued=%v", seen, queued)
	}
}
