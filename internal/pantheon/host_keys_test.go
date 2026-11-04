package pantheon

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestAutoUpdateHostKeysPersistsAndReplaces(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "ssh", "known_hosts.d")
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 2222}
	firstKey := testHostPublicKey(t)
	secondKey := testHostPublicKey(t)
	for _, key := range []ssh.PublicKey{firstKey, firstKey, secondKey} {
		// Reconstructing the callback models a restarted process using persisted data.
		if err := autoUpdateHostKeys(directory)("appserver.live.example.drush.in:2222", remote, key); err != nil {
			t.Fatal(err)
		}
		files, err := filepath.Glob(filepath.Join(directory, "*.known_hosts"))
		if err != nil || len(files) != 1 {
			t.Fatalf("persisted key files = %d, err %v; want one", len(files), err)
		}
		verify, err := knownhosts.New(files[0])
		if err != nil {
			t.Fatal(err)
		}
		if err := verify(remote.String(), remote, key); err != nil {
			t.Fatalf("persisted key differs from latest key: %v", err)
		}
	}
	files, _ := filepath.Glob(filepath.Join(directory, "*.known_hosts"))
	verify, err := knownhosts.New(files[0])
	if err != nil {
		t.Fatal(err)
	}
	var mismatch *knownhosts.KeyError
	if err := verify(remote.String(), remote, firstKey); !errors.As(err, &mismatch) || len(mismatch.Want) == 0 {
		t.Fatalf("old key verification = %v, want key mismatch", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 {
		t.Fatalf("directory entries = %d, err %v; temporary files should be removed", len(entries), err)
	}
}

func TestAutoUpdateHostKeysKeepsConcurrentBackendsSeparate(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "known_hosts.d")
	key := testHostPublicKey(t)
	const backends = 8
	errors := make(chan error, backends)
	var workers sync.WaitGroup
	for index := range backends {
		workers.Go(func() {
			remote := &net.TCPAddr{IP: net.ParseIP(fmt.Sprintf("192.0.2.%d", index+1)), Port: 2222}
			errors <- autoUpdateHostKeys(directory)("appserver.live.example.drush.in:2222", remote, key)
		})
	}
	workers.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	files, err := filepath.Glob(filepath.Join(directory, "*.known_hosts"))
	if err != nil || len(files) != backends {
		t.Fatalf("persisted backend files = %d, err %v; want %d", len(files), err, backends)
	}
	verify, err := knownhosts.New(files...)
	if err != nil {
		t.Fatal(err)
	}
	for index := range backends {
		remote := &net.TCPAddr{IP: net.ParseIP(fmt.Sprintf("192.0.2.%d", index+1)), Port: 2222}
		if err := verify(remote.String(), remote, key); err != nil {
			t.Fatalf("backend %d was lost: %v", index+1, err)
		}
	}
}

func TestAutoUpdateHostKeysReportsStorageFailure(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(directory, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 2222}
	if err := autoUpdateHostKeys(directory)(remote.String(), remote, testHostPublicKey(t)); err == nil {
		t.Fatal("key accepted despite failure to persist it")
	}
}

func testHostPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
