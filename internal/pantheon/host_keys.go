package pantheon

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// autoUpdateHostKeys records the presented key without requiring prior trust.
func autoUpdateHostKeys(directory string) ssh.HostKeyCallback {
	return func(_ string, remote net.Addr, key ssh.PublicKey) error {
		// A Pantheon hostname can resolve to several backends with different keys.
		address := remote.String()
		if _, _, err := net.SplitHostPort(address); err != nil {
			return fmt.Errorf("parse SSH server address: %w", err)
		}
		name := fmt.Sprintf("%x.known_hosts", sha256.Sum256([]byte(address)))
		filename := filepath.Join(directory, name)
		line := []byte(knownhosts.Line([]string{address}, key) + "\n")
		previous, err := os.ReadFile(filename)
		if err == nil && bytes.Equal(previous, line) {
			return nil
		}
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("read learned SSH host key: %w", err)
		}
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return fmt.Errorf("create SSH host key directory: %w", err)
		}
		file, err := os.CreateTemp(directory, ".host-key-*")
		if err != nil {
			return fmt.Errorf("create SSH host key file: %w", err)
		}
		defer os.Remove(file.Name())
		defer file.Close()
		if _, err := file.Write(line); err != nil {
			return fmt.Errorf("write SSH host key: %w", err)
		}
		if err := file.Sync(); err != nil {
			return fmt.Errorf("sync SSH host key: %w", err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("close SSH host key file: %w", err)
		}
		// One atomic file per endpoint prevents API/collector writers losing other keys.
		if err := os.Rename(file.Name(), filename); err != nil {
			return fmt.Errorf("save SSH host key: %w", err)
		}
		return nil
	}
}
