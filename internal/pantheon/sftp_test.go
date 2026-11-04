package pantheon

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"originpulse/internal/config"
)

func TestSSHClientConfigFailsClosedWithoutHostVerification(t *testing.T) {
	cfg := testSSHConfig(t)
	_, err := NewSFTPDownloader(cfg, nil).sshClientConfig("test")
	if err == nil || !strings.Contains(err.Error(), "host verification is not configured") {
		t.Fatalf("sshClientConfig error = %v, want host-verification error", err)
	}
}

func TestSSHClientConfigUsesKnownHostsAndModernAlgorithms(t *testing.T) {
	cfg := testSSHConfig(t)
	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHostsPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Pantheon.SSH.KnownHostsPath = knownHostsPath

	sshConfig, err := NewSFTPDownloader(cfg, nil).sshClientConfig("test")
	if err != nil {
		t.Fatal(err)
	}
	if sshConfig.HostKeyCallback == nil {
		t.Fatal("host key callback is nil")
	}
	if slices.Contains(sshConfig.HostKeyAlgorithms, ssh.KeyAlgoRSA) {
		t.Fatal("legacy ssh-rsa host keys are enabled without an explicit opt-in")
	}
}

func TestSSHClientConfigAllowsExplicitLegacyRSACompatibility(t *testing.T) {
	cfg := testSSHConfig(t)
	cfg.Pantheon.SSH.InsecureIgnoreHostKey = true
	cfg.Pantheon.SSH.AllowLegacyRSA = true

	sshConfig, err := NewSFTPDownloader(cfg, nil).sshClientConfig("test")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(sshConfig.HostKeyAlgorithms, ssh.KeyAlgoRSA) {
		t.Fatal("legacy ssh-rsa host key algorithm was not enabled")
	}
}

func TestKnownHostsUsesLogicalPantheonHostname(t *testing.T) {
	_, hostPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostPublicKey, err := ssh.NewPublicKey(hostPrivateKey.Public())
	if err != nil {
		t.Fatal(err)
	}

	const hostname = "appserver.live.example.drush.in"
	const address = "192.0.2.10"
	identity := sshHostIdentity(Target{AppserverDNS: hostname}, "appserver", address, 2222)
	if identity != hostname+":2222" {
		t.Fatalf("host identity = %q", identity)
	}

	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{identity}, hostPublicKey) + "\n"
	if err := os.WriteFile(knownHostsPath, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := testSSHConfig(t)
	cfg.Pantheon.SSH.KnownHostsPath = knownHostsPath
	sshConfig, err := NewSFTPDownloader(cfg, nil).sshClientConfig("test")
	if err != nil {
		t.Fatal(err)
	}
	remote := &net.TCPAddr{IP: net.ParseIP(address), Port: 2222}
	if err := sshConfig.HostKeyCallback(identity, remote, hostPublicKey); err != nil {
		t.Fatalf("verified logical hostname was rejected: %v", err)
	}
	if err := sshConfig.HostKeyCallback(net.JoinHostPort(address, "2222"), remote, hostPublicKey); err == nil {
		t.Fatal("IP alias unexpectedly matched the hostname known_hosts entry")
	}
}

func TestKnownHostsPreservesIPPinsWithoutBypassingDNSMismatchOrRevocation(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(privateKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	_, otherPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := ssh.NewPublicKey(otherPrivateKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	const identity = "appserver.live.example.drush.in:2222"
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 2222}
	ipLine := knownhosts.Line([]string{remote.String()}, key) + "\n"
	tests := []struct {
		name         string
		lines        string
		wantMismatch bool
		wantRevoked  bool
	}{
		{name: "legacy IP pin", lines: ipLine},
		{name: "DNS mismatch with valid IP pin", lines: knownhosts.Line([]string{identity}, otherKey) + "\n" + ipLine, wantMismatch: true},
		{name: "revoked key with valid IP pin", lines: "@revoked " + knownhosts.Line([]string{identity}, key) + "\n" + ipLine, wantRevoked: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
			if err := os.WriteFile(knownHostsPath, []byte(tt.lines), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := testSSHConfig(t)
			cfg.Pantheon.SSH.KnownHostsPath = knownHostsPath
			sshConfig, err := NewSFTPDownloader(cfg, nil).sshClientConfig("test")
			if err != nil {
				t.Fatal(err)
			}
			err = sshConfig.HostKeyCallback(identity, remote, key)
			var mismatch *knownhosts.KeyError
			var revoked *knownhosts.RevokedError
			switch {
			case tt.wantMismatch:
				if !errors.As(err, &mismatch) || len(mismatch.Want) == 0 {
					t.Fatalf("verification error = %v, want DNS key mismatch", err)
				}
			case tt.wantRevoked:
				if !errors.As(err, &revoked) {
					t.Fatalf("verification error = %v, want revoked key", err)
				}
			default:
				if err != nil {
					t.Fatalf("legacy IP pin rejected: %v", err)
				}
			}
		})
	}
}

func TestSSHClientConfigAutoUpdateOverridesStrictKnownHosts(t *testing.T) {
	cfg := testSSHConfig(t)
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 2222}
	const identity = "appserver.live.example.drush.in:2222"
	oldKey := testHostPublicKey(t)
	newKey := testHostPublicKey(t)
	seed := []byte(knownhosts.Line([]string{identity}, oldKey) + "\n")
	cfg.Pantheon.SSH.KnownHostsPath = filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(cfg.Pantheon.SSH.KnownHostsPath, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Pantheon.SSH.AutoUpdateHostKeys = true
	sshConfig, err := NewSFTPDownloader(cfg, nil).sshClientConfig("test")
	if err != nil {
		t.Fatal(err)
	}
	if err := sshConfig.HostKeyCallback(identity, remote, newKey); err != nil {
		t.Fatalf("automatic mode rejected new key: %v", err)
	}
	persisted, err := filepath.Glob(filepath.Join(cfg.DataDir(), "ssh", "known_hosts.d", "*.known_hosts"))
	if err != nil || len(persisted) != 1 {
		t.Fatalf("learned key files = %d, err %v", len(persisted), err)
	}
	unchanged, err := os.ReadFile(cfg.Pantheon.SSH.KnownHostsPath)
	if err != nil || !bytes.Equal(unchanged, seed) {
		t.Fatalf("strict known-hosts file changed: %v", err)
	}
	cfg.Pantheon.SSH.AutoUpdateHostKeys = false
	strictConfig, err := NewSFTPDownloader(cfg, nil).sshClientConfig("test")
	if err != nil {
		t.Fatal(err)
	}
	var mismatch *knownhosts.KeyError
	if err := strictConfig.HostKeyCallback(identity, remote, newKey); !errors.As(err, &mismatch) || len(mismatch.Want) == 0 {
		t.Fatalf("strict mode verification = %v, want key mismatch", err)
	}
}

func testSSHConfig(t *testing.T) config.Config {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	keyPath := filepath.Join(t.TempDir(), "id_rsa")
	if err := os.WriteFile(keyPath, keyBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.App.DataDir = t.TempDir()
	cfg.Pantheon.SSH.PrivateKeyPathEnv = ""
	cfg.Pantheon.SSH.PrivateKeyPath = keyPath
	cfg.Pantheon.SSH.KnownHostsPathEnv = ""
	cfg.Pantheon.SSH.KnownHostsPath = ""
	cfg.Pantheon.SSH.AutoUpdateHostKeysEnv = ""
	cfg.Pantheon.SSH.InsecureIgnoreHostKey = false
	cfg.Pantheon.SSH.AllowLegacyRSA = false
	return cfg
}
