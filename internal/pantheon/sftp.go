package pantheon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"originpulse/internal/config"
	"originpulse/internal/jobs"
)

type SFTPDownloader struct {
	cfg                 config.Config
	jobs                *jobs.Store
	securityWarningOnce sync.Once
}

type DownloadStats struct {
	FilesSeen        int
	FilesDownloaded  int
	FilesSkipped     int
	BytesDownloaded  int64
	ServersAttempted int
	ServersSucceeded int
	ServersFailed    int
	ServersSkipped   int
	ServersLocked    int
	ServerErrors     []string
}

func (s *DownloadStats) add(other DownloadStats) {
	s.FilesSeen += other.FilesSeen
	s.FilesDownloaded += other.FilesDownloaded
	s.FilesSkipped += other.FilesSkipped
	s.BytesDownloaded += other.BytesDownloaded
	s.ServersAttempted += other.ServersAttempted
	s.ServersSucceeded += other.ServersSucceeded
	s.ServersFailed += other.ServersFailed
	s.ServersSkipped += other.ServersSkipped
	s.ServersLocked += other.ServersLocked
	s.ServerErrors = append(s.ServerErrors, other.ServerErrors...)
}

func NewSFTPDownloader(cfg config.Config, store *jobs.Store) *SFTPDownloader {
	return &SFTPDownloader{cfg: cfg, jobs: store}
}

func (d *SFTPDownloader) DownloadLogs(ctx context.Context, jobID string, target Target, serverKind string, serverAddress string, containerID string, repo *RawFileRepository) (DownloadStats, error) {
	var stats DownloadStats
	serverMeta := map[string]any{
		"site_id":      target.SiteID,
		"env":          target.Environment,
		"server_kind":  serverKind,
		"server":       serverAddress,
		"container_id": containerID,
	}

	configStep := d.startStep(ctx, jobID, "prepare ssh config", serverMeta)
	sshConfig, err := d.sshClientConfig(target.SFTPUser)
	if err != nil {
		d.finishStep(configStep, jobs.StatusFailed, "SSH config failed", err, nil)
		return stats, err
	}
	d.finishStep(configStep, jobs.StatusSuccess, "SSH config ready", nil, nil)

	address := net.JoinHostPort(serverAddress, fmt.Sprintf("%d", d.cfg.Pantheon.SFTPPort))
	hostIdentity := sshHostIdentity(target, serverKind, serverAddress, d.cfg.Pantheon.SFTPPort)
	connectStep := d.startStep(ctx, jobID, "connect sftp", mergeStepMeta(serverMeta, map[string]any{"address": address, "host_identity": hostIdentity}))
	conn, err := d.dialSSH(ctx, "tcp", address, hostIdentity, sshConfig)
	if err != nil {
		if isPantheonResourceLocked(err) {
			d.finishStep(connectStep, jobs.StatusSkipped, "Pantheon resource lock detected", nil, map[string]any{"reason": err.Error()})
			return stats, err
		}
		d.finishStep(connectStep, jobs.StatusFailed, "SSH connection failed", err, nil)
		return stats, err
	}
	defer conn.Close()

	client, err := sftp.NewClient(conn)
	if err != nil {
		if isPantheonResourceLocked(err) {
			d.finishStep(connectStep, jobs.StatusSkipped, "Pantheon resource lock detected", nil, map[string]any{"reason": err.Error()})
			return stats, err
		}
		d.finishStep(connectStep, jobs.StatusFailed, "SFTP client failed", err, nil)
		return stats, err
	}
	defer client.Close()
	d.finishStep(connectStep, jobs.StatusSuccess, "SFTP connected", nil, nil)

	listStep := d.startStep(ctx, jobID, "list remote files", mergeStepMeta(serverMeta, map[string]any{"root": "logs"}))
	candidates := make([]RawFile, 0)
	walker := client.Walk("logs")
	for walker.Step() {
		if err := walker.Err(); err != nil {
			d.finishStep(listStep, jobs.StatusFailed, "remote file listing failed", err, map[string]any{
				"files_seen": stats.FilesSeen,
			})
			return stats, err
		}

		info := walker.Stat()
		if info == nil || info.IsDir() {
			continue
		}

		remotePath := NormalizeRemotePath(walker.Path())
		logType := DetectLogType(remotePath)
		if !d.shouldCollect(logType) {
			continue
		}

		stats.FilesSeen++
		localPath := LocalRawPath(d.cfg.RawDir(), target.SiteID, target.Environment, containerID, remotePath)
		candidates = append(candidates, RawFile{
			SiteID:      target.SiteID,
			Env:         target.Environment,
			ContainerID: containerID,
			LogType:     logType,
			RemotePath:  remotePath,
			RemoteSize:  info.Size(),
			RemoteMTime: info.ModTime().UTC(),
			LocalPath:   localPath,
		})
	}
	d.finishStep(listStep, jobs.StatusSuccess, "remote file listing completed", nil, map[string]any{
		"files_seen": stats.FilesSeen,
	})

	for _, rawFile := range candidates {
		if (repo == nil || !repo.Enabled()) && localFileMatches(rawFile.LocalPath, rawFile.RemoteSize) {
			stats.FilesSkipped++
			skipStep := d.startStep(ctx, jobID, "download file", fileStepMeta(serverMeta, rawFile))
			d.finishStep(skipStep, jobs.StatusSkipped, "local file already matches remote size", nil, map[string]any{"downloaded": false})
			continue
		}

		shouldDownload := true
		if repo != nil {
			discoverStep := d.startStep(ctx, jobID, "register remote file", fileStepMeta(serverMeta, rawFile))
			if err := repo.MarkDiscovered(ctx, rawFile); err != nil {
				d.finishStep(discoverStep, jobs.StatusFailed, "failed to register remote file", err, nil)
				return stats, err
			}
			d.finishStep(discoverStep, jobs.StatusSuccess, "remote file registered", nil, nil)
			var err error
			decisionStep := d.startStep(ctx, jobID, "check download need", fileStepMeta(serverMeta, rawFile))
			shouldDownload, err = repo.ShouldDownload(ctx, rawFile)
			if err != nil {
				d.finishStep(decisionStep, jobs.StatusFailed, "download decision failed", err, nil)
				return stats, err
			}
			d.finishStep(decisionStep, jobs.StatusSuccess, downloadDecisionMessage(shouldDownload), nil, map[string]any{"should_download": shouldDownload})
		}
		if !shouldDownload && localFileMatches(rawFile.LocalPath, rawFile.RemoteSize) {
			stats.FilesSkipped++
			skipStep := d.startStep(ctx, jobID, "download file", fileStepMeta(serverMeta, rawFile))
			d.finishStep(skipStep, jobs.StatusSkipped, "file already current", nil, map[string]any{"downloaded": false})
			continue
		}

		downloadStep := d.startStep(ctx, jobID, "download file", fileStepMeta(serverMeta, rawFile))
		sha, bytesWritten, err := d.downloadFile(ctx, client, rawFile.RemotePath, rawFile.LocalPath, rawFile.RemoteSize)
		if err != nil {
			if repo != nil {
				_ = repo.MarkFailed(ctx, rawFile, err)
			}
			d.finishStep(downloadStep, jobs.StatusFailed, "download failed", err, map[string]any{"bytes_written": bytesWritten})
			return stats, err
		}
		d.finishStep(downloadStep, jobs.StatusSuccess, "file downloaded", nil, map[string]any{"bytes_written": bytesWritten, "sha256": sha, "downloaded": true})

		rawFile.SHA256 = sha
		if repo != nil {
			markStep := d.startStep(ctx, jobID, "mark file downloaded", fileStepMeta(serverMeta, rawFile))
			if err := repo.MarkDownloaded(ctx, rawFile); err != nil {
				d.finishStep(markStep, jobs.StatusFailed, "failed to mark file downloaded", err, nil)
				return stats, err
			}
			d.finishStep(markStep, jobs.StatusSuccess, "file marked downloaded", nil, nil)
		}
		stats.FilesDownloaded++
		stats.BytesDownloaded += bytesWritten
	}

	summaryStep := d.startStep(ctx, jobID, "summarize server download", serverMeta)
	d.finishStep(summaryStep, jobs.StatusSuccess, "server download summarized", nil, map[string]any{
		"files_seen":       stats.FilesSeen,
		"files_downloaded": stats.FilesDownloaded,
		"files_skipped":    stats.FilesSkipped,
		"bytes_downloaded": stats.BytesDownloaded,
	})
	return stats, nil
}

func (d *SFTPDownloader) startStep(ctx context.Context, jobID string, name string, meta map[string]any) jobs.Step {
	if d.jobs == nil {
		return jobs.Step{}
	}
	return d.jobs.StartStep(ctx, jobID, name, meta)
}

func (d *SFTPDownloader) finishStep(step jobs.Step, status jobs.Status, message string, err error, meta map[string]any) {
	if d.jobs == nil {
		return
	}
	d.jobs.FinishStep(step, status, message, err, meta)
}

func fileStepMeta(serverMeta map[string]any, rawFile RawFile) map[string]any {
	return mergeStepMeta(serverMeta, map[string]any{
		"log_type":     rawFile.LogType,
		"remote_path":  rawFile.RemotePath,
		"remote_size":  rawFile.RemoteSize,
		"remote_mtime": rawFile.RemoteMTime.Format(time.RFC3339),
		"local_path":   rawFile.LocalPath,
	})
}

func mergeStepMeta(base map[string]any, extra map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(extra))
	maps.Copy(out, base)
	maps.Copy(out, extra)
	return out
}

func downloadDecisionMessage(shouldDownload bool) string {
	if shouldDownload {
		return "download required"
	}
	return "download not required"
}

func (d *SFTPDownloader) sshClientConfig(username string) (*ssh.ClientConfig, error) {
	d.securityWarningOnce.Do(func() {
		if d.cfg.SSHAutoUpdateHostKeys() {
			log.Warn().Msg("Pantheon SSH host keys are automatically added and replaced")
		} else if d.cfg.Pantheon.SSH.InsecureIgnoreHostKey && d.cfg.SSHKnownHostsPath() == "" {
			log.Warn().Msg("Pantheon SSH host-key verification is disabled by compatibility configuration")
		}
		if d.cfg.Pantheon.SSH.AllowLegacyRSA {
			log.Warn().Msg("legacy Pantheon ssh-rsa compatibility is enabled by compatibility configuration")
		}
	})

	keyPath := d.cfg.SSHPrivateKeyPath()
	if strings.TrimSpace(keyPath) == "" {
		return nil, errors.New("pantheon SSH private key path is not configured")
	}

	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, err
	}
	if algorithmSigner, ok := signer.(ssh.AlgorithmSigner); ok && signer.PublicKey().Type() == ssh.KeyAlgoRSA {
		signerAlgorithms := []string{
			ssh.KeyAlgoRSASHA512,
			ssh.KeyAlgoRSASHA256,
		}
		if d.cfg.Pantheon.SSH.AllowLegacyRSA {
			signerAlgorithms = append(signerAlgorithms, ssh.KeyAlgoRSA)
		}
		compatibleSigner, err := ssh.NewSignerWithAlgorithms(algorithmSigner, signerAlgorithms)
		if err != nil {
			return nil, err
		}
		signer = compatibleSigner
	}

	knownHostsPath := d.cfg.SSHKnownHostsPath()
	var hostKeyCallback ssh.HostKeyCallback
	if d.cfg.SSHAutoUpdateHostKeys() {
		hostKeyCallback = autoUpdateHostKeys(filepath.Join(d.cfg.DataDir(), "ssh", "known_hosts.d"))
	} else if knownHostsPath != "" {
		hostKeyCallback, err = knownhosts.New(knownHostsPath)
		if err != nil {
			return nil, err
		}
		hostKeyCallback = withKnownHostsIPFallback(hostKeyCallback)
	} else if d.cfg.Pantheon.SSH.InsecureIgnoreHostKey {
		hostKeyCallback = ssh.InsecureIgnoreHostKey()
	} else {
		return nil, errors.New("pantheon SSH host verification is not configured; set known_hosts_path or explicitly enable insecure_ignore_host_key")
	}

	algorithms := ssh.SupportedAlgorithms()
	hostKeyAlgorithms := slices.Clone(algorithms.HostKeys)
	if d.cfg.Pantheon.SSH.AllowLegacyRSA && !slices.Contains(hostKeyAlgorithms, ssh.KeyAlgoRSA) {
		hostKeyAlgorithms = append(hostKeyAlgorithms, ssh.KeyAlgoRSA)
	}
	return &ssh.ClientConfig{
		Config: ssh.Config{
			KeyExchanges: algorithms.KeyExchanges,
			Ciphers:      algorithms.Ciphers,
			MACs:         algorithms.MACs,
		},
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback:   hostKeyCallback,
		HostKeyAlgorithms: hostKeyAlgorithms,
		Timeout:           d.cfg.Collection.TimeoutPerSite,
	}, nil
}

func withKnownHostsIPFallback(verify ssh.HostKeyCallback) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := verify(hostname, remote, key)
		var keyErr *knownhosts.KeyError
		if errors.As(err, &keyErr) && len(keyErr.Want) == 0 {
			// Existing installations pinned the dialed IP before logical DNS identities were used.
			return verify(remote.String(), remote, key)
		}
		return err
	}
}

func sshHostIdentity(target Target, serverKind string, fallbackAddress string, port int) string {
	host := fallbackAddress
	switch serverKind {
	case "appserver":
		if strings.TrimSpace(target.AppserverDNS) != "" {
			host = target.AppserverDNS
		}
	case "dbserver":
		if strings.TrimSpace(target.DBServerDNS) != "" {
			host = target.DBServerDNS
		}
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", port))
}

func (d *SFTPDownloader) dialSSH(ctx context.Context, network string, address string, hostIdentity string, sshConfig *ssh.ClientConfig) (*ssh.Client, error) {
	dialer := net.Dialer{Timeout: d.cfg.Collection.TimeoutPerSite}
	rawConn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}

	type result struct {
		conn *ssh.Client
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, chans, reqs, err := ssh.NewClientConn(rawConn, hostIdentity, sshConfig)
		if err != nil {
			ch <- result{err: err}
			return
		}
		ch <- result{conn: ssh.NewClient(conn, chans, reqs)}
	}()

	select {
	case <-ctx.Done():
		_ = rawConn.Close()
		return nil, ctx.Err()
	case out := <-ch:
		if out.err != nil {
			_ = rawConn.Close()
		}
		return out.conn, out.err
	}
}

func (d *SFTPDownloader) downloadFile(ctx context.Context, client *sftp.Client, remotePath string, localPath string, remoteSize int64) (string, int64, error) {
	if localSize, ok := appendableLocalSize(remotePath, localPath, remoteSize); ok {
		return d.appendFile(ctx, client, remotePath, localPath, localSize)
	}
	return d.replaceFile(ctx, client, remotePath, localPath)
}

func (d *SFTPDownloader) replaceFile(ctx context.Context, client *sftp.Client, remotePath string, localPath string) (string, int64, error) {
	remoteFile, err := client.Open(path.Clean(remotePath))
	if err != nil {
		return "", 0, err
	}
	defer remoteFile.Close()

	if err := os.MkdirAll(filepath.Dir(localPath), 0o750); err != nil {
		return "", 0, err
	}

	tmpPath := fmt.Sprintf("%s.tmp.%d", localPath, time.Now().UnixNano())
	localFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return "", 0, err
	}

	hasher := sha256.New()
	written, copyErr := copyWithContext(ctx, io.MultiWriter(localFile, hasher), remoteFile)
	syncErr := localFile.Sync()
	closeErr := localFile.Close()
	if copyErr != nil {
		_ = os.Remove(tmpPath)
		return "", written, copyErr
	}
	if syncErr != nil {
		_ = os.Remove(tmpPath)
		return "", written, syncErr
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return "", written, closeErr
	}

	if err := replaceLocalFile(tmpPath, localPath); err != nil {
		_ = os.Remove(tmpPath)
		return "", written, err
	}

	return hex.EncodeToString(hasher.Sum(nil)), written, nil
}

func (d *SFTPDownloader) appendFile(ctx context.Context, client *sftp.Client, remotePath string, localPath string, localSize int64) (string, int64, error) {
	remoteFile, err := client.Open(path.Clean(remotePath))
	if err != nil {
		return "", 0, err
	}
	defer remoteFile.Close()
	if _, err := remoteFile.Seek(localSize, io.SeekStart); err != nil {
		return "", 0, err
	}

	if err := os.MkdirAll(filepath.Dir(localPath), 0o750); err != nil {
		return "", 0, err
	}

	existingFile, err := os.Open(localPath)
	if err != nil {
		return "", 0, err
	}

	tmpPath := fmt.Sprintf("%s.tmp.%d", localPath, time.Now().UnixNano())
	localFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		_ = existingFile.Close()
		return "", 0, err
	}

	hasher := sha256.New()
	if _, err := copyWithContext(ctx, io.MultiWriter(localFile, hasher), existingFile); err != nil {
		_ = existingFile.Close()
		_ = localFile.Close()
		_ = os.Remove(tmpPath)
		return "", 0, err
	}
	if err := existingFile.Close(); err != nil {
		_ = localFile.Close()
		_ = os.Remove(tmpPath)
		return "", 0, err
	}

	written, copyErr := copyWithContext(ctx, io.MultiWriter(localFile, hasher), remoteFile)
	syncErr := localFile.Sync()
	closeErr := localFile.Close()
	if copyErr != nil {
		_ = os.Remove(tmpPath)
		return "", written, copyErr
	}
	if syncErr != nil {
		_ = os.Remove(tmpPath)
		return "", written, syncErr
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return "", written, closeErr
	}

	if err := replaceLocalFile(tmpPath, localPath); err != nil {
		_ = os.Remove(tmpPath)
		return "", written, err
	}

	return hex.EncodeToString(hasher.Sum(nil)), written, nil
}

func (d *SFTPDownloader) shouldCollect(logType string) bool {
	if logType == "unknown" {
		return false
	}
	return slices.Contains(d.cfg.Collection.LogTypes, logType)
}

func copyWithContext(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, 256*1024)
	var written int64
	for {
		select {
		case <-ctx.Done():
			return written, ctx.Err()
		default:
		}

		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			written += int64(nw)
			if ew != nil {
				return written, ew
			}
			if nw != nr {
				return written, io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return written, nil
			}
			return written, er
		}
	}
}

func localFileMatches(localPath string, remoteSize int64) bool {
	info, err := os.Stat(localPath)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Size() == remoteSize
}

func appendableLocalSize(remotePath string, localPath string, remoteSize int64) (int64, bool) {
	if strings.HasSuffix(strings.ToLower(remotePath), ".gz") {
		return 0, false
	}
	info, err := os.Stat(localPath)
	if err != nil || info.IsDir() {
		return 0, false
	}
	localSize := info.Size()
	return localSize, localSize > 0 && remoteSize > localSize
}

func replaceLocalFile(tmpPath string, finalPath string) error {
	if err := os.Rename(tmpPath, finalPath); err == nil {
		return nil
	}
	if err := os.Remove(finalPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Rename(tmpPath, finalPath)
}
