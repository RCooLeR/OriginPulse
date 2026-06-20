package geoip

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func DownloadGeoLite2CityMMDB(dbPath string, url string, accountID string, licenseKey string, timeout time.Duration) error {
	if strings.TrimSpace(accountID) == "" || strings.TrimSpace(licenseKey) == "" {
		return errors.New("MAXMIND_ACCOUNT_ID/MAXMIND_LICENSE_KEY required for download")
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return err
	}

	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(accountID, licenseKey)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("download failed: status %d", resp.StatusCode)
	}

	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tmpFile := filepath.Join(filepath.Dir(dbPath), "."+filepath.Base(dbPath)+".tmp")
	f, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
		if err != nil {
			_ = os.Remove(tmpFile)
		}
	}()

	found := false
	tr := tar.NewReader(gzr)
	for {
		hdr, nextErr := tr.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			err = nextErr
			return err
		}
		if hdr.Typeflag != tar.TypeReg || !strings.HasSuffix(hdr.Name, "GeoLite2-City.mmdb") {
			continue
		}
		if _, err = io.Copy(f, tr); err != nil {
			return err
		}
		found = true
		break
	}
	if !found {
		return errors.New("GeoLite2-City.mmdb not found inside tar.gz")
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(tmpFile, dbPath)
}
