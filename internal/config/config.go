package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server        ServerConfig        `yaml:"server" json:"server"`
	App           AppConfig           `yaml:"app" json:"app"`
	Database      DatabaseConfig      `yaml:"database" json:"database"`
	Auth          AuthConfig          `yaml:"auth" json:"auth"`
	Pantheon      PantheonConfig      `yaml:"pantheon" json:"pantheon"`
	Ollama        OllamaConfig        `yaml:"ollama" json:"ollama"`
	Collection    CollectionConfig    `yaml:"collection" json:"collection"`
	Combiner      CombinerConfig      `yaml:"combiner" json:"combiner"`
	Pipeline      PipelineConfig      `yaml:"pipeline" json:"pipeline"`
	Retention     RetentionConfig     `yaml:"retention" json:"retention"`
	Reports       ReportsConfig       `yaml:"reports" json:"reports"`
	Notifications NotificationsConfig `yaml:"notifications" json:"notifications"`
	GeoIP         GeoIPConfig         `yaml:"geoip" json:"geoip"`
	IPIntel       IPIntelConfig       `yaml:"ip_intel" json:"ip_intel"`
	IPAllowlist   IPAllowlistConfig   `yaml:"ip_allowlist" json:"ip_allowlist"`
	Sites         []SiteConfig        `yaml:"sites" json:"sites"`
}

type ServerConfig struct {
	Addr string `yaml:"addr" json:"addr"`
}

type AppConfig struct {
	Name     string `yaml:"name" json:"name"`
	DataDir  string `yaml:"data_dir" json:"data_dir"`
	LogLevel string `yaml:"log_level" json:"log_level"`
}

type DatabaseConfig struct {
	URL             string `yaml:"url" json:"-"`
	URLEnv          string `yaml:"url_env" json:"url_env"`
	AutoMigrate     bool   `yaml:"auto_migrate" json:"auto_migrate"`
	SeedConfigSites bool   `yaml:"seed_config_sites" json:"seed_config_sites"`
	MaxConns        int    `yaml:"max_conns" json:"max_conns"`
}

type AuthConfig struct {
	SessionCookieName string        `yaml:"session_cookie_name" json:"session_cookie_name"`
	SessionTTL        time.Duration `yaml:"session_ttl" json:"session_ttl"`
	SecureCookies     bool          `yaml:"secure_cookies" json:"secure_cookies"`
}

type PantheonConfig struct {
	MachineTokenEnv string        `yaml:"machine_token_env" json:"machine_token_env"`
	EmailEnv        string        `yaml:"email_env" json:"email_env"`
	SSH             SSHConfig     `yaml:"ssh" json:"ssh"`
	DefaultEnvs     []string      `yaml:"default_envs" json:"default_envs"`
	SFTPPort        int           `yaml:"sftp_port" json:"sftp_port"`
	DNSTimeout      time.Duration `yaml:"dns_timeout" json:"dns_timeout"`
}

type OllamaConfig struct {
	BaseURL    string        `yaml:"base_url" json:"-"`
	BaseURLEnv string        `yaml:"base_url_env" json:"base_url_env"`
	Model      string        `yaml:"model" json:"model"`
	ModelEnv   string        `yaml:"model_env" json:"model_env"`
	Timeout    time.Duration `yaml:"timeout" json:"timeout"`
	TimeoutEnv string        `yaml:"timeout_env" json:"timeout_env"`
}

type SSHConfig struct {
	PrivateKeyPath    string `yaml:"private_key_path" json:"private_key_path"`
	PrivateKeyPathEnv string `yaml:"private_key_path_env" json:"private_key_path_env"`
	KnownHostsPath    string `yaml:"known_hosts_path" json:"known_hosts_path"`
}

type CollectionConfig struct {
	Enabled            bool          `yaml:"enabled" json:"enabled"`
	Interval           time.Duration `yaml:"interval" json:"interval"`
	TimeoutPerSite     time.Duration `yaml:"timeout_per_site" json:"timeout_per_site"`
	ServerLockCooldown time.Duration `yaml:"server_lock_cooldown" json:"server_lock_cooldown"`
	MaxParallelSites   int           `yaml:"max_parallel_sites" json:"max_parallel_sites"`
	LogTypes           []string      `yaml:"log_types" json:"log_types"`
	RawDir             string        `yaml:"raw_dir" json:"raw_dir"`
}

type CombinerConfig struct {
	CombinedDir    string        `yaml:"combined_dir" json:"combined_dir"`
	QuarantineDir  string        `yaml:"quarantine_dir" json:"quarantine_dir"`
	SettlingWindow time.Duration `yaml:"settling_window" json:"settling_window"`
	FinalizeAfter  time.Duration `yaml:"finalize_after" json:"finalize_after"`
}

type PipelineConfig struct {
	IndexWorkers int `yaml:"index_workers" json:"index_workers"`
}

type RetentionConfig struct {
	Enabled                bool          `yaml:"enabled" json:"enabled"`
	Interval               time.Duration `yaml:"interval" json:"interval"`
	MaxAge                 time.Duration `yaml:"max_age" json:"max_age"`
	ArchiveDir             string        `yaml:"archive_dir" json:"archive_dir"`
	RawFileMaxAge          time.Duration `yaml:"raw_file_max_age" json:"raw_file_max_age"`
	HotEventMaxAge         time.Duration `yaml:"hot_event_max_age" json:"hot_event_max_age"`
	DailyArchiveAfter      time.Duration `yaml:"daily_archive_after" json:"daily_archive_after"`
	WeeklyArchiveAfter     time.Duration `yaml:"weekly_archive_after" json:"weekly_archive_after"`
	ArchiveMaxAge          time.Duration `yaml:"archive_max_age" json:"archive_max_age"`
	ReportMaxAge           time.Duration `yaml:"report_max_age" json:"report_max_age"`
	TemporaryImportMaxAge  time.Duration `yaml:"temporary_import_max_age" json:"temporary_import_max_age"`
	DeleteRawFiles         bool          `yaml:"delete_raw_files" json:"delete_raw_files"`
	DeleteCombinedFiles    bool          `yaml:"delete_combined_files" json:"delete_combined_files"`
	DeleteHotEvents        bool          `yaml:"delete_hot_events" json:"delete_hot_events"`
	DeleteRollups          bool          `yaml:"delete_rollups" json:"delete_rollups"`
	DeleteTemporaryImports bool          `yaml:"delete_temporary_imports" json:"delete_temporary_imports"`
}

type ReportsConfig struct {
	Enabled  bool          `yaml:"enabled" json:"enabled"`
	Interval time.Duration `yaml:"interval" json:"interval"`
	Ranges   []string      `yaml:"ranges" json:"ranges"`
}

type NotificationsConfig struct {
	Enabled     bool                    `yaml:"enabled" json:"enabled"`
	MinSeverity string                  `yaml:"min_severity" json:"min_severity"`
	Email       EmailNotificationConfig `yaml:"email" json:"email"`
	Push        PushNotificationConfig  `yaml:"push" json:"push"`
}

type GeoIPConfig struct {
	Enabled          bool          `yaml:"enabled" json:"enabled"`
	DBPath           string        `yaml:"db_path" json:"db_path"`
	DBPathEnv        string        `yaml:"db_path_env" json:"db_path_env"`
	SeedPath         string        `yaml:"seed_path" json:"seed_path"`
	SeedPathEnv      string        `yaml:"seed_path_env" json:"seed_path_env"`
	AccountID        string        `yaml:"account_id" json:"-"`
	AccountIDEnv     string        `yaml:"account_id_env" json:"account_id_env"`
	LicenseKey       string        `yaml:"license_key" json:"-"`
	LicenseKeyEnv    string        `yaml:"license_key_env" json:"license_key_env"`
	DownloadURL      string        `yaml:"download_url" json:"download_url"`
	DownloadURLEnv   string        `yaml:"download_url_env" json:"download_url_env"`
	UpdateInterval   time.Duration `yaml:"update_interval" json:"update_interval"`
	DownloadTimeout  time.Duration `yaml:"download_timeout" json:"download_timeout"`
	LastModifiedPath string        `yaml:"last_modified_path" json:"last_modified_path"`
	LastModifiedEnv  string        `yaml:"last_modified_env" json:"last_modified_env"`
}

type IPIntelConfig struct {
	Enabled               bool          `yaml:"enabled" json:"enabled"`
	Interval              time.Duration `yaml:"interval" json:"interval"`
	Range                 string        `yaml:"range" json:"range"`
	Limit                 int           `yaml:"limit" json:"limit"`
	StartupBackfill       bool          `yaml:"startup_backfill" json:"startup_backfill"`
	StartupBackfillRange  string        `yaml:"startup_backfill_range" json:"startup_backfill_range"`
	StartupBackfillLimit  int           `yaml:"startup_backfill_limit" json:"startup_backfill_limit"`
	StartupUserAgentLimit int           `yaml:"startup_user_agent_limit" json:"startup_user_agent_limit"`
}

type IPAllowlistConfig struct {
	Enabled bool               `yaml:"enabled" json:"enabled"`
	Entries []IPAllowlistEntry `yaml:"entries" json:"entries"`
}

type IPAllowlistEntry struct {
	Value     string `yaml:"value" json:"value"`
	Label     string `yaml:"label" json:"label"`
	ActorType string `yaml:"actor_type" json:"actor_type"`
	Source    string `yaml:"source" json:"source"`
}

type EmailNotificationConfig struct {
	Enabled     bool     `yaml:"enabled" json:"enabled"`
	SMTPHost    string   `yaml:"smtp_host" json:"smtp_host"`
	SMTPPort    int      `yaml:"smtp_port" json:"smtp_port"`
	Username    string   `yaml:"username" json:"-"`
	UsernameEnv string   `yaml:"username_env" json:"username_env"`
	Password    string   `yaml:"password" json:"-"`
	PasswordEnv string   `yaml:"password_env" json:"password_env"`
	From        string   `yaml:"from" json:"from"`
	To          []string `yaml:"to" json:"to"`
}

type PushNotificationConfig struct {
	Enabled            bool     `yaml:"enabled" json:"enabled"`
	WebhookURLs        []string `yaml:"webhook_urls" json:"-"`
	WebhookURLsEnv     string   `yaml:"webhook_urls_env" json:"webhook_urls_env"`
	VAPIDPublicKey     string   `yaml:"vapid_public_key" json:"-"`
	VAPIDPublicKeyEnv  string   `yaml:"vapid_public_key_env" json:"vapid_public_key_env"`
	VAPIDPrivateKey    string   `yaml:"vapid_private_key" json:"-"`
	VAPIDPrivateKeyEnv string   `yaml:"vapid_private_key_env" json:"vapid_private_key_env"`
	VAPIDSubject       string   `yaml:"vapid_subject" json:"vapid_subject"`
	VAPIDSubjectEnv    string   `yaml:"vapid_subject_env" json:"vapid_subject_env"`
}

type SiteConfig struct {
	ID             string   `yaml:"id" json:"id"`
	Name           string   `yaml:"name" json:"name"`
	SourceType     string   `yaml:"source_type" json:"source_type"`
	PantheonSiteID string   `yaml:"pantheon_site_id" json:"pantheon_site_id"`
	LocalPath      string   `yaml:"local_path" json:"local_path"`
	FilenameMasks  []string `yaml:"filename_masks" json:"filename_masks"`
	Enabled        bool     `yaml:"enabled" json:"enabled"`
	Envs           []string `yaml:"envs" json:"envs"`
	Tags           []string `yaml:"tags" json:"tags"`
}

type CredentialSummary struct {
	MachineTokenConfigured bool   `json:"machine_token_configured"`
	MachineTokenEnv        string `json:"machine_token_env"`
	EmailConfigured        bool   `json:"email_configured"`
	EmailEnv               string `json:"email_env"`
	SSHKeyConfigured       bool   `json:"ssh_key_configured"`
	SSHKeyPath             string `json:"ssh_key_path"`
	KnownHostsConfigured   bool   `json:"known_hosts_configured"`
	KnownHostsPath         string `json:"known_hosts_path"`
}

func Load(path string) (Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && path == "config.yml" {
			return cfg, nil
		}
		return Config{}, err
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}

	cfg.applyEnv()
	cfg.normalize()
	return cfg, nil
}

func Default() Config {
	cfg := Config{
		Server: ServerConfig{
			Addr: ":8080",
		},
		App: AppConfig{
			Name:     "OriginPulse",
			DataDir:  "./data",
			LogLevel: "info",
		},
		Database: DatabaseConfig{
			URLEnv:          "DATABASE_URL",
			AutoMigrate:     true,
			SeedConfigSites: true,
			MaxConns:        10,
		},
		Auth: AuthConfig{
			SessionCookieName: "originpulse_session",
			SessionTTL:        168 * time.Hour,
		},
		Pantheon: PantheonConfig{
			MachineTokenEnv: "PANTHEON_MACHINE_TOKEN",
			EmailEnv:        "PANTHEON_EMAIL",
			DefaultEnvs:     []string{"live"},
			SFTPPort:        2222,
			DNSTimeout:      10 * time.Second,
			SSH: SSHConfig{
				PrivateKeyPathEnv: "PANTHEON_SSH_KEY_PATH",
			},
		},
		Ollama: OllamaConfig{
			BaseURLEnv: "OLLAMA_BASE_URL",
			ModelEnv:   "OLLAMA_MODEL",
			Model:      "gemma4:12b",
			Timeout:    10 * time.Minute,
			TimeoutEnv: "OLLAMA_TIMEOUT",
		},
		Collection: CollectionConfig{
			Enabled:            false,
			Interval:           10 * time.Minute,
			TimeoutPerSite:     90 * time.Second,
			ServerLockCooldown: 15 * time.Minute,
			MaxParallelSites:   4,
			LogTypes:           []string{"nginx-access", "nginx-error", "apache-access", "apache-error", "php-error"},
			RawDir:             "./data/raw",
		},
		Combiner: CombinerConfig{
			CombinedDir:    "./data/combined",
			QuarantineDir:  "./data/quarantine",
			SettlingWindow: 2 * time.Hour,
			FinalizeAfter:  3 * time.Hour,
		},
		Pipeline: PipelineConfig{
			IndexWorkers: 2,
		},
		Retention: RetentionConfig{
			Enabled:                true,
			Interval:               24 * time.Hour,
			MaxAge:                 60 * 24 * time.Hour,
			RawFileMaxAge:          14 * 24 * time.Hour,
			HotEventMaxAge:         60 * 24 * time.Hour,
			DailyArchiveAfter:      7 * 24 * time.Hour,
			WeeklyArchiveAfter:     30 * 24 * time.Hour,
			ArchiveMaxAge:          90 * 24 * time.Hour,
			ReportMaxAge:           5 * 365 * 24 * time.Hour,
			TemporaryImportMaxAge:  7 * 24 * time.Hour,
			DeleteRawFiles:         true,
			DeleteCombinedFiles:    false,
			DeleteHotEvents:        true,
			DeleteRollups:          false,
			DeleteTemporaryImports: true,
		},
		Reports: ReportsConfig{
			Enabled:  true,
			Interval: 24 * time.Hour,
			Ranges:   []string{"24h", "7d", "30d", "90d", "365d"},
		},
		Notifications: NotificationsConfig{
			Enabled:     true,
			MinSeverity: "high",
			Email: EmailNotificationConfig{
				SMTPPort:    587,
				UsernameEnv: "ORIGINPULSE_SMTP_USERNAME",
				PasswordEnv: "ORIGINPULSE_SMTP_PASSWORD",
			},
			Push: PushNotificationConfig{
				WebhookURLsEnv:     "ORIGINPULSE_PUSH_WEBHOOK_URLS",
				VAPIDPublicKeyEnv:  "ORIGINPULSE_VAPID_PUBLIC_KEY",
				VAPIDPrivateKeyEnv: "ORIGINPULSE_VAPID_PRIVATE_KEY",
				VAPIDSubjectEnv:    "ORIGINPULSE_VAPID_SUBJECT",
				VAPIDSubject:       "mailto:originpulse@localhost",
			},
		},
		GeoIP: GeoIPConfig{
			Enabled:          true,
			DBPath:           "./data/GeoLite2-City.mmdb",
			DBPathEnv:        "GEOIP_DB_PATH",
			SeedPath:         "./assets/geoip/GeoLite2-City.mmdb",
			SeedPathEnv:      "GEOIP_SEED_PATH",
			AccountIDEnv:     "MAXMIND_ACCOUNT_ID",
			LicenseKeyEnv:    "MAXMIND_LICENSE_KEY",
			DownloadURL:      "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz",
			DownloadURLEnv:   "MAXMIND_GEOLITE2_CITY_URL",
			UpdateInterval:   24 * time.Hour,
			DownloadTimeout:  2 * time.Minute,
			LastModifiedPath: "./data/GeoLite2-City.lastmod",
			LastModifiedEnv:  "GEOIP_LAST_MODIFIED_PATH",
		},
		IPIntel: IPIntelConfig{
			Enabled:               true,
			Interval:              15 * time.Minute,
			Range:                 "24h",
			Limit:                 500,
			StartupBackfill:       true,
			StartupBackfillRange:  "365d",
			StartupBackfillLimit:  5000,
			StartupUserAgentLimit: 50000,
		},
		IPAllowlist: IPAllowlistConfig{
			Enabled: true,
		},
	}
	cfg.normalize()
	return cfg
}

func (c *Config) Validate() error {
	c.normalize()

	if strings.TrimSpace(c.Server.Addr) == "" {
		return errors.New("server.addr is required")
	}
	if strings.TrimSpace(c.App.DataDir) == "" {
		return errors.New("app.data_dir is required")
	}
	if c.Auth.SessionTTL <= 0 {
		return errors.New("auth.session_ttl must be positive")
	}
	if strings.TrimSpace(c.Auth.SessionCookieName) == "" {
		return errors.New("auth.session_cookie_name is required")
	}
	if c.Collection.Interval <= 0 {
		return errors.New("collection.interval must be positive")
	}
	if c.Collection.TimeoutPerSite <= 0 {
		return errors.New("collection.timeout_per_site must be positive")
	}
	if c.Collection.ServerLockCooldown <= 0 {
		return errors.New("collection.server_lock_cooldown must be positive")
	}
	if c.Collection.MaxParallelSites <= 0 {
		return errors.New("collection.max_parallel_sites must be positive")
	}
	if strings.TrimSpace(c.Combiner.CombinedDir) == "" {
		return errors.New("combiner.combined_dir is required")
	}
	if strings.TrimSpace(c.Combiner.QuarantineDir) == "" {
		return errors.New("combiner.quarantine_dir is required")
	}
	if c.Pipeline.IndexWorkers <= 0 {
		return errors.New("pipeline.index_workers must be positive")
	}
	if c.Pantheon.SFTPPort == 0 {
		return errors.New("pantheon.sftp_port must be set")
	}
	if c.Retention.Enabled {
		if c.Retention.Interval <= 0 {
			return errors.New("retention.interval must be positive")
		}
		if c.Retention.RawFileMaxAge <= 0 {
			return errors.New("retention.raw_file_max_age must be positive")
		}
		if c.Retention.HotEventMaxAge <= 0 {
			return errors.New("retention.hot_event_max_age must be positive")
		}
		if c.Retention.DailyArchiveAfter <= 0 {
			return errors.New("retention.daily_archive_after must be positive")
		}
		if c.Retention.WeeklyArchiveAfter <= 0 {
			return errors.New("retention.weekly_archive_after must be positive")
		}
		if c.Retention.ArchiveMaxAge <= 0 {
			return errors.New("retention.archive_max_age must be positive")
		}
		if c.Retention.ReportMaxAge <= 0 {
			return errors.New("retention.report_max_age must be positive")
		}
		if c.Retention.TemporaryImportMaxAge <= 0 {
			return errors.New("retention.temporary_import_max_age must be positive")
		}
	}
	if c.Reports.Enabled && c.Reports.Interval <= 0 {
		return errors.New("reports.interval must be positive")
	}
	if c.Notifications.Email.Enabled {
		if strings.TrimSpace(c.Notifications.Email.SMTPHost) == "" {
			return errors.New("notifications.email.smtp_host is required when email notifications are enabled")
		}
		if c.Notifications.Email.SMTPPort <= 0 {
			return errors.New("notifications.email.smtp_port must be positive")
		}
		if strings.TrimSpace(c.Notifications.Email.From) == "" {
			return errors.New("notifications.email.from is required when email notifications are enabled")
		}
		if len(c.Notifications.Email.To) == 0 {
			return errors.New("notifications.email.to must include at least one recipient when email notifications are enabled")
		}
	}
	push := c.Notifications.Push
	if strings.TrimSpace(c.PushVAPIDPublicKey()) != "" && strings.TrimSpace(c.PushVAPIDPrivateKey()) == "" {
		return errors.New("notifications.push.vapid_private_key is required when vapid_public_key is set")
	}
	if strings.TrimSpace(c.PushVAPIDPrivateKey()) != "" && strings.TrimSpace(c.PushVAPIDPublicKey()) == "" {
		return errors.New("notifications.push.vapid_public_key is required when vapid_private_key is set")
	}
	if push.Enabled && strings.TrimSpace(c.PushVAPIDSubject()) == "" && strings.TrimSpace(c.PushVAPIDPublicKey()) != "" {
		return errors.New("notifications.push.vapid_subject is required when browser push is configured")
	}
	if c.GeoIP.Enabled {
		if strings.TrimSpace(c.GeoIPDBPath()) == "" {
			return errors.New("geoip.db_path is required when geoip is enabled")
		}
		if c.GeoIP.UpdateInterval < 0 {
			return errors.New("geoip.update_interval cannot be negative")
		}
		if c.GeoIP.DownloadTimeout <= 0 {
			return errors.New("geoip.download_timeout must be positive")
		}
	}
	if c.IPIntel.Enabled {
		if c.IPIntel.Interval <= 0 {
			return errors.New("ip_intel.interval must be positive")
		}
		if strings.TrimSpace(c.IPIntel.Range) == "" {
			return errors.New("ip_intel.range is required when ip_intel is enabled")
		}
		if c.IPIntel.Limit <= 0 {
			return errors.New("ip_intel.limit must be positive")
		}
		if c.IPIntel.StartupBackfill {
			if strings.TrimSpace(c.IPIntel.StartupBackfillRange) == "" {
				return errors.New("ip_intel.startup_backfill_range is required when startup backfill is enabled")
			}
			if c.IPIntel.StartupBackfillLimit <= 0 {
				return errors.New("ip_intel.startup_backfill_limit must be positive")
			}
			if c.IPIntel.StartupUserAgentLimit <= 0 {
				return errors.New("ip_intel.startup_user_agent_limit must be positive")
			}
		}
	}
	if c.IPAllowlist.Enabled {
		for _, entry := range c.IPAllowlist.Entries {
			value := strings.TrimSpace(entry.Value)
			if value == "" {
				return errors.New("ip_allowlist entry value is required")
			}
			if _, err := netip.ParseAddr(value); err != nil {
				if _, prefixErr := netip.ParsePrefix(value); prefixErr != nil {
					return fmt.Errorf("ip_allowlist entry %q must be an IP address or CIDR", value)
				}
			}
		}
	}

	ids := make(map[string]struct{}, len(c.Sites))
	for _, site := range c.Sites {
		if strings.TrimSpace(site.ID) == "" {
			return errors.New("site id is required")
		}
		if _, exists := ids[site.ID]; exists {
			return fmt.Errorf("duplicate site id %q", site.ID)
		}
		ids[site.ID] = struct{}{}
		if site.Enabled {
			switch normalizeSiteSourceType(site) {
			case "pantheon":
				if strings.TrimSpace(site.PantheonSiteID) == "" {
					return fmt.Errorf("site %q is enabled but pantheon_site_id is empty", site.ID)
				}
			case "local":
				if strings.TrimSpace(site.LocalPath) == "" {
					return fmt.Errorf("site %q is enabled but local_path is empty", site.ID)
				}
				for _, mask := range site.FilenameMasks {
					if _, err := filepath.Match(mask, "example.log"); err != nil {
						return fmt.Errorf("site %q has invalid filename mask %q: %w", site.ID, mask, err)
					}
				}
			default:
				return fmt.Errorf("site %q has unsupported source_type %q", site.ID, site.SourceType)
			}
		}
	}

	return nil
}

func (c Config) EnabledSites() []SiteConfig {
	sites := make([]SiteConfig, 0, len(c.Sites))
	for _, site := range c.Sites {
		if site.Enabled {
			if len(site.Envs) == 0 {
				site.Envs = append([]string(nil), c.Pantheon.DefaultEnvs...)
			}
			sites = append(sites, site)
		}
	}
	return sites
}

func (c Config) CredentialSummary() CredentialSummary {
	sshPath := c.SSHPrivateKeyPath()
	knownHosts := strings.TrimSpace(c.Pantheon.SSH.KnownHostsPath)

	return CredentialSummary{
		MachineTokenConfigured: envSet(c.Pantheon.MachineTokenEnv),
		MachineTokenEnv:        c.Pantheon.MachineTokenEnv,
		EmailConfigured:        envSet(c.Pantheon.EmailEnv),
		EmailEnv:               c.Pantheon.EmailEnv,
		SSHKeyConfigured:       sshPath != "",
		SSHKeyPath:             sshPath,
		KnownHostsConfigured:   knownHosts != "",
		KnownHostsPath:         knownHosts,
	}
}

func (c DatabaseConfig) URLValue() string {
	if c.URLEnv != "" {
		if value := strings.TrimSpace(os.Getenv(c.URLEnv)); value != "" {
			return value
		}
	}
	return strings.TrimSpace(c.URL)
}

func (c Config) DatabaseURL() string {
	return c.Database.URLValue()
}

func (c Config) SSHPrivateKeyPath() string {
	if c.Pantheon.SSH.PrivateKeyPathEnv != "" {
		if value := strings.TrimSpace(os.Getenv(c.Pantheon.SSH.PrivateKeyPathEnv)); value != "" {
			return value
		}
	}
	return strings.TrimSpace(c.Pantheon.SSH.PrivateKeyPath)
}

func (c Config) OllamaBaseURL() string {
	if c.Ollama.BaseURLEnv != "" {
		if value := strings.TrimSpace(os.Getenv(c.Ollama.BaseURLEnv)); value != "" {
			return strings.TrimRight(value, "/")
		}
	}
	return strings.TrimRight(strings.TrimSpace(c.Ollama.BaseURL), "/")
}

func (c Config) OllamaModel() string {
	if c.Ollama.ModelEnv != "" {
		if value := strings.TrimSpace(os.Getenv(c.Ollama.ModelEnv)); value != "" {
			return value
		}
	}
	if strings.TrimSpace(c.Ollama.Model) == "" {
		return "gemma4:12b"
	}
	return strings.TrimSpace(c.Ollama.Model)
}

func (c Config) OllamaTimeout() time.Duration {
	if c.Ollama.TimeoutEnv != "" {
		if value := strings.TrimSpace(os.Getenv(c.Ollama.TimeoutEnv)); value != "" {
			if parsed, err := time.ParseDuration(value); err == nil && parsed > 0 {
				return parsed
			}
		}
	}
	if c.Ollama.Timeout > 0 {
		return c.Ollama.Timeout
	}
	return 10 * time.Minute
}

func (c Config) SMTPUsername() string {
	if c.Notifications.Email.UsernameEnv != "" {
		if value := strings.TrimSpace(os.Getenv(c.Notifications.Email.UsernameEnv)); value != "" {
			return value
		}
	}
	return strings.TrimSpace(c.Notifications.Email.Username)
}

func (c Config) SMTPPassword() string {
	if c.Notifications.Email.PasswordEnv != "" {
		if value := strings.TrimSpace(os.Getenv(c.Notifications.Email.PasswordEnv)); value != "" {
			return value
		}
	}
	return strings.TrimSpace(c.Notifications.Email.Password)
}

func (c Config) PushWebhookURLs() []string {
	urls := append([]string(nil), c.Notifications.Push.WebhookURLs...)
	if c.Notifications.Push.WebhookURLsEnv != "" {
		for _, part := range strings.Split(os.Getenv(c.Notifications.Push.WebhookURLsEnv), ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				urls = append(urls, trimmed)
			}
		}
	}
	out := make([]string, 0, len(urls))
	seen := make(map[string]struct{}, len(urls))
	for _, raw := range urls {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if _, ok := seen[raw]; ok {
			continue
		}
		seen[raw] = struct{}{}
		out = append(out, raw)
	}
	return out
}

func (c Config) PushVAPIDPublicKey() string {
	if c.Notifications.Push.VAPIDPublicKeyEnv != "" {
		if value := strings.TrimSpace(os.Getenv(c.Notifications.Push.VAPIDPublicKeyEnv)); value != "" {
			return value
		}
	}
	return strings.TrimSpace(c.Notifications.Push.VAPIDPublicKey)
}

func (c Config) PushVAPIDPrivateKey() string {
	if c.Notifications.Push.VAPIDPrivateKeyEnv != "" {
		if value := strings.TrimSpace(os.Getenv(c.Notifications.Push.VAPIDPrivateKeyEnv)); value != "" {
			return value
		}
	}
	return strings.TrimSpace(c.Notifications.Push.VAPIDPrivateKey)
}

func (c Config) PushVAPIDSubject() string {
	if c.Notifications.Push.VAPIDSubjectEnv != "" {
		if value := strings.TrimSpace(os.Getenv(c.Notifications.Push.VAPIDSubjectEnv)); value != "" {
			return value
		}
	}
	return strings.TrimSpace(c.Notifications.Push.VAPIDSubject)
}

func (c Config) GeoIPDBPath() string {
	if c.GeoIP.DBPathEnv != "" {
		if value := strings.TrimSpace(os.Getenv(c.GeoIP.DBPathEnv)); value != "" {
			return c.absPath(value)
		}
	}
	return c.absPath(c.GeoIP.DBPath)
}

func (c Config) GeoIPSeedPath() string {
	if c.GeoIP.SeedPathEnv != "" {
		if value := strings.TrimSpace(os.Getenv(c.GeoIP.SeedPathEnv)); value != "" {
			return c.absPath(value)
		}
	}
	return c.absPath(c.GeoIP.SeedPath)
}

func (c Config) GeoIPAccountID() string {
	if c.GeoIP.AccountIDEnv != "" {
		if value := strings.TrimSpace(os.Getenv(c.GeoIP.AccountIDEnv)); value != "" {
			return value
		}
	}
	return strings.TrimSpace(c.GeoIP.AccountID)
}

func (c Config) GeoIPLicenseKey() string {
	if c.GeoIP.LicenseKeyEnv != "" {
		if value := strings.TrimSpace(os.Getenv(c.GeoIP.LicenseKeyEnv)); value != "" {
			return value
		}
	}
	return strings.TrimSpace(c.GeoIP.LicenseKey)
}

func (c Config) GeoIPDownloadURL() string {
	if c.GeoIP.DownloadURLEnv != "" {
		if value := strings.TrimSpace(os.Getenv(c.GeoIP.DownloadURLEnv)); value != "" {
			return value
		}
	}
	return strings.TrimSpace(c.GeoIP.DownloadURL)
}

func (c Config) GeoIPLastModifiedPath() string {
	if c.GeoIP.LastModifiedEnv != "" {
		if value := strings.TrimSpace(os.Getenv(c.GeoIP.LastModifiedEnv)); value != "" {
			return c.absPath(value)
		}
	}
	return c.absPath(c.GeoIP.LastModifiedPath)
}

func (c Config) RawDir() string {
	return c.absPath(c.Collection.RawDir)
}

func (c Config) CombinedDir() string {
	return c.absPath(c.Combiner.CombinedDir)
}

func (c Config) ArchiveDir() string {
	return c.absPath(c.Retention.ArchiveDir)
}

func (c Config) QuarantineDir() string {
	return c.absPath(c.Combiner.QuarantineDir)
}

func (c Config) DataDir() string {
	return c.absPath(c.App.DataDir)
}

func (c Config) absPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return path
	}
	if filepath.IsAbs(path) {
		return path
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}

func (c *Config) applyEnv() {
	if port := strings.TrimSpace(os.Getenv("PORT")); port != "" && strings.HasPrefix(c.Server.Addr, ":") {
		c.Server.Addr = ":" + port
	}
	if level := strings.TrimSpace(os.Getenv("LOG_LEVEL")); level != "" {
		c.App.LogLevel = level
	}
}

func (c *Config) normalize() {
	if c.Server.Addr == "" {
		c.Server.Addr = ":8080"
	}
	if c.App.Name == "" {
		c.App.Name = "OriginPulse"
	}
	if c.App.DataDir == "" {
		c.App.DataDir = "./data"
	}
	if c.App.LogLevel == "" {
		c.App.LogLevel = "info"
	}
	if c.Database.URLEnv == "" {
		c.Database.URLEnv = "DATABASE_URL"
	}
	if c.Database.MaxConns == 0 {
		c.Database.MaxConns = 10
	}
	if c.Auth.SessionCookieName == "" {
		c.Auth.SessionCookieName = "originpulse_session"
	}
	if c.Auth.SessionTTL == 0 {
		c.Auth.SessionTTL = 168 * time.Hour
	}
	if c.Pantheon.MachineTokenEnv == "" {
		c.Pantheon.MachineTokenEnv = "PANTHEON_MACHINE_TOKEN"
	}
	if c.Pantheon.EmailEnv == "" {
		c.Pantheon.EmailEnv = "PANTHEON_EMAIL"
	}
	if c.Pantheon.SFTPPort == 0 {
		c.Pantheon.SFTPPort = 2222
	}
	if c.Pantheon.DNSTimeout == 0 {
		c.Pantheon.DNSTimeout = 10 * time.Second
	}
	if len(c.Pantheon.DefaultEnvs) == 0 {
		c.Pantheon.DefaultEnvs = []string{"live"}
	}
	if c.Pantheon.SSH.PrivateKeyPathEnv == "" {
		c.Pantheon.SSH.PrivateKeyPathEnv = "PANTHEON_SSH_KEY_PATH"
	}
	if c.Ollama.BaseURLEnv == "" {
		c.Ollama.BaseURLEnv = "OLLAMA_BASE_URL"
	}
	if c.Ollama.ModelEnv == "" {
		c.Ollama.ModelEnv = "OLLAMA_MODEL"
	}
	if c.Ollama.Model == "" {
		c.Ollama.Model = "gemma4:12b"
	}
	if c.Ollama.TimeoutEnv == "" {
		c.Ollama.TimeoutEnv = "OLLAMA_TIMEOUT"
	}
	if c.Ollama.Timeout == 0 {
		c.Ollama.Timeout = 10 * time.Minute
	}
	if c.Collection.Interval == 0 {
		c.Collection.Interval = 10 * time.Minute
	}
	if c.Collection.TimeoutPerSite == 0 {
		c.Collection.TimeoutPerSite = 90 * time.Second
	}
	if c.Collection.ServerLockCooldown == 0 {
		c.Collection.ServerLockCooldown = 15 * time.Minute
	}
	if c.Collection.MaxParallelSites == 0 {
		c.Collection.MaxParallelSites = 4
	}
	if len(c.Collection.LogTypes) == 0 {
		c.Collection.LogTypes = []string{"nginx-access", "nginx-error", "apache-access", "apache-error", "php-error"}
	}
	if c.Collection.RawDir == "" {
		c.Collection.RawDir = filepath.Join(c.App.DataDir, "raw")
	}
	if c.Combiner.CombinedDir == "" {
		c.Combiner.CombinedDir = filepath.Join(c.App.DataDir, "combined")
	}
	if c.Combiner.QuarantineDir == "" {
		c.Combiner.QuarantineDir = filepath.Join(c.App.DataDir, "quarantine")
	}
	if c.Combiner.SettlingWindow == 0 {
		c.Combiner.SettlingWindow = 2 * time.Hour
	}
	if c.Combiner.FinalizeAfter == 0 {
		c.Combiner.FinalizeAfter = 3 * time.Hour
	}
	if c.Pipeline.IndexWorkers == 0 {
		c.Pipeline.IndexWorkers = 2
	}
	if c.Retention.Interval == 0 {
		c.Retention.Interval = 24 * time.Hour
	}
	if c.Retention.MaxAge == 0 {
		c.Retention.MaxAge = 60 * 24 * time.Hour
	}
	if c.Retention.ArchiveDir == "" {
		c.Retention.ArchiveDir = filepath.Join(c.App.DataDir, "archives")
	}
	if c.Retention.RawFileMaxAge == 0 {
		c.Retention.RawFileMaxAge = 14 * 24 * time.Hour
	}
	if c.Retention.HotEventMaxAge == 0 {
		c.Retention.HotEventMaxAge = 60 * 24 * time.Hour
	}
	if c.Retention.DailyArchiveAfter == 0 {
		c.Retention.DailyArchiveAfter = 7 * 24 * time.Hour
	}
	if c.Retention.WeeklyArchiveAfter == 0 {
		c.Retention.WeeklyArchiveAfter = 30 * 24 * time.Hour
	}
	if c.Retention.ArchiveMaxAge == 0 {
		c.Retention.ArchiveMaxAge = 90 * 24 * time.Hour
	}
	if c.Retention.ReportMaxAge == 0 {
		c.Retention.ReportMaxAge = 5 * 365 * 24 * time.Hour
	}
	if c.Retention.TemporaryImportMaxAge == 0 {
		c.Retention.TemporaryImportMaxAge = 7 * 24 * time.Hour
	}
	if c.Reports.Interval == 0 {
		c.Reports.Interval = 24 * time.Hour
	}
	if len(c.Reports.Ranges) == 0 {
		c.Reports.Ranges = []string{"24h", "7d", "30d", "90d", "365d"}
	}
	if c.Notifications.MinSeverity == "" {
		c.Notifications.MinSeverity = "high"
	}
	if c.Notifications.Email.SMTPPort == 0 {
		c.Notifications.Email.SMTPPort = 587
	}
	if c.Notifications.Email.UsernameEnv == "" {
		c.Notifications.Email.UsernameEnv = "ORIGINPULSE_SMTP_USERNAME"
	}
	if c.Notifications.Email.PasswordEnv == "" {
		c.Notifications.Email.PasswordEnv = "ORIGINPULSE_SMTP_PASSWORD"
	}
	if c.Notifications.Push.WebhookURLsEnv == "" {
		c.Notifications.Push.WebhookURLsEnv = "ORIGINPULSE_PUSH_WEBHOOK_URLS"
	}
	if c.Notifications.Push.VAPIDPublicKeyEnv == "" {
		c.Notifications.Push.VAPIDPublicKeyEnv = "ORIGINPULSE_VAPID_PUBLIC_KEY"
	}
	if c.Notifications.Push.VAPIDPrivateKeyEnv == "" {
		c.Notifications.Push.VAPIDPrivateKeyEnv = "ORIGINPULSE_VAPID_PRIVATE_KEY"
	}
	if c.Notifications.Push.VAPIDSubjectEnv == "" {
		c.Notifications.Push.VAPIDSubjectEnv = "ORIGINPULSE_VAPID_SUBJECT"
	}
	if c.Notifications.Push.VAPIDSubject == "" {
		c.Notifications.Push.VAPIDSubject = "mailto:originpulse@localhost"
	}
	if c.GeoIP.DBPath == "" {
		c.GeoIP.DBPath = filepath.Join(c.App.DataDir, "GeoLite2-City.mmdb")
	}
	if c.GeoIP.DBPathEnv == "" {
		c.GeoIP.DBPathEnv = "GEOIP_DB_PATH"
	}
	if c.GeoIP.SeedPath == "" {
		c.GeoIP.SeedPath = filepath.Join("assets", "geoip", "GeoLite2-City.mmdb")
	}
	if c.GeoIP.SeedPathEnv == "" {
		c.GeoIP.SeedPathEnv = "GEOIP_SEED_PATH"
	}
	if c.GeoIP.AccountIDEnv == "" {
		c.GeoIP.AccountIDEnv = "MAXMIND_ACCOUNT_ID"
	}
	if c.GeoIP.LicenseKeyEnv == "" {
		c.GeoIP.LicenseKeyEnv = "MAXMIND_LICENSE_KEY"
	}
	if c.GeoIP.DownloadURL == "" {
		c.GeoIP.DownloadURL = "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz"
	}
	if c.GeoIP.DownloadURLEnv == "" {
		c.GeoIP.DownloadURLEnv = "MAXMIND_GEOLITE2_CITY_URL"
	}
	if c.GeoIP.UpdateInterval == 0 {
		c.GeoIP.UpdateInterval = 24 * time.Hour
	}
	if c.GeoIP.DownloadTimeout == 0 {
		c.GeoIP.DownloadTimeout = 2 * time.Minute
	}
	if c.GeoIP.LastModifiedPath == "" {
		c.GeoIP.LastModifiedPath = filepath.Join(c.App.DataDir, "GeoLite2-City.lastmod")
	}
	if c.GeoIP.LastModifiedEnv == "" {
		c.GeoIP.LastModifiedEnv = "GEOIP_LAST_MODIFIED_PATH"
	}
	if c.IPIntel.Interval == 0 {
		c.IPIntel.Interval = 15 * time.Minute
	}
	if c.IPIntel.Range == "" {
		c.IPIntel.Range = "24h"
	}
	if c.IPIntel.Limit == 0 {
		c.IPIntel.Limit = 500
	}
	if c.IPIntel.StartupBackfillRange == "" {
		c.IPIntel.StartupBackfillRange = "365d"
	}
	if c.IPIntel.StartupBackfillLimit == 0 {
		c.IPIntel.StartupBackfillLimit = 5000
	}
	if c.IPIntel.StartupUserAgentLimit == 0 {
		c.IPIntel.StartupUserAgentLimit = 50000
	}
	if !c.IPAllowlist.Enabled && len(c.IPAllowlist.Entries) > 0 {
		c.IPAllowlist.Enabled = true
	}
	for i := range c.Sites {
		c.Sites[i].SourceType = normalizeSiteSourceType(c.Sites[i])
		c.Sites[i].LocalPath = strings.TrimSpace(c.Sites[i].LocalPath)
		c.Sites[i].PantheonSiteID = strings.TrimSpace(c.Sites[i].PantheonSiteID)
		c.Sites[i].FilenameMasks = normalizeStringList(c.Sites[i].FilenameMasks)
	}
}

func envSet(name string) bool {
	if name == "" {
		return false
	}
	return strings.TrimSpace(os.Getenv(name)) != ""
}

func normalizeSiteSourceType(site SiteConfig) string {
	sourceType := strings.ToLower(strings.TrimSpace(site.SourceType))
	switch sourceType {
	case "", "pantheon":
		if sourceType == "" && strings.TrimSpace(site.PantheonSiteID) == "" && strings.TrimSpace(site.LocalPath) != "" {
			return "local"
		}
		return "pantheon"
	case "local", "direct", "apache", "file", "filesystem":
		return "local"
	default:
		return sourceType
	}
}

func normalizeStringList(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
