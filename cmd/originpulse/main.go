package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"originpulse/internal/app"
	"originpulse/internal/combiner"
	"originpulse/internal/config"
	"originpulse/internal/indexer"
	"originpulse/internal/pipeline"
	"originpulse/internal/retention"
)

func main() {
	os.Exit(run())
}

func run() int {
	zerolog.TimeFieldFormat = time.RFC3339Nano

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	command := "server"
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command = args[0]
		args = args[1:]
	}

	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath(), "path to OriginPulse config file")
	email := fs.String("email", "", "user email for create-user")
	password := fs.String("password", "", "user password for create-user")
	displayName := fs.String("display-name", "", "display name for create-user")
	logType := fs.String("log-type", "nginx-access", "log type for combine")
	from := fs.String("from", "", "inclusive RFC3339 start time for combine")
	to := fs.String("to", "", "exclusive RFC3339 end time for combine")
	force := fs.Bool("force", false, "force regeneration where supported")
	segment := fs.String("segment", "", "combined segment path for index")
	logTypes := fs.String("log-types", "nginx-access", "comma-separated log types for pipeline")
	maxSegments := fs.Int("max-segments", 100, "maximum pending segments to index")
	skipCombine := fs.Bool("skip-combine", false, "skip combine phase and only index pending segments")
	dryRun := fs.Bool("dry-run", false, "show retention matches without deleting")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	if command == "web-push-keys" {
		privateKey, publicKey, err := webpush.GenerateVAPIDKeys()
		if err != nil {
			fmt.Fprintf(os.Stderr, "generate VAPID keys: %v\n", err)
			return 1
		}
		fmt.Printf("ORIGINPULSE_VAPID_PUBLIC_KEY=%s\n", publicKey)
		fmt.Printf("ORIGINPULSE_VAPID_PRIVATE_KEY=%s\n", privateKey)
		fmt.Println("ORIGINPULSE_VAPID_SUBJECT=mailto:originpulse@localhost")
		return 0
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		return 1
	}

	level, err := zerolog.ParseLevel(cfg.App.LogLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339})

	runtime, err := app.New(ctx, cfg)
	if err != nil {
		log.Error().Err(err).Msg("create runtime")
		return 1
	}
	defer runtime.Close()

	switch command {
	case "server":
		if err := runtime.RunServer(ctx); err != nil {
			log.Error().Err(err).Msg("server stopped with error")
			return 1
		}
	case "collect":
		if err := runtime.CollectOnce(ctx); err != nil {
			log.Error().Err(err).Msg("collection failed")
			return 1
		}
	case "combine":
		fromTime, err := parseCLITime(*from)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid -from: %v\n", err)
			return 2
		}
		toTime, err := parseCLITime(*to)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid -to: %v\n", err)
			return 2
		}
		result, err := runtime.Combine(ctx, combiner.Options{
			LogType: *logType,
			From:    fromTime,
			To:      toTime,
			Force:   *force,
		})
		if err != nil {
			log.Error().Err(err).Msg("combine failed")
			return 1
		}
		fmt.Printf("segments_written: %d\n", result.SegmentsWritten)
		fmt.Printf("lines_combined: %d\n", result.LinesCombined)
		fmt.Printf("lines_quarantined: %d\n", result.LinesQuarantined)
	case "index":
		result, err := runtime.IndexSegment(ctx, indexer.Options{SegmentPath: *segment})
		if err != nil {
			log.Error().Err(err).Msg("index failed")
			return 1
		}
		fmt.Printf("segment_status: %s\n", result.SegmentStatus)
		fmt.Printf("already_indexed: %t\n", result.AlreadyIndexed)
		fmt.Printf("events_seen: %d\n", result.EventsSeen)
		fmt.Printf("valid_events: %d\n", result.ValidEvents)
		fmt.Printf("invalid_events: %d\n", result.InvalidEvents)
		fmt.Printf("events_stored_before: %d\n", result.EventsStoredBefore)
		fmt.Printf("events_deleted: %d\n", result.EventsDeleted)
		fmt.Printf("events_inserted: %d\n", result.EventsInserted)
		fmt.Printf("events_conflicted: %d\n", result.EventsConflicted)
		fmt.Printf("events_stored: %d\n", result.EventsStored)
		fmt.Printf("events_skipped: %d\n", result.EventsSkipped)
		fmt.Printf("rollups_updated: %d\n", result.RollupsUpdated)
	case "pipeline":
		var fromTime time.Time
		var toTime time.Time
		if !*skipCombine {
			var err error
			fromTime, err = parseCLITime(*from)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid -from: %v\n", err)
				return 2
			}
			toTime, err = parseCLITime(*to)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid -to: %v\n", err)
				return 2
			}
		}
		result, err := runtime.RunPipeline(ctx, pipeline.Options{
			From:        fromTime,
			To:          toTime,
			Force:       *force,
			SkipCombine: *skipCombine,
			LogTypes:    splitCSV(*logTypes),
			MaxSegments: *maxSegments,
			TriggeredBy: "cli",
		})
		if err != nil {
			log.Error().Err(err).Msg("pipeline failed")
			return 1
		}
		fmt.Printf("combined_segments: %d\n", result.CombinedSegments)
		fmt.Printf("lines_combined: %d\n", result.LinesCombined)
		fmt.Printf("lines_quarantined: %d\n", result.LinesQuarantined)
		fmt.Printf("indexed_segments: %d\n", result.IndexedSegments)
		fmt.Printf("events_inserted: %d\n", result.EventsInserted)
		fmt.Printf("events_stored: %d\n", result.EventsStored)
		fmt.Printf("events_skipped: %d\n", result.EventsSkipped)
		fmt.Printf("rollups_updated: %d\n", result.RollupsUpdated)
	case "migrate":
		if err := runtime.Migrate(ctx); err != nil {
			log.Error().Err(err).Msg("migration failed")
			return 1
		}
		fmt.Println("migrations: ok")
	case "create-user":
		userPassword := *password
		if userPassword == "" {
			userPassword = os.Getenv("ORIGINPULSE_CREATE_USER_PASSWORD")
		}
		if *email == "" || userPassword == "" {
			fmt.Fprintln(os.Stderr, "create-user requires -email and -password or ORIGINPULSE_CREATE_USER_PASSWORD")
			return 2
		}
		user, err := runtime.CreateUser(ctx, *email, userPassword, *displayName)
		if err != nil {
			log.Error().Err(err).Msg("create user failed")
			return 1
		}
		fmt.Printf("user: %s <%s>\n", user.ID, user.Email)
	case "retention":
		result, err := runtime.RunRetention(ctx, retention.Options{DryRun: *dryRun})
		if err != nil {
			log.Error().Err(err).Msg("retention failed")
			return 1
		}
		fmt.Printf("enabled: %t\n", result.Enabled)
		fmt.Printf("dry_run: %t\n", result.DryRun)
		if !result.Cutoff.IsZero() {
			fmt.Printf("cutoff: %s\n", result.Cutoff.Format(time.RFC3339))
		}
		fmt.Printf("max_age: %s\n", result.MaxAge)
		fmt.Printf("raw_files_matched: %d\n", result.RawFilesMatched)
		fmt.Printf("raw_bytes_matched: %d\n", result.RawBytesMatched)
		fmt.Printf("combined_segments_matched: %d\n", result.CombinedSegmentsMatched)
		fmt.Printf("access_events_matched: %d\n", result.AccessEventsMatched)
		fmt.Printf("rollups_matched: %d\n", result.RollupsMatched)
		fmt.Printf("raw_files_deleted: %d\n", result.RawFilesDeleted)
		fmt.Printf("combined_segments_deleted: %d\n", result.CombinedSegmentsDeleted)
		fmt.Printf("access_events_deleted: %d\n", result.AccessEventsDeleted)
		fmt.Printf("rollups_deleted: %d\n", result.RollupsDeleted)
		fmt.Printf("local_files_deleted: %d\n", result.LocalFilesDeleted)
		fmt.Printf("local_file_errors: %d\n", result.LocalFileErrors)
	case "check-config":
		summary := cfg.CredentialSummary()
		fmt.Printf("config: ok\n")
		fmt.Printf("sites: %d\n", len(cfg.EnabledSites()))
		fmt.Printf("database_configured: %t\n", cfg.DatabaseURL() != "")
		fmt.Printf("machine_token_configured: %t\n", summary.MachineTokenConfigured)
		fmt.Printf("ssh_key_configured: %t\n", summary.SSHKeyConfigured)
		fmt.Printf("retention_enabled: %t\n", cfg.Retention.Enabled)
		fmt.Printf("retention_max_age: %s\n", cfg.Retention.MaxAge)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", command)
		return 2
	}

	return 0
}

func parseCLITime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, fmt.Errorf("required")
	}
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed.UTC(), nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, err
	}
	return parsed.UTC(), nil
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func defaultConfigPath() string {
	if value := os.Getenv("ORIGINPULSE_CONFIG"); value != "" {
		return value
	}
	return "config.yml"
}
