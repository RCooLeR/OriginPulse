package notifications

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"originpulse/internal/config"
	"originpulse/internal/db"
)

func TestSendPushPostsJSONPayload(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("content-type = %q, want application/json", got)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if body["title"] != "Alert title" {
			t.Fatalf("title = %q", body["title"])
		}
		if body["source"] != "originpulse" {
			t.Fatalf("source = %q", body["source"])
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	service := &Service{client: server.Client()}
	err := service.sendPush(context.Background(), server.URL, "Alert title", "Alert body", map[string]any{"severity": "high"})
	if err != nil {
		t.Fatalf("send push: %v", err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want 1", requests)
	}
}

func TestSendEmailUsesSMTP(t *testing.T) {
	addr, received, stop := startFakeSMTP(t)
	defer stop()

	host, rawPort, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split smtp addr: %v", err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatalf("parse smtp port: %v", err)
	}

	cfg := config.Default()
	cfg.Notifications.Email.SMTPHost = host
	cfg.Notifications.Email.SMTPPort = port
	cfg.Notifications.Email.From = "originpulse@example.test"
	cfg.Notifications.Email.To = []string{"ops@example.test"}

	service := NewService(cfg, nil)
	if err := service.sendEmail("Critical alert", "Something needs attention.", map[string]any{"severity": "critical"}); err != nil {
		t.Fatalf("send email: %v", err)
	}

	message := <-received
	for _, want := range []string{
		"From: originpulse@example.test",
		"To: ops@example.test",
		"Subject: Critical alert",
		"Something needs attention.",
		"\"severity\": \"critical\"",
	} {
		if !strings.Contains(message, want) {
			t.Fatalf("message missing %q:\n%s", want, message)
		}
	}
}

func TestChannelsReportConfiguredTargets(t *testing.T) {
	cfg := config.Default()
	cfg.Notifications.Email.Enabled = true
	cfg.Notifications.Email.SMTPHost = "smtp.example.test"
	cfg.Notifications.Email.From = "originpulse@example.test"
	cfg.Notifications.Email.To = []string{"ops@example.test"}
	cfg.Notifications.Push.Enabled = true
	cfg.Notifications.Push.WebhookURLs = []string{"https://push.example.test/secret"}
	cfg.Notifications.Push.VAPIDPublicKey = "public"
	cfg.Notifications.Push.VAPIDPrivateKey = "private"

	service := NewService(cfg, nil)
	channels := service.channels()
	if len(channels) != 3 {
		t.Fatalf("channels = %d, want 3", len(channels))
	}
	if !channels[0].Configured {
		t.Fatal("email channel should be configured")
	}
	if !channels[1].Configured {
		t.Fatal("push channel should be configured")
	}
	if channels[1].Targets[0] != "https://push.example.test/..." {
		t.Fatalf("push target = %q, want redacted URL", channels[1].Targets[0])
	}
	if !channels[2].Configured {
		t.Fatal("web push channel should be configured")
	}
}

func TestChannelsReportMissingConfiguration(t *testing.T) {
	cfg := config.Default()
	cfg.Notifications.Email.Enabled = true
	cfg.Notifications.Email.SMTPHost = ""
	cfg.Notifications.Email.From = ""
	cfg.Notifications.Email.To = nil
	cfg.Notifications.Push.Enabled = true
	cfg.Notifications.Push.WebhookURLs = nil
	cfg.Notifications.Push.VAPIDPublicKey = ""
	cfg.Notifications.Push.VAPIDPrivateKey = ""

	service := NewService(cfg, nil)
	channels := service.channels()

	if channels[0].Configured {
		t.Fatal("email channel should not be configured")
	}
	for _, want := range []string{"notifications.email.smtp_host", "notifications.email.from", "notifications.email.to"} {
		if !containsString(channels[0].Missing, want) {
			t.Fatalf("email missing config should include %q: %#v", want, channels[0].Missing)
		}
	}
	if channels[1].Configured {
		t.Fatal("push channel should not be configured")
	}
	if !containsString(channels[1].Missing, "ORIGINPULSE_PUSH_WEBHOOK_URLS") {
		t.Fatalf("push missing config should include webhook env: %#v", channels[1].Missing)
	}
	if channels[2].Configured {
		t.Fatal("web push channel should not be configured")
	}
	for _, want := range []string{"ORIGINPULSE_VAPID_PUBLIC_KEY", "ORIGINPULSE_VAPID_PRIVATE_KEY"} {
		if !containsString(channels[2].Missing, want) {
			t.Fatalf("web push missing config should include %q: %#v", want, channels[2].Missing)
		}
	}
}

func TestNotificationWarningsExplainMissingTargets(t *testing.T) {
	warnings := notificationWarnings(true, []Channel{
		{Name: "email", Enabled: true, Configured: false},
		{Name: "push", Enabled: true, Configured: false},
		{Name: "web_push", Enabled: true, Configured: true},
	}, 0, 0)

	for _, want := range []string{
		"Email is enabled but SMTP host, sender, or recipients are missing.",
		"Webhook push is enabled but no webhook URLs are configured.",
		"Browser push is configured but no browsers are subscribed.",
		"No delivery targets are configured.",
	} {
		if !containsString(warnings, want) {
			t.Fatalf("warnings missing %q: %#v", want, warnings)
		}
	}
}

func TestNotificationWarningsReadyWhenTargetExists(t *testing.T) {
	warnings := notificationWarnings(true, []Channel{
		{Name: "email", Enabled: true, Configured: true, Targets: []string{"ops@example.test"}},
	}, 1, -1)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %#v, want none", warnings)
	}
}

func TestWebPushPayloadIsCompact(t *testing.T) {
	payload := webPushPayload("Alert title", strings.Repeat("x", 500), map[string]any{
		"alert": map[string]any{
			"id":       "alert-1",
			"severity": "critical",
		},
	})
	if payload["title"] != "Alert title" {
		t.Fatalf("title = %q", payload["title"])
	}
	if payload["tag"] != "alert-1" {
		t.Fatalf("tag = %q", payload["tag"])
	}
	if len(payload["body"].(string)) > 263 {
		t.Fatalf("body was not truncated: %d", len(payload["body"].(string)))
	}
}

func TestNormalizeRecentLimit(t *testing.T) {
	tests := []struct {
		name  string
		limit int
		want  int
	}{
		{name: "default", limit: 0, want: 25},
		{name: "negative", limit: -1, want: 25},
		{name: "keeps requested", limit: 250, want: 250},
		{name: "max", limit: RecentMaxLimit, want: RecentMaxLimit},
		{name: "clamped", limit: RecentMaxLimit + 1, want: RecentMaxLimit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeRecentLimit(tt.limit); got != tt.want {
				t.Fatalf("normalizeRecentLimit(%d) = %d, want %d", tt.limit, got, tt.want)
			}
		})
	}
}

func TestNormalizeRecentOffset(t *testing.T) {
	tests := []struct {
		name   string
		offset int
		want   int
	}{
		{name: "default", offset: 0, want: 0},
		{name: "negative", offset: -20, want: 0},
		{name: "keeps requested", offset: 40, want: 40},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeRecentOffset(tt.offset); got != tt.want {
				t.Fatalf("normalizeRecentOffset(%d) = %d, want %d", tt.offset, got, tt.want)
			}
		})
	}
}

func TestInsertPendingRetriesFailedAlertDelivery(t *testing.T) {
	ctx := context.Background()
	store := testNotificationStore(t, ctx)
	service := NewService(config.Default(), store)
	pool, err := store.Pool()
	if err != nil {
		t.Fatalf("pool: %v", err)
	}

	var alertID string
	now := time.Now().UTC()
	err = pool.QueryRow(ctx, `
INSERT INTO alerts (rule_key, title, severity, status, score, summary, first_seen_at, last_seen_at)
VALUES ($1, 'Retry delivery', 'critical', 'open', 90, 'retry test', $2, $2)
RETURNING id::text`, "notification_retry_test_"+strconv.FormatInt(now.UnixNano(), 10), now).Scan(&alertID)
	if err != nil {
		t.Fatalf("insert alert: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM alerts WHERE id = $1::uuid`, alertID)
	})

	first, inserted, err := service.insertPending(ctx, &alertID, "push", "https://push.example.test/hook", "critical", "First attempt", map[string]any{"try": 1})
	if err != nil || !inserted {
		t.Fatalf("first insert = inserted:%v err:%v", inserted, err)
	}
	if err := service.finish(ctx, first.ID, "failed", "temporary outage"); err != nil {
		t.Fatalf("finish failed: %v", err)
	}

	retry, inserted, err := service.insertPending(ctx, &alertID, "push", "https://push.example.test/hook", "critical", "Retry attempt", map[string]any{"try": 2})
	if err != nil || !inserted {
		t.Fatalf("retry insert = inserted:%v err:%v", inserted, err)
	}
	if retry.ID != first.ID {
		t.Fatalf("retry ID = %q, want existing delivery %q", retry.ID, first.ID)
	}
	if retry.Status != "pending" || retry.Error != "" || retry.Attempts != 1 {
		t.Fatalf("retry delivery = status:%q error:%q attempts:%d, want pending/no error/1 attempt", retry.Status, retry.Error, retry.Attempts)
	}
	if retry.Title != "Retry attempt" {
		t.Fatalf("retry title = %q, want updated title", retry.Title)
	}
	if err := service.finish(ctx, retry.ID, "sent", ""); err != nil {
		t.Fatalf("finish sent: %v", err)
	}

	_, inserted, err = service.insertPending(ctx, &alertID, "push", "https://push.example.test/hook", "critical", "Third attempt", map[string]any{"try": 3})
	if err != nil {
		t.Fatalf("third insert err: %v", err)
	}
	if inserted {
		t.Fatal("sent delivery should remain deduped")
	}
}

func testNotificationStore(t *testing.T, ctx context.Context) *db.Store {
	t.Helper()
	url := os.Getenv("ORIGINPULSE_TEST_DATABASE_URL")
	if strings.TrimSpace(url) == "" {
		t.Skip("ORIGINPULSE_TEST_DATABASE_URL is not set")
	}
	store, err := db.Open(ctx, config.DatabaseConfig{URL: url, MaxConns: 1})
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(store.Close)
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("migrate test database: %v", err)
	}
	return store
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func startFakeSMTP(t *testing.T) (string, <-chan string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen smtp: %v", err)
	}
	received := make(chan string, 1)
	done := make(chan struct{})

	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		write := func(value string) {
			_, _ = conn.Write([]byte(value))
		}
		write("220 localhost ESMTP\r\n")

		var data strings.Builder
		inData := false
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			upper := strings.ToUpper(line)
			switch {
			case inData && line == ".":
				inData = false
				received <- data.String()
				write("250 queued\r\n")
			case inData:
				data.WriteString(line)
				data.WriteString("\n")
			case strings.HasPrefix(upper, "EHLO") || strings.HasPrefix(upper, "HELO"):
				write("250-localhost\r\n250 OK\r\n")
			case strings.HasPrefix(upper, "MAIL FROM:"):
				write("250 sender ok\r\n")
			case strings.HasPrefix(upper, "RCPT TO:"):
				write("250 recipient ok\r\n")
			case upper == "DATA":
				write("354 end with dot\r\n")
				inData = true
			case upper == "QUIT":
				write("221 bye\r\n")
				return
			default:
				write("250 ok\r\n")
			}
		}
	}()

	return listener.Addr().String(), received, func() {
		_ = listener.Close()
		<-done
	}
}
