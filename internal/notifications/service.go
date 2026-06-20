package notifications

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/smtp"
	"net/url"
	"strings"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/jackc/pgx/v5"

	"originpulse/internal/config"
	"originpulse/internal/db"
)

type Result struct {
	Enabled     bool       `json:"enabled"`
	Evaluated   int        `json:"evaluated"`
	Sent        int        `json:"sent"`
	Skipped     int        `json:"skipped"`
	Failed      int        `json:"failed"`
	TargetCount int        `json:"target_count"`
	Message     string     `json:"message,omitempty"`
	Warnings    []string   `json:"warnings,omitempty"`
	Channels    []Channel  `json:"channels"`
	Items       []Delivery `json:"items"`
}

type Channel struct {
	Name       string   `json:"name"`
	Enabled    bool     `json:"enabled"`
	Configured bool     `json:"configured"`
	Targets    []string `json:"targets,omitempty"`
}

type Delivery struct {
	ID        string     `json:"id"`
	AlertID   string     `json:"alert_id,omitempty"`
	Channel   string     `json:"channel"`
	Target    string     `json:"target"`
	Status    string     `json:"status"`
	Severity  string     `json:"severity,omitempty"`
	Title     string     `json:"title,omitempty"`
	Error     string     `json:"error,omitempty"`
	Attempts  int        `json:"attempts"`
	CreatedAt time.Time  `json:"created_at"`
	SentAt    *time.Time `json:"sent_at,omitempty"`
}

type Status struct {
	Enabled     bool       `json:"enabled"`
	Ready       bool       `json:"ready"`
	MinSeverity string     `json:"min_severity"`
	TargetCount int        `json:"target_count"`
	Warnings    []string   `json:"warnings,omitempty"`
	Channels    []Channel  `json:"channels"`
	Recent      []Delivery `json:"recent"`
}

type WebPushStatus struct {
	Enabled             bool   `json:"enabled"`
	Configured          bool   `json:"configured"`
	PublicKey           string `json:"public_key,omitempty"`
	ActiveSubscriptions int    `json:"active_subscriptions"`
}

type WebPushSubscription struct {
	ID         string    `json:"id"`
	UserID     string    `json:"user_id,omitempty"`
	Endpoint   string    `json:"endpoint"`
	UserAgent  string    `json:"user_agent,omitempty"`
	IsActive   bool      `json:"is_active"`
	LastSeenAt time.Time `json:"last_seen_at"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type Service struct {
	cfg    config.Config
	db     *db.Store
	client *http.Client
}

type alertItem struct {
	ID         string         `json:"id"`
	RuleKey    string         `json:"rule_key"`
	Title      string         `json:"title"`
	Severity   string         `json:"severity"`
	SiteID     string         `json:"site_id,omitempty"`
	Env        string         `json:"env,omitempty"`
	ActorType  string         `json:"actor_type,omitempty"`
	ActorValue string         `json:"actor_value,omitempty"`
	Score      int            `json:"score,omitempty"`
	Summary    string         `json:"summary,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
	LastSeenAt time.Time      `json:"last_seen_at"`
}

type target struct {
	channel      string
	value        string
	subscription *webpush.Subscription
}

const RecentMaxLimit = 500

func NewService(cfg config.Config, store *db.Store) *Service {
	return &Service{
		cfg:    cfg,
		db:     store,
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

func (s *Service) Enabled() bool {
	return s != nil && s.db != nil && s.db.Enabled()
}

func (s *Service) Status(ctx context.Context, limit int) (Status, error) {
	recent, err := s.Recent(ctx, limit)
	if err != nil {
		return Status{}, err
	}
	channels := s.channels()
	targetCount := channelTargetCount(channels)
	activeWebPush := -1
	if count, err := s.activeWebPushCount(ctx); err == nil {
		activeWebPush = count
		targetCount += count
		for index := range channels {
			if channels[index].Name == "web_push" && s.browserPushConfigured() {
				channels[index].Targets = []string{fmt.Sprintf("%d active browser subscriptions", count)}
			}
		}
	} else if !errors.Is(err, db.ErrUnavailable) {
		return Status{}, err
	}
	warnings := notificationWarnings(s.cfg.Notifications.Enabled, channels, targetCount, activeWebPush)
	return Status{
		Enabled:     s.cfg.Notifications.Enabled,
		Ready:       s.cfg.Notifications.Enabled && targetCount > 0,
		MinSeverity: s.cfg.Notifications.MinSeverity,
		TargetCount: targetCount,
		Warnings:    warnings,
		Channels:    channels,
		Recent:      recent,
	}, nil
}

func (s *Service) NotifyOpenAlerts(ctx context.Context, limit int) (Result, error) {
	result := Result{
		Enabled:  s.cfg.Notifications.Enabled,
		Channels: s.channels(),
		Items:    []Delivery{},
	}
	if !s.cfg.Notifications.Enabled {
		result.Message = "Notifications are disabled."
		result.Warnings = notificationWarnings(result.Enabled, result.Channels, 0, -1)
		return result, nil
	}
	if !s.Enabled() {
		return result, db.ErrUnavailable
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	targets, err := s.targets(ctx)
	if err != nil {
		return result, err
	}
	result.TargetCount = len(targets)
	result.Warnings = notificationWarnings(result.Enabled, result.Channels, len(targets), -1)
	if len(targets) == 0 {
		result.Message = "No delivery targets are configured."
		return result, nil
	}

	alerts, err := s.openAlerts(ctx, limit)
	if err != nil {
		return result, err
	}
	for _, alert := range alerts {
		result.Evaluated++
		for _, target := range targets {
			delivery, inserted, err := s.insertPending(ctx, &alert.ID, target.channel, target.value, alert.Severity, alert.Title, alertPayload(alert))
			if err != nil {
				return result, err
			}
			if !inserted {
				result.Skipped++
				continue
			}
			err = s.send(ctx, target, alert.Title, alert.Summary, alertPayload(alert))
			if err != nil {
				result.Failed++
				delivery.Status = "failed"
				delivery.Error = err.Error()
				if updateErr := s.finish(ctx, delivery.ID, "failed", err.Error()); updateErr != nil {
					return result, updateErr
				}
			} else {
				result.Sent++
				delivery.Status = "sent"
				now := time.Now().UTC()
				delivery.SentAt = &now
				if updateErr := s.finish(ctx, delivery.ID, "sent", ""); updateErr != nil {
					return result, updateErr
				}
			}
			delivery.Target = redactTarget(delivery.Channel, delivery.Target)
			result.Items = append(result.Items, delivery)
		}
	}
	result.Message = fmt.Sprintf("Evaluated %d alert(s), sent %d, skipped %d, failed %d.", result.Evaluated, result.Sent, result.Skipped, result.Failed)
	return result, nil
}

func (s *Service) Test(ctx context.Context) (Result, error) {
	result := Result{
		Enabled:  s.cfg.Notifications.Enabled,
		Channels: s.channels(),
		Items:    []Delivery{},
	}
	if !s.cfg.Notifications.Enabled {
		result.Message = "Notifications are disabled."
		result.Warnings = notificationWarnings(result.Enabled, result.Channels, 0, -1)
		return result, nil
	}
	if !s.Enabled() {
		return result, db.ErrUnavailable
	}

	payload := map[string]any{
		"type":       "test",
		"service":    "OriginPulse",
		"created_at": time.Now().UTC(),
	}
	targets, err := s.targets(ctx)
	if err != nil {
		return result, err
	}
	result.TargetCount = len(targets)
	result.Warnings = notificationWarnings(result.Enabled, result.Channels, len(targets), -1)
	if len(targets) == 0 {
		result.Message = "No delivery targets are configured."
		return result, nil
	}
	for _, target := range targets {
		delivery, _, err := s.insertPending(ctx, nil, target.channel, target.value, "test", "OriginPulse test notification", payload)
		if err != nil {
			return result, err
		}
		err = s.send(ctx, target, "OriginPulse test notification", "Notification delivery is configured correctly.", payload)
		if err != nil {
			result.Failed++
			delivery.Status = "failed"
			delivery.Error = err.Error()
			if updateErr := s.finish(ctx, delivery.ID, "failed", err.Error()); updateErr != nil {
				return result, updateErr
			}
		} else {
			result.Sent++
			delivery.Status = "sent"
			now := time.Now().UTC()
			delivery.SentAt = &now
			if updateErr := s.finish(ctx, delivery.ID, "sent", ""); updateErr != nil {
				return result, updateErr
			}
		}
		delivery.Target = redactTarget(delivery.Channel, delivery.Target)
		result.Items = append(result.Items, delivery)
	}
	result.Message = fmt.Sprintf("Sent %d test notification(s), failed %d.", result.Sent, result.Failed)
	return result, nil
}

func (s *Service) Recent(ctx context.Context, limit int) ([]Delivery, error) {
	if !s.Enabled() {
		return []Delivery{}, nil
	}
	limit = normalizeRecentLimit(limit)
	pool, err := s.db.Pool()
	if err != nil {
		return nil, err
	}

	rows, err := pool.Query(ctx, `
SELECT id::text,
       coalesce(alert_id::text, ''),
       channel,
       target,
       status,
       coalesce(severity, ''),
       coalesce(title, ''),
       coalesce(error, ''),
       attempts,
       created_at,
       sent_at
FROM notification_deliveries
ORDER BY created_at DESC
LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]Delivery, 0, limit)
	for rows.Next() {
		var item Delivery
		if err := rows.Scan(
			&item.ID,
			&item.AlertID,
			&item.Channel,
			&item.Target,
			&item.Status,
			&item.Severity,
			&item.Title,
			&item.Error,
			&item.Attempts,
			&item.CreatedAt,
			&item.SentAt,
		); err != nil {
			return nil, err
		}
		item.Target = redactTarget(item.Channel, item.Target)
		items = append(items, item)
	}
	return items, rows.Err()
}

func normalizeRecentLimit(limit int) int {
	if limit <= 0 {
		return 25
	}
	if limit > RecentMaxLimit {
		return RecentMaxLimit
	}
	return limit
}

func (s *Service) WebPushStatus(ctx context.Context) (WebPushStatus, error) {
	status := WebPushStatus{
		Enabled:    s.cfg.Notifications.Enabled && s.cfg.Notifications.Push.Enabled,
		Configured: s.browserPushConfigured(),
		PublicKey:  s.cfg.PushVAPIDPublicKey(),
	}
	count, err := s.activeWebPushCount(ctx)
	if err != nil && !errors.Is(err, db.ErrUnavailable) {
		return WebPushStatus{}, err
	}
	status.ActiveSubscriptions = count
	return status, nil
}

func (s *Service) SaveWebPushSubscription(ctx context.Context, userID string, userAgent string, subscription webpush.Subscription) (WebPushSubscription, error) {
	if !s.Enabled() {
		return WebPushSubscription{}, db.ErrUnavailable
	}
	endpoint := strings.TrimSpace(subscription.Endpoint)
	p256dh := strings.TrimSpace(subscription.Keys.P256dh)
	authKey := strings.TrimSpace(subscription.Keys.Auth)
	if endpoint == "" || p256dh == "" || authKey == "" {
		return WebPushSubscription{}, errors.New("web push subscription must include endpoint, p256dh, and auth")
	}
	pool, err := s.db.Pool()
	if err != nil {
		return WebPushSubscription{}, err
	}

	var userArg any
	if strings.TrimSpace(userID) != "" {
		userArg = userID
	}
	var saved WebPushSubscription
	err = pool.QueryRow(ctx, `
INSERT INTO web_push_subscriptions (
  user_id, endpoint, p256dh, auth, user_agent, is_active, last_seen_at, updated_at
) VALUES (
  $1::uuid, $2, $3, $4, nullif($5, ''), true, now(), now()
)
ON CONFLICT (endpoint) DO UPDATE
SET user_id = coalesce(EXCLUDED.user_id, web_push_subscriptions.user_id),
    p256dh = EXCLUDED.p256dh,
    auth = EXCLUDED.auth,
    user_agent = EXCLUDED.user_agent,
    is_active = true,
    last_seen_at = now(),
    updated_at = now()
RETURNING id::text,
          coalesce(user_id::text, ''),
          endpoint,
          coalesce(user_agent, ''),
          is_active,
          last_seen_at,
          created_at,
          updated_at`,
		userArg,
		endpoint,
		p256dh,
		authKey,
		strings.TrimSpace(userAgent),
	).Scan(
		&saved.ID,
		&saved.UserID,
		&saved.Endpoint,
		&saved.UserAgent,
		&saved.IsActive,
		&saved.LastSeenAt,
		&saved.CreatedAt,
		&saved.UpdatedAt,
	)
	return saved, err
}

func (s *Service) DeleteWebPushSubscription(ctx context.Context, userID string, endpoint string) error {
	if !s.Enabled() {
		return db.ErrUnavailable
	}
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return errors.New("endpoint is required")
	}
	pool, err := s.db.Pool()
	if err != nil {
		return err
	}
	var userArg any
	if strings.TrimSpace(userID) != "" {
		userArg = userID
	}
	_, err = pool.Exec(ctx, `
UPDATE web_push_subscriptions
SET is_active = false,
    updated_at = now()
WHERE endpoint = $1
  AND ($2::uuid IS NULL OR user_id = $2::uuid OR user_id IS NULL)`, endpoint, userArg)
	return err
}

func (s *Service) openAlerts(ctx context.Context, limit int) ([]alertItem, error) {
	pool, err := s.db.Pool()
	if err != nil {
		return nil, err
	}
	rows, err := pool.Query(ctx, `
SELECT id::text,
       rule_key,
       title,
       severity,
       coalesce(site_id, ''),
       coalesce(env, ''),
       coalesce(actor_type, ''),
       coalesce(actor_value, ''),
       coalesce(score, 0),
       coalesce(summary, ''),
       details::text,
       last_seen_at
FROM alerts
WHERE status = 'open'
  AND CASE severity
    WHEN 'critical' THEN 4
    WHEN 'high' THEN 3
    WHEN 'medium' THEN 2
    WHEN 'low' THEN 1
    ELSE 0
  END >= $1
ORDER BY
  CASE severity
    WHEN 'critical' THEN 4
    WHEN 'high' THEN 3
    WHEN 'medium' THEN 2
    WHEN 'low' THEN 1
    ELSE 0
  END DESC,
  last_seen_at DESC
LIMIT $2`, severityRank(s.cfg.Notifications.MinSeverity), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	alerts := make([]alertItem, 0, limit)
	for rows.Next() {
		var item alertItem
		var detailsRaw string
		if err := rows.Scan(
			&item.ID,
			&item.RuleKey,
			&item.Title,
			&item.Severity,
			&item.SiteID,
			&item.Env,
			&item.ActorType,
			&item.ActorValue,
			&item.Score,
			&item.Summary,
			&detailsRaw,
			&item.LastSeenAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(detailsRaw), &item.Details)
		alerts = append(alerts, item)
	}
	return alerts, rows.Err()
}

func (s *Service) insertPending(ctx context.Context, alertID *string, channel string, target string, severity string, title string, payload map[string]any) (Delivery, bool, error) {
	pool, err := s.db.Pool()
	if err != nil {
		return Delivery{}, false, err
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return Delivery{}, false, err
	}

	var alertArg any
	if alertID != nil && strings.TrimSpace(*alertID) != "" {
		alertArg = *alertID
	}

	var delivery Delivery
	err = pool.QueryRow(ctx, `
INSERT INTO notification_deliveries (
  alert_id, channel, target, status, severity, title, payload
) VALUES (
  $1::uuid, $2, $3, 'pending', $4, $5, $6::jsonb
)
ON CONFLICT (alert_id, channel, target) WHERE alert_id IS NOT NULL DO NOTHING
RETURNING id::text,
          coalesce(alert_id::text, ''),
          channel,
          target,
          status,
          coalesce(severity, ''),
          coalesce(title, ''),
          coalesce(error, ''),
          attempts,
          created_at,
          sent_at`,
		alertArg,
		channel,
		target,
		emptyToNil(severity),
		emptyToNil(title),
		string(payloadJSON),
	).Scan(
		&delivery.ID,
		&delivery.AlertID,
		&delivery.Channel,
		&delivery.Target,
		&delivery.Status,
		&delivery.Severity,
		&delivery.Title,
		&delivery.Error,
		&delivery.Attempts,
		&delivery.CreatedAt,
		&delivery.SentAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Delivery{}, false, nil
	}
	return delivery, err == nil, err
}

func (s *Service) finish(ctx context.Context, id string, status string, errorMessage string) error {
	pool, err := s.db.Pool()
	if err != nil {
		return err
	}
	_, err = pool.Exec(ctx, `
UPDATE notification_deliveries
SET status = $2,
    error = nullif($3, ''),
    attempts = attempts + 1,
    sent_at = CASE WHEN $2 = 'sent' THEN now() ELSE sent_at END
WHERE id = $1`, id, status, errorMessage)
	return err
}

func (s *Service) send(ctx context.Context, target target, title string, body string, payload map[string]any) error {
	switch target.channel {
	case "email":
		return s.sendEmail(title, body, payload)
	case "push":
		return s.sendPush(ctx, target.value, title, body, payload)
	case "web_push":
		return s.sendWebPush(ctx, target, title, body, payload)
	default:
		return fmt.Errorf("unsupported notification channel %q", target.channel)
	}
}

func (s *Service) sendEmail(title string, body string, payload map[string]any) error {
	email := s.cfg.Notifications.Email
	host := strings.TrimSpace(email.SMTPHost)
	if host == "" || email.SMTPPort <= 0 {
		return errors.New("SMTP host/port is not configured")
	}
	from := strings.TrimSpace(email.From)
	recipients := cleanStrings(email.To)
	if from == "" || len(recipients) == 0 {
		return errors.New("email from/to is not configured")
	}

	var auth smtp.Auth
	username := s.cfg.SMTPUsername()
	password := s.cfg.SMTPPassword()
	if username != "" || password != "" {
		auth = smtp.PlainAuth("", username, password, host)
	}

	subject := strings.TrimSpace(title)
	if subject == "" {
		subject = "OriginPulse notification"
	}
	text := strings.TrimSpace(body)
	if text == "" {
		text = subject
	}
	payloadJSON, _ := json.MarshalIndent(payload, "", "  ")
	message := strings.Join([]string{
		"From: " + from,
		"To: " + strings.Join(recipients, ", "),
		"Subject: " + sanitizeHeader(subject),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"",
		text,
		"",
		string(payloadJSON),
	}, "\r\n")
	return smtp.SendMail(fmt.Sprintf("%s:%d", host, email.SMTPPort), auth, from, recipients, []byte(message))
}

func (s *Service) sendPush(ctx context.Context, rawURL string, title string, body string, payload map[string]any) error {
	pushBody := map[string]any{
		"title":   title,
		"body":    body,
		"payload": payload,
		"source":  "originpulse",
	}
	bodyBytes, err := json.Marshal(pushBody)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("push endpoint returned %s", resp.Status)
	}
	return nil
}

func (s *Service) sendWebPush(ctx context.Context, target target, title string, body string, payload map[string]any) error {
	if target.subscription == nil {
		return errors.New("web push subscription is missing")
	}
	message, err := json.Marshal(webPushPayload(title, body, payload))
	if err != nil {
		return err
	}
	resp, err := webpush.SendNotificationWithContext(ctx, message, target.subscription, &webpush.Options{
		HTTPClient:      s.client,
		Subscriber:      s.cfg.PushVAPIDSubject(),
		TTL:             3600,
		Urgency:         webpush.UrgencyHigh,
		VAPIDPublicKey:  s.cfg.PushVAPIDPublicKey(),
		VAPIDPrivateKey: s.cfg.PushVAPIDPrivateKey(),
	})
	if resp != nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusGone || resp.StatusCode == http.StatusNotFound {
			_ = s.deactivateWebPushEndpoint(context.Background(), target.value)
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return fmt.Errorf("web push endpoint returned %s", resp.Status)
		}
	}
	return err
}

func (s *Service) channels() []Channel {
	email := s.cfg.Notifications.Email
	pushURLs := s.cfg.PushWebhookURLs()
	return []Channel{
		{
			Name:       "email",
			Enabled:    email.Enabled,
			Configured: email.Enabled && strings.TrimSpace(email.SMTPHost) != "" && strings.TrimSpace(email.From) != "" && len(cleanStrings(email.To)) > 0,
			Targets:    cleanStrings(email.To),
		},
		{
			Name:       "push",
			Enabled:    s.cfg.Notifications.Push.Enabled,
			Configured: s.cfg.Notifications.Push.Enabled && len(pushURLs) > 0,
			Targets:    redactTargets("push", pushURLs),
		},
		{
			Name:       "web_push",
			Enabled:    s.cfg.Notifications.Push.Enabled,
			Configured: s.cfg.Notifications.Push.Enabled && s.browserPushConfigured(),
		},
	}
}

func channelTargetCount(channels []Channel) int {
	count := 0
	for _, channel := range channels {
		if channel.Name == "web_push" {
			continue
		}
		if channel.Enabled && channel.Configured {
			count += len(channel.Targets)
		}
	}
	return count
}

func notificationWarnings(enabled bool, channels []Channel, targetCount int, activeWebPush int) []string {
	warnings := []string{}
	if !enabled {
		return append(warnings, "Notifications are disabled.")
	}

	for _, channel := range channels {
		if !channel.Enabled {
			continue
		}
		if channel.Configured {
			continue
		}
		switch channel.Name {
		case "email":
			warnings = append(warnings, "Email is enabled but SMTP host, sender, or recipients are missing.")
		case "push":
			warnings = append(warnings, "Webhook push is enabled but no webhook URLs are configured.")
		case "web_push":
			if targetCount == 0 {
				warnings = append(warnings, "Browser push is enabled but VAPID public key, private key, or subject is missing.")
			}
		default:
			warnings = append(warnings, fmt.Sprintf("%s is enabled but not configured.", formatChannelName(channel.Name)))
		}
	}
	if activeWebPush == 0 {
		warnings = append(warnings, "Browser push is configured but no browsers are subscribed.")
	}
	if targetCount == 0 {
		warnings = append(warnings, "No delivery targets are configured.")
	}
	return dedupeStrings(warnings)
}

func formatChannelName(value string) string {
	value = strings.ReplaceAll(value, "_", " ")
	if value == "" {
		return "channel"
	}
	return value
}

func dedupeStrings(values []string) []string {
	seen := map[string]struct{}{}
	deduped := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		deduped = append(deduped, value)
	}
	return deduped
}

func (s *Service) targets(ctx context.Context) ([]target, error) {
	targets := []target{}
	if s.cfg.Notifications.Email.Enabled {
		email := s.cfg.Notifications.Email
		if strings.TrimSpace(email.SMTPHost) != "" && strings.TrimSpace(email.From) != "" {
			for _, recipient := range cleanStrings(email.To) {
				targets = append(targets, target{channel: "email", value: recipient})
			}
		}
	}
	if s.cfg.Notifications.Push.Enabled {
		for _, webhookURL := range s.cfg.PushWebhookURLs() {
			targets = append(targets, target{channel: "push", value: webhookURL})
		}
		if s.browserPushConfigured() {
			subscriptions, err := s.activeWebPushSubscriptions(ctx)
			if err != nil {
				return nil, err
			}
			for _, subscription := range subscriptions {
				sub := subscription.Subscription
				targets = append(targets, target{
					channel:      "web_push",
					value:        sub.Endpoint,
					subscription: &sub,
				})
			}
		}
	}
	return targets, nil
}

func alertPayload(alert alertItem) map[string]any {
	title := alert.Title
	if title == "" {
		title = alert.RuleKey
	}
	return map[string]any{
		"type":       "alert",
		"service":    "OriginPulse",
		"created_at": time.Now().UTC(),
		"alert": map[string]any{
			"id":           alert.ID,
			"rule_key":     alert.RuleKey,
			"title":        title,
			"severity":     alert.Severity,
			"site_id":      alert.SiteID,
			"env":          alert.Env,
			"actor_type":   alert.ActorType,
			"actor_value":  alert.ActorValue,
			"score":        alert.Score,
			"summary":      alert.Summary,
			"details":      alert.Details,
			"last_seen_at": alert.LastSeenAt,
		},
	}
}

func severityRank(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 3
	}
}

func cleanStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func redactTargets(channel string, values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, redactTarget(channel, value))
	}
	return out
}

func redactTarget(channel string, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if channel == "push" || channel == "web_push" {
		parsed, err := url.Parse(value)
		if err == nil && parsed.Host != "" {
			return parsed.Scheme + "://" + parsed.Host + "/..."
		}
	}
	return value
}

type activeWebPushSubscription struct {
	Subscription webpush.Subscription
}

func (s *Service) browserPushConfigured() bool {
	return strings.TrimSpace(s.cfg.PushVAPIDPublicKey()) != "" &&
		strings.TrimSpace(s.cfg.PushVAPIDPrivateKey()) != "" &&
		strings.TrimSpace(s.cfg.PushVAPIDSubject()) != ""
}

func (s *Service) activeWebPushCount(ctx context.Context) (int, error) {
	if !s.Enabled() {
		return 0, db.ErrUnavailable
	}
	pool, err := s.db.Pool()
	if err != nil {
		return 0, err
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*)::int FROM web_push_subscriptions WHERE is_active = true`).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *Service) activeWebPushSubscriptions(ctx context.Context) ([]activeWebPushSubscription, error) {
	if !s.Enabled() {
		return nil, db.ErrUnavailable
	}
	pool, err := s.db.Pool()
	if err != nil {
		return nil, err
	}
	rows, err := pool.Query(ctx, `
SELECT endpoint, p256dh, auth
FROM web_push_subscriptions
WHERE is_active = true
ORDER BY updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	subscriptions := []activeWebPushSubscription{}
	for rows.Next() {
		var sub activeWebPushSubscription
		if err := rows.Scan(&sub.Subscription.Endpoint, &sub.Subscription.Keys.P256dh, &sub.Subscription.Keys.Auth); err != nil {
			return nil, err
		}
		subscriptions = append(subscriptions, sub)
	}
	return subscriptions, rows.Err()
}

func (s *Service) deactivateWebPushEndpoint(ctx context.Context, endpoint string) error {
	if !s.Enabled() {
		return db.ErrUnavailable
	}
	pool, err := s.db.Pool()
	if err != nil {
		return err
	}
	_, err = pool.Exec(ctx, `
UPDATE web_push_subscriptions
SET is_active = false,
    updated_at = now()
WHERE endpoint = $1`, endpoint)
	return err
}

func webPushPayload(title string, body string, payload map[string]any) map[string]any {
	severity := ""
	alertID := ""
	if alert, ok := payload["alert"].(map[string]any); ok {
		if value, ok := alert["severity"].(string); ok {
			severity = value
		}
		if value, ok := alert["id"].(string); ok {
			alertID = value
		}
	}
	return map[string]any{
		"title":      defaultString(title, "OriginPulse notification"),
		"body":       truncate(defaultString(body, "Open OriginPulse for details."), 260),
		"url":        "/alerts",
		"tag":        defaultString(alertID, "originpulse-notification"),
		"severity":   severity,
		"created_at": time.Now().UTC(),
	}
}

func defaultString(value string, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func truncate(value string, limit int) string {
	value = strings.TrimSpace(value)
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return strings.TrimSpace(value[:limit-1]) + "..."
}

func sanitizeHeader(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return strings.TrimSpace(value)
}

func emptyToNil(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}
