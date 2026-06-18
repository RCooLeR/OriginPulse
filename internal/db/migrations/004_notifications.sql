CREATE TABLE IF NOT EXISTS notification_deliveries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  alert_id uuid REFERENCES alerts(id) ON DELETE CASCADE,
  channel text NOT NULL,
  target text NOT NULL,
  status text NOT NULL,
  severity text,
  title text,
  payload jsonb NOT NULL DEFAULT '{}',
  error text,
  attempts int NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  sent_at timestamptz
);

CREATE UNIQUE INDEX IF NOT EXISTS notification_deliveries_alert_target_idx
  ON notification_deliveries (alert_id, channel, target)
  WHERE alert_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS notification_deliveries_status_idx
  ON notification_deliveries (status, created_at DESC);

CREATE INDEX IF NOT EXISTS notification_deliveries_created_idx
  ON notification_deliveries (created_at DESC);
