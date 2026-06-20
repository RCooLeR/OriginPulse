ALTER TABLE security_probe_events ADD COLUMN IF NOT EXISTS temporary_import_id uuid;

UPDATE security_probe_events f
SET temporary_import_id = e.temporary_import_id
FROM access_events e
WHERE f.event_id = e.id
  AND f.temporary_import_id IS NULL
  AND e.temporary_import_id IS NOT NULL;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'security_probe_events_event_id_fkey') THEN
    ALTER TABLE security_probe_events DROP CONSTRAINT security_probe_events_event_id_fkey;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'security_probe_events_segment_id_fkey') THEN
    ALTER TABLE security_probe_events DROP CONSTRAINT security_probe_events_segment_id_fkey;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'security_probe_events_temporary_import_id_fkey') THEN
    ALTER TABLE security_probe_events
      ADD CONSTRAINT security_probe_events_temporary_import_id_fkey
      FOREIGN KEY (temporary_import_id) REFERENCES temporary_imports(id) ON DELETE SET NULL;
  END IF;
END $$;

ALTER TABLE security_probe_events ALTER COLUMN event_id DROP NOT NULL;

ALTER TABLE security_probe_events
  ADD CONSTRAINT security_probe_events_event_id_fkey
  FOREIGN KEY (event_id) REFERENCES access_events(id) ON DELETE SET NULL;

ALTER TABLE security_probe_events
  ADD CONSTRAINT security_probe_events_segment_id_fkey
  FOREIGN KEY (segment_id) REFERENCES combined_segments(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS security_probe_events_temporary_import_idx
  ON security_probe_events (temporary_import_id)
  WHERE temporary_import_id IS NOT NULL;

ALTER TABLE error_events ADD COLUMN IF NOT EXISTS id bigserial;
ALTER TABLE slow_request_events ADD COLUMN IF NOT EXISTS id bigserial;

UPDATE error_events
SET id = nextval(pg_get_serial_sequence('error_events', 'id'))
WHERE id IS NULL;

UPDATE slow_request_events
SET id = nextval(pg_get_serial_sequence('slow_request_events', 'id'))
WHERE id IS NULL;

ALTER TABLE error_events ALTER COLUMN id SET NOT NULL;
ALTER TABLE slow_request_events ALTER COLUMN id SET NOT NULL;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'error_events_pkey') THEN
    ALTER TABLE error_events DROP CONSTRAINT error_events_pkey;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'error_events_event_id_fkey') THEN
    ALTER TABLE error_events DROP CONSTRAINT error_events_event_id_fkey;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'error_events_event_id_key') THEN
    ALTER TABLE error_events ADD CONSTRAINT error_events_event_id_key UNIQUE (event_id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'error_events_pkey') THEN
    ALTER TABLE error_events ADD CONSTRAINT error_events_pkey PRIMARY KEY (id);
  END IF;
END $$;

ALTER TABLE error_events ALTER COLUMN event_id DROP NOT NULL;

ALTER TABLE error_events
  ADD CONSTRAINT error_events_event_id_fkey
  FOREIGN KEY (event_id) REFERENCES access_events(id) ON DELETE SET NULL;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'slow_request_events_pkey') THEN
    ALTER TABLE slow_request_events DROP CONSTRAINT slow_request_events_pkey;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'slow_request_events_event_id_fkey') THEN
    ALTER TABLE slow_request_events DROP CONSTRAINT slow_request_events_event_id_fkey;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'slow_request_events_event_id_key') THEN
    ALTER TABLE slow_request_events ADD CONSTRAINT slow_request_events_event_id_key UNIQUE (event_id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'slow_request_events_pkey') THEN
    ALTER TABLE slow_request_events ADD CONSTRAINT slow_request_events_pkey PRIMARY KEY (id);
  END IF;
END $$;

ALTER TABLE slow_request_events ALTER COLUMN event_id DROP NOT NULL;

ALTER TABLE slow_request_events
  ADD CONSTRAINT slow_request_events_event_id_fkey
  FOREIGN KEY (event_id) REFERENCES access_events(id) ON DELETE SET NULL;
