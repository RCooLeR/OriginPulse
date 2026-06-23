ALTER TABLE sites ADD COLUMN IF NOT EXISTS source_type text NOT NULL DEFAULT 'pantheon';
ALTER TABLE sites ADD COLUMN IF NOT EXISTS local_path text;

ALTER TABLE sites ALTER COLUMN pantheon_site_id DROP NOT NULL;

UPDATE sites
SET source_type = 'pantheon'
WHERE source_type IS NULL OR btrim(source_type) = '';

ALTER TABLE sites
ADD CONSTRAINT sites_source_type_check
CHECK (source_type IN ('pantheon', 'local')) NOT VALID;

ALTER TABLE sites VALIDATE CONSTRAINT sites_source_type_check;
