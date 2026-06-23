ALTER TABLE sites ADD COLUMN IF NOT EXISTS filename_masks text[] NOT NULL DEFAULT '{}';
