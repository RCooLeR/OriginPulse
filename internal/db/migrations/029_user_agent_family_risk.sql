ALTER TABLE dim_user_agents ADD COLUMN IF NOT EXISTS family text;
ALTER TABLE dim_user_agents ADD COLUMN IF NOT EXISTS risk_score integer;

CREATE INDEX IF NOT EXISTS dim_user_agents_family_idx ON dim_user_agents (family);
CREATE INDEX IF NOT EXISTS dim_user_agents_risk_idx ON dim_user_agents (risk_score DESC) WHERE risk_score IS NOT NULL;
