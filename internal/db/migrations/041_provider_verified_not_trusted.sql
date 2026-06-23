UPDATE ip_intel
SET verified_actor = false
WHERE provider_verified = true
  AND coalesce(manual_action, '') NOT IN ('allowlisted', 'verified');

UPDATE ip_intel
SET risk_score = greatest(coalesce(risk_score, 0), 55),
    is_datacenter = true
WHERE provider_verified = true
  AND lower(coalesce(actor_type, '')) IN ('cloud', 'datacenter')
  AND coalesce(manual_action, '') <> 'allowlisted';

UPDATE ip_intel
SET risk_score = greatest(coalesce(risk_score, 0), 45),
    is_datacenter = true
WHERE provider_verified = true
  AND lower(coalesce(actor_type, '')) = 'edge'
  AND coalesce(manual_action, '') <> 'allowlisted';

WITH pressure AS (
  SELECT client_ip,
         count(*)::bigint AS requests,
         count(*) FILTER (WHERE status >= 400)::bigint AS errors
  FROM access_events
  WHERE client_ip IS NOT NULL
  GROUP BY client_ip
)
UPDATE ip_intel ii
SET risk_score = greatest(coalesce(ii.risk_score, 0), 85)
FROM pressure p
WHERE ii.ip = p.client_ip
  AND p.requests >= 100
  AND p.errors >= 50
  AND p.errors::float8 / p.requests::float8 >= 0.80
  AND coalesce(ii.manual_action, '') <> 'allowlisted'
  AND (
    ii.provider_verified = true
    OR coalesce(ii.is_datacenter, false) = true
    OR lower(coalesce(ii.actor_type, '')) IN ('cloud', 'datacenter', 'edge', 'hosting', 'vps')
  );
