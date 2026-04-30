-- ============================================================
-- KAVACH — Complete Supabase Database Schema
-- National Intelligence Platform · CID Karnataka
-- ============================================================

-- ── Extensions ───────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================
-- TABLE: users
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
  id              UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  badge_number    TEXT          NOT NULL UNIQUE,
  full_name       TEXT          NOT NULL,
  rank            TEXT          NOT NULL DEFAULT 'Officer',
  department      TEXT,
  email           TEXT          UNIQUE,
  phone           TEXT,
  password_hash   TEXT          NOT NULL,
  role            TEXT          NOT NULL DEFAULT 'operator'
                                CHECK (role IN ('admin', 'operator', 'investigator', 'analyst', 'auditor')),
  is_active       BOOLEAN       NOT NULL DEFAULT TRUE,
  last_login_at   TIMESTAMPTZ,
  avatar_url      TEXT,
  created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_badge       ON users (badge_number);
CREATE INDEX idx_users_role        ON users (role);
CREATE INDEX idx_users_is_active   ON users (is_active);

-- ============================================================
-- TABLE: documents
-- ============================================================
CREATE TABLE IF NOT EXISTS documents (
  id              UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  uploaded_by     UUID          NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  file_name       TEXT          NOT NULL,
  file_path       TEXT          NOT NULL,
  file_size_bytes BIGINT,
  mime_type       TEXT,
  doc_type        TEXT          NOT NULL DEFAULT 'unknown'
                                CHECK (doc_type IN ('aadhaar', 'passport', 'voter_id', 'pan', 'license', 'fir', 'evidence', 'unknown')),
  sha256_hash     TEXT          NOT NULL UNIQUE,
  status          TEXT          NOT NULL DEFAULT 'pending'
                                CHECK (status IN ('pending', 'verified', 'flagged', 'forged', 'inconclusive')),
  ocr_text        TEXT,
  metadata        JSONB         DEFAULT '{}',
  created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_documents_uploaded_by ON documents (uploaded_by);
CREATE INDEX idx_documents_status      ON documents (status);
CREATE INDEX idx_documents_doc_type    ON documents (doc_type);
CREATE INDEX idx_documents_sha256      ON documents (sha256_hash);
CREATE INDEX idx_documents_created_at  ON documents (created_at DESC);

-- ============================================================
-- TABLE: document_verifications
-- ============================================================
CREATE TABLE IF NOT EXISTS document_verifications (
  id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  document_id         UUID        NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  verified_by         UUID        REFERENCES users(id) ON DELETE SET NULL,
  verification_method TEXT        NOT NULL DEFAULT 'ela'
                                  CHECK (verification_method IN ('ela', 'ocr', 'hash', 'ai_model', 'manual', 'combined')),
  verdict             TEXT        NOT NULL
                                  CHECK (verdict IN ('authentic', 'forged', 'inconclusive', 'flagged')),
  confidence_score    NUMERIC(5,2) CHECK (confidence_score BETWEEN 0 AND 100),
  ela_score           NUMERIC(5,2),
  ocr_match_score     NUMERIC(5,2),
  model_version       TEXT,
  anomalies           JSONB       DEFAULT '[]',
  report_url          TEXT,
  notes               TEXT,
  processing_ms       INTEGER,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_docver_document_id  ON document_verifications (document_id);
CREATE INDEX idx_docver_verdict      ON document_verifications (verdict);
CREATE INDEX idx_docver_created_at   ON document_verifications (created_at DESC);

-- ============================================================
-- TABLE: firs
-- ============================================================
CREATE TABLE IF NOT EXISTS firs (
  id                UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  fir_number        TEXT          NOT NULL UNIQUE,
  station_code      TEXT          NOT NULL,
  district          TEXT          NOT NULL,
  state             TEXT          NOT NULL DEFAULT 'Karnataka',
  filed_by          UUID          NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  assigned_to       UUID          REFERENCES users(id) ON DELETE SET NULL,
  complainant_name  TEXT          NOT NULL,
  complainant_phone TEXT,
  incident_date     DATE          NOT NULL,
  incident_location TEXT          NOT NULL,
  incident_lat      DOUBLE PRECISION,
  incident_lng      DOUBLE PRECISION,
  category          TEXT          NOT NULL
                                  CHECK (category IN ('theft', 'assault', 'cyber_crime', 'fraud', 'missing_person', 'arms', 'drugs', 'homicide', 'terrorism', 'other')),
  severity          TEXT          NOT NULL DEFAULT 'medium'
                                  CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  status            TEXT          NOT NULL DEFAULT 'open'
                                  CHECK (status IN ('open', 'under_investigation', 'closed', 'chargesheet_filed', 'court_referred')),
  description       TEXT          NOT NULL,
  sections          TEXT[],
  suspect_details   JSONB         DEFAULT '[]',
  evidence_links    UUID[],
  blockchain_hash   TEXT,
  is_sealed         BOOLEAN       NOT NULL DEFAULT FALSE,
  created_at        TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  updated_at        TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_firs_fir_number    ON firs (fir_number);
CREATE INDEX idx_firs_filed_by      ON firs (filed_by);
CREATE INDEX idx_firs_assigned_to   ON firs (assigned_to);
CREATE INDEX idx_firs_status        ON firs (status);
CREATE INDEX idx_firs_severity      ON firs (severity);
CREATE INDEX idx_firs_category      ON firs (category);
CREATE INDEX idx_firs_created_at    ON firs (created_at DESC);
CREATE INDEX idx_firs_incident_date ON firs (incident_date DESC);

-- ============================================================
-- TABLE: fir_versions  (immutable audit trail)
-- ============================================================
CREATE TABLE IF NOT EXISTS fir_versions (
  id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  fir_id          UUID        NOT NULL REFERENCES firs(id) ON DELETE CASCADE,
  version_number  INTEGER     NOT NULL DEFAULT 1,
  changed_by      UUID        NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  change_type     TEXT        NOT NULL
                              CHECK (change_type IN ('created', 'updated', 'status_change', 'sealed', 'evidence_added', 'assigned')),
  diff_snapshot   JSONB       NOT NULL DEFAULT '{}',
  change_summary  TEXT,
  ip_address      INET,
  user_agent      TEXT,
  blockchain_tx   TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  UNIQUE (fir_id, version_number)
);

CREATE INDEX idx_firver_fir_id     ON fir_versions (fir_id);
CREATE INDEX idx_firver_changed_by ON fir_versions (changed_by);
CREATE INDEX idx_firver_created_at ON fir_versions (created_at DESC);

-- ============================================================
-- TABLE: blockchain_records
-- ============================================================
CREATE TABLE IF NOT EXISTS blockchain_records (
  id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  record_type     TEXT        NOT NULL
                              CHECK (record_type IN ('fir', 'fir_version', 'document', 'verification', 'evidence', 'custody')),
  reference_id    UUID        NOT NULL,
  tx_hash         TEXT        NOT NULL UNIQUE,
  block_number    BIGINT,
  block_hash      TEXT,
  contract_addr   TEXT,
  network         TEXT        NOT NULL DEFAULT 'localhost',
  data_hash       TEXT        NOT NULL,
  gas_used        BIGINT,
  status          TEXT        NOT NULL DEFAULT 'pending'
                              CHECK (status IN ('pending', 'confirmed', 'failed', 'orphaned')),
  confirmations   INTEGER     NOT NULL DEFAULT 0,
  anchored_at     TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_blockchain_reference_id ON blockchain_records (reference_id);
CREATE INDEX idx_blockchain_tx_hash      ON blockchain_records (tx_hash);
CREATE INDEX idx_blockchain_record_type  ON blockchain_records (record_type);
CREATE INDEX idx_blockchain_status       ON blockchain_records (status);
CREATE INDEX idx_blockchain_created_at   ON blockchain_records (created_at DESC);

-- ============================================================
-- TABLE: network_logs
-- ============================================================
CREATE TABLE IF NOT EXISTS network_logs (
  id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  source_ip       INET        NOT NULL,
  destination_ip  INET,
  source_port     INTEGER     CHECK (source_port BETWEEN 0 AND 65535),
  destination_port INTEGER    CHECK (destination_port BETWEEN 0 AND 65535),
  protocol        TEXT        NOT NULL DEFAULT 'TCP'
                              CHECK (protocol IN ('TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'SMTP', 'FTP', 'SSH', 'OTHER')),
  bytes_sent      BIGINT      DEFAULT 0,
  bytes_received  BIGINT      DEFAULT 0,
  duration_ms     INTEGER,
  action          TEXT        NOT NULL DEFAULT 'allow'
                              CHECK (action IN ('allow', 'block', 'alert', 'quarantine')),
  threat_type     TEXT,
  threat_score    NUMERIC(5,2) CHECK (threat_score BETWEEN 0 AND 100),
  geo_country     TEXT,
  geo_city        TEXT,
  isp             TEXT,
  asn             TEXT,
  user_id         UUID        REFERENCES users(id) ON DELETE SET NULL,
  device_id       TEXT,
  tags            TEXT[],
  raw_payload     JSONB       DEFAULT '{}',
  logged_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_netlogs_source_ip   ON network_logs (source_ip);
CREATE INDEX idx_netlogs_action      ON network_logs (action);
CREATE INDEX idx_netlogs_threat_type ON network_logs (threat_type);
CREATE INDEX idx_netlogs_logged_at   ON network_logs (logged_at DESC);
CREATE INDEX idx_netlogs_threat_score ON network_logs (threat_score DESC NULLS LAST);

-- Partition hint: for production, partition by logged_at range (monthly)

-- ============================================================
-- TABLE: alerts
-- ============================================================
CREATE TABLE IF NOT EXISTS alerts (
  id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  source_module   TEXT        NOT NULL
                              CHECK (source_module IN ('crowd_sentinel', 'deep_trace', 'doc_guard', 'fir_warden', 'net_watch', 'system')),
  alert_type      TEXT        NOT NULL,
  severity        TEXT        NOT NULL DEFAULT 'medium'
                              CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  title           TEXT        NOT NULL,
  description     TEXT,
  reference_id    UUID,
  reference_type  TEXT,
  threat_score    NUMERIC(5,2),
  location        TEXT,
  lat             DOUBLE PRECISION,
  lng             DOUBLE PRECISION,
  status          TEXT        NOT NULL DEFAULT 'open'
                              CHECK (status IN ('open', 'acknowledged', 'investigating', 'resolved', 'false_positive', 'escalated')),
  acknowledged_by UUID        REFERENCES users(id) ON DELETE SET NULL,
  acknowledged_at TIMESTAMPTZ,
  resolved_by     UUID        REFERENCES users(id) ON DELETE SET NULL,
  resolved_at     TIMESTAMPTZ,
  resolution_note TEXT,
  metadata        JSONB       DEFAULT '{}',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_alerts_source_module ON alerts (source_module);
CREATE INDEX idx_alerts_severity      ON alerts (severity);
CREATE INDEX idx_alerts_status        ON alerts (status);
CREATE INDEX idx_alerts_created_at    ON alerts (created_at DESC);
CREATE INDEX idx_alerts_reference_id  ON alerts (reference_id);

-- ============================================================
-- TABLE: events  (alert → events chain)
-- ============================================================
CREATE TABLE IF NOT EXISTS events (
  id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  alert_id        UUID        REFERENCES alerts(id) ON DELETE CASCADE,
  event_type      TEXT        NOT NULL,
  actor_id        UUID        REFERENCES users(id) ON DELETE SET NULL,
  actor_module    TEXT,
  summary         TEXT        NOT NULL,
  detail          JSONB       DEFAULT '{}',
  severity        TEXT        NOT NULL DEFAULT 'info'
                              CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  source_ip       INET,
  tags            TEXT[],
  occurred_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_events_alert_id    ON events (alert_id);
CREATE INDEX idx_events_event_type  ON events (event_type);
CREATE INDEX idx_events_actor_id    ON events (actor_id);
CREATE INDEX idx_events_occurred_at ON events (occurred_at DESC);

-- ============================================================
-- TRIGGERS: updated_at auto-refresh
-- ============================================================
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_users_updated_at
  BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_documents_updated_at
  BEFORE UPDATE ON documents
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_firs_updated_at
  BEFORE UPDATE ON firs
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_blockchain_updated_at
  BEFORE UPDATE ON blockchain_records
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_alerts_updated_at
  BEFORE UPDATE ON alerts
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ============================================================
-- TRIGGER: auto-create fir_version on every FIR update
-- ============================================================
CREATE OR REPLACE FUNCTION fir_audit_version()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
  v_num INTEGER;
BEGIN
  SELECT COALESCE(MAX(version_number), 0) + 1
    INTO v_num
    FROM fir_versions
   WHERE fir_id = NEW.id;

  INSERT INTO fir_versions (
    fir_id, version_number, changed_by,
    change_type, diff_snapshot, change_summary
  ) VALUES (
    NEW.id, v_num, NEW.filed_by,
    CASE WHEN TG_OP = 'INSERT' THEN 'created' ELSE 'updated' END,
    to_jsonb(NEW),
    TG_OP || ' at ' || NOW()
  );
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_fir_version
  AFTER INSERT OR UPDATE ON firs
  FOR EACH ROW EXECUTE FUNCTION fir_audit_version();

-- ============================================================
-- VIEWS
-- ============================================================

-- Dashboard summary
CREATE OR REPLACE VIEW v_dashboard_stats AS
SELECT
  (SELECT COUNT(*) FROM alerts  WHERE status = 'open')                   AS open_alerts,
  (SELECT COUNT(*) FROM alerts  WHERE severity = 'critical'
                               AND created_at > NOW() - INTERVAL '24h') AS critical_24h,
  (SELECT COUNT(*) FROM firs    WHERE status = 'open')                   AS open_firs,
  (SELECT COUNT(*) FROM firs    WHERE created_at > NOW() - INTERVAL '24h') AS firs_today,
  (SELECT COUNT(*) FROM documents WHERE status = 'pending')              AS pending_docs,
  (SELECT COUNT(*) FROM documents WHERE status = 'flagged')              AS flagged_docs,
  (SELECT COUNT(*) FROM network_logs WHERE action = 'block'
                                    AND logged_at > NOW() - INTERVAL '1h') AS blocked_1h,
  (SELECT COUNT(*) FROM network_logs WHERE logged_at > NOW() - INTERVAL '1h') AS net_events_1h,
  (SELECT COUNT(*) FROM blockchain_records WHERE status = 'confirmed')   AS chain_confirmed,
  (SELECT COUNT(*) FROM users WHERE is_active = TRUE)                    AS active_users;

-- Alerts with event counts
CREATE OR REPLACE VIEW v_alerts_timeline AS
SELECT
  a.*,
  u_ack.full_name  AS acknowledged_by_name,
  u_res.full_name  AS resolved_by_name,
  COUNT(e.id)      AS event_count
FROM alerts a
LEFT JOIN users u_ack ON a.acknowledged_by = u_ack.id
LEFT JOIN users u_res ON a.resolved_by    = u_res.id
LEFT JOIN events e    ON e.alert_id       = a.id
GROUP BY a.id, u_ack.full_name, u_res.full_name
ORDER BY a.created_at DESC;

-- FIR full detail with version count
CREATE OR REPLACE VIEW v_firs_detail AS
SELECT
  f.*,
  u_filed.full_name    AS filed_by_name,
  u_assigned.full_name AS assigned_to_name,
  COUNT(fv.id)         AS version_count,
  MAX(fv.created_at)   AS last_modified_at
FROM firs f
LEFT JOIN users u_filed    ON f.filed_by    = u_filed.id
LEFT JOIN users u_assigned ON f.assigned_to = u_assigned.id
LEFT JOIN fir_versions fv  ON fv.fir_id     = f.id
GROUP BY f.id, u_filed.full_name, u_assigned.full_name
ORDER BY f.created_at DESC;

-- Document verification summary
CREATE OR REPLACE VIEW v_documents_with_verdict AS
SELECT
  d.*,
  u.full_name                    AS uploaded_by_name,
  dv.verdict,
  dv.confidence_score,
  dv.verification_method,
  dv.ela_score,
  dv.created_at                  AS verified_at
FROM documents d
LEFT JOIN users u ON d.uploaded_by = u.id
LEFT JOIN LATERAL (
  SELECT * FROM document_verifications
  WHERE document_id = d.id
  ORDER BY created_at DESC LIMIT 1
) dv ON TRUE
ORDER BY d.created_at DESC;

-- ============================================================
-- ROW LEVEL SECURITY (Supabase)
-- ============================================================
ALTER TABLE users               ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents           ENABLE ROW LEVEL SECURITY;
ALTER TABLE document_verifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE firs                ENABLE ROW LEVEL SECURITY;
ALTER TABLE fir_versions        ENABLE ROW LEVEL SECURITY;
ALTER TABLE blockchain_records  ENABLE ROW LEVEL SECURITY;
ALTER TABLE network_logs        ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts              ENABLE ROW LEVEL SECURITY;
ALTER TABLE events              ENABLE ROW LEVEL SECURITY;

-- Admins see everything; operators see their own records
CREATE POLICY "admins_all" ON users
  FOR ALL USING (auth.jwt() ->> 'role' = 'admin');

CREATE POLICY "self_read" ON users
  FOR SELECT USING (auth.uid()::text = id::text);

-- ============================================================
-- SAMPLE DATA QUERIES
-- ============================================================

-- [1] INSERT a new user (admin)
INSERT INTO users (badge_number, full_name, rank, department, email, password_hash, role)
VALUES (
  'KAR-2024-001',
  'Supt. Rajesh Kumar',
  'Superintendent',
  'CID Karnataka',
  'rajesh.kumar@kar.gov.in',
  crypt('SecurePass@123', gen_salt('bf')),
  'admin'
);

-- [2] INSERT a new FIR
INSERT INTO firs (
  fir_number, station_code, district, filed_by,
  complainant_name, complainant_phone,
  incident_date, incident_location, incident_lat, incident_lng,
  category, severity, description, sections
)
SELECT
  'KAR/BLR/2024/001234',
  'BLR-CENTRAL-001',
  'Bengaluru Urban',
  id,
  'Priya Sharma',
  '+91-9876543210',
  '2024-01-15',
  'MG Road, Bengaluru',
  12.9716, 77.5946,
  'cyber_crime',
  'high',
  'Complainant reports unauthorized access to her bank account resulting in fraudulent transfer of ₹2,40,000.',
  ARRAY['IT Act S.66', 'IPC 420', 'IPC 120B']
FROM users WHERE badge_number = 'KAR-2024-001';

-- [3] VERIFY a document
WITH doc AS (
  INSERT INTO documents (
    uploaded_by, file_name, file_path, file_size_bytes,
    mime_type, doc_type, sha256_hash, status
  )
  SELECT
    id,
    'aadhaar_priya_sharma.pdf',
    '/uploads/docs/2024/aadhaar_priya_sharma.pdf',
    524288,
    'application/pdf',
    'aadhaar',
    encode(digest('dummy_content_hash', 'sha256'), 'hex'),
    'pending'
  FROM users WHERE badge_number = 'KAR-2024-001'
  RETURNING id, uploaded_by
)
INSERT INTO document_verifications (
  document_id, verified_by, verification_method,
  verdict, confidence_score, ela_score, ocr_match_score,
  model_version, anomalies, processing_ms
)
SELECT
  doc.id,
  doc.uploaded_by,
  'combined',
  'authentic',
  97.43,
  2.1,
  94.8,
  'doc-guard-v2.3',
  '[]'::jsonb,
  842
FROM doc;

-- Update document status after verification
UPDATE documents d
SET status = 'verified'
FROM document_verifications dv
WHERE dv.document_id = d.id
  AND dv.verdict = 'authentic'
  AND d.status = 'pending';

-- [4] FETCH DASHBOARD DATA
SELECT * FROM v_dashboard_stats;

-- [5] LOG network activity
INSERT INTO network_logs (
  source_ip, destination_ip, source_port, destination_port,
  protocol, bytes_sent, bytes_received, duration_ms,
  action, threat_type, threat_score, geo_country, tags
) VALUES (
  '185.234.219.45'::inet,
  '10.0.0.5'::inet,
  54321, 443,
  'HTTPS',
  4096, 128,
  234,
  'block',
  'port_scan',
  78.5,
  'RU',
  ARRAY['suspicious', 'foreign_ip', 'high_frequency']
);

-- [6] FETCH ALERTS TIMELINE (last 48h)
SELECT
  id, source_module, alert_type, severity,
  title, description, status,
  threat_score, location,
  event_count,
  created_at
FROM v_alerts_timeline
WHERE created_at > NOW() - INTERVAL '48h'
ORDER BY
  CASE severity
    WHEN 'critical' THEN 1
    WHEN 'high'     THEN 2
    WHEN 'medium'   THEN 3
    WHEN 'low'      THEN 4
    ELSE 5
  END,
  created_at DESC
LIMIT 50;

-- [7] INSERT an alert + linked event
WITH new_alert AS (
  INSERT INTO alerts (
    source_module, alert_type, severity, title, description,
    reference_type, threat_score, location, lat, lng
  ) VALUES (
    'crowd_sentinel',
    'weapon_detected',
    'critical',
    'Weapon Detected — MG Road CCTV Feed',
    'YOLOv8 detected a concealed firearm with 94.2% confidence in Frame #3847.',
    'network_log',
    94.2,
    'MG Road, Bengaluru',
    12.9716, 77.5946
  )
  RETURNING id
)
INSERT INTO events (alert_id, event_type, actor_module, summary, severity, detail)
SELECT
  id,
  'detection_triggered',
  'crowd_sentinel',
  'Automated weapon detection fired by YOLOv8 model',
  'critical',
  jsonb_build_object(
    'model', 'yolov8x', 'confidence', 94.2,
    'frame', 3847, 'camera_id', 'BLR-MG-CAM-07'
  )
FROM new_alert;

-- [8] FIR → versions → blockchain custody chain
SELECT
  f.fir_number,
  f.status,
  f.severity,
  fv.version_number,
  fv.change_type,
  fv.change_summary,
  fv.created_at AS version_time,
  br.tx_hash,
  br.block_number,
  br.status AS chain_status
FROM firs f
JOIN fir_versions fv      ON fv.fir_id      = f.id
LEFT JOIN blockchain_records br ON br.reference_id = fv.id
                               AND br.record_type   = 'fir_version'
WHERE f.fir_number = 'KAR/BLR/2024/001234'
ORDER BY fv.version_number ASC;

-- [9] Real-time threat feed (net-watch)
SELECT
  source_ip::text,
  COUNT(*)          AS hit_count,
  MAX(threat_score) AS max_threat,
  array_agg(DISTINCT threat_type) FILTER (WHERE threat_type IS NOT NULL) AS threat_types,
  MAX(logged_at)    AS last_seen
FROM network_logs
WHERE logged_at > NOW() - INTERVAL '1h'
  AND action IN ('block', 'alert')
GROUP BY source_ip
ORDER BY max_threat DESC, hit_count DESC
LIMIT 20;

-- ============================================================
-- TABLE: transactions  (CRITICAL — was completely missing)
-- ============================================================
CREATE TABLE IF NOT EXISTS transactions (
  id              UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  transaction_id  TEXT          NOT NULL UNIQUE DEFAULT ('TXN-' || upper(substr(gen_random_uuid()::text, 1, 8))),
  account_id      TEXT          NOT NULL,
  amount          NUMERIC(15,2) NOT NULL,
  currency        TEXT          NOT NULL DEFAULT 'INR',
  channel         TEXT          NOT NULL CHECK (channel IN ('ATM', 'UPI', 'NEFT', 'RTGS', 'IMPS', 'online', 'POS', 'mobile')),
  direction       TEXT          NOT NULL DEFAULT 'debit' CHECK (direction IN ('debit', 'credit')),
  merchant        TEXT,
  merchant_category TEXT,
  ip_address      TEXT,
  device_id       TEXT,
  latitude        DOUBLE PRECISION,
  longitude       DOUBLE PRECISION,
  city            TEXT,
  country         TEXT          DEFAULT 'IN',
  status          TEXT          NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'completed', 'flagged', 'blocked', 'reversed')),
  fraud_score     NUMERIC(5,2)  CHECK (fraud_score BETWEEN 0 AND 100),
  risk_level      TEXT          CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
  flagged_reason  TEXT,
  timestamp       TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_txn_account_id   ON transactions (account_id);
CREATE INDEX IF NOT EXISTS idx_txn_channel       ON transactions (channel);
CREATE INDEX IF NOT EXISTS idx_txn_status        ON transactions (status);
CREATE INDEX IF NOT EXISTS idx_txn_fraud_score   ON transactions (fraud_score DESC);
CREATE INDEX IF NOT EXISTS idx_txn_timestamp     ON transactions (timestamp DESC);

-- ============================================================
-- TABLE: fraud_scores   (per-transaction multi-channel score log)
-- ============================================================
CREATE TABLE IF NOT EXISTS fraud_scores (
  id              UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  transaction_id  TEXT          NOT NULL,
  account_id      TEXT          NOT NULL,
  net_watch_score NUMERIC(5,2)  DEFAULT 0,   -- IP risk signal
  doc_guard_score NUMERIC(5,2)  DEFAULT 0,   -- KYC tampering signal
  deep_trace_score NUMERIC(5,2) DEFAULT 0,   -- Deepfake identity signal
  sentinel_score  NUMERIC(5,2)  DEFAULT 0,   -- ATM/CCTV signal
  fir_warden_score NUMERIC(5,2) DEFAULT 0,   -- Transaction pattern signal
  final_score     NUMERIC(5,2)  NOT NULL,
  risk_level      TEXT          NOT NULL CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
  explanation     JSONB         DEFAULT '[]',
  created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fscore_txn_id  ON fraud_scores (transaction_id);
CREATE INDEX IF NOT EXISTS idx_fscore_account ON fraud_scores (account_id);
CREATE INDEX IF NOT EXISTS idx_fscore_final   ON fraud_scores (final_score DESC);

-- ============================================================
-- Add fraud-domain columns to alerts if not already there
-- ============================================================
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS account_id TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS transaction_id TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS channels TEXT[] DEFAULT '{}';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS fraud_score NUMERIC(5,2);

-- Add channel column to events
ALTER TABLE events ADD COLUMN IF NOT EXISTS channel TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS account_id TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS transaction_id TEXT;


-- ============================================================
-- TABLE: kyc_documents (Doc-Guard persistence)
-- ============================================================
CREATE TABLE IF NOT EXISTS kyc_documents (
  id              UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  doc_id          TEXT          NOT NULL UNIQUE,
  filename        TEXT          NOT NULL,
  original_text   TEXT          NOT NULL,
  hash            TEXT          NOT NULL,
  image_data      TEXT,
  timestamp       TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_kyc_doc_id ON kyc_documents (doc_id);

-- ============================================================
-- NET-WATCH & FRAUD DETECTION TABLES
-- ============================================================

-- ip_log table (Net-Watch stores here)
CREATE TABLE IF NOT EXISTS ip_log (
  id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  ip         TEXT        NOT NULL,
  geo        JSONB       DEFAULT '{}',
  flagged    BOOLEAN     DEFAULT FALSE,
  count      INT         DEFAULT 1,
  context    TEXT,
  logged_at  TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ip_log_ip ON ip_log(ip);
CREATE INDEX IF NOT EXISTS idx_ip_log_logged_at ON ip_log(logged_at DESC);

-- transactions table
CREATE TABLE IF NOT EXISTS transactions (
  id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  transaction_id  TEXT        NOT NULL UNIQUE,
  account_id      TEXT        NOT NULL,
  amount          NUMERIC,
  currency        TEXT        DEFAULT 'INR',
  channel         TEXT,
  direction       TEXT        DEFAULT 'debit',
  merchant        TEXT,
  ip_address      TEXT,
  device_id       TEXT,
  latitude        NUMERIC,
  longitude       NUMERIC,
  city            TEXT,
  country         TEXT        DEFAULT 'IN',
  status          TEXT        DEFAULT 'completed',
  fraud_score     NUMERIC,
  risk_level      TEXT,
  flagged_reason  TEXT,
  timestamp       TIMESTAMPTZ DEFAULT NOW(),
  created_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_txn_account ON transactions(account_id);
CREATE INDEX IF NOT EXISTS idx_txn_status  ON transactions(status);
CREATE INDEX IF NOT EXISTS idx_txn_ts      ON transactions(timestamp DESC);

-- fraud_scores table
CREATE TABLE IF NOT EXISTS fraud_scores (
  id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  transaction_id   TEXT,
  account_id       TEXT,
  net_watch_score  NUMERIC,
  doc_guard_score  NUMERIC,
  deep_trace_score NUMERIC,
  sentinel_score   NUMERIC,
  fir_warden_score NUMERIC,
  final_score      NUMERIC,
  risk_level       TEXT,
  explanation      JSONB       DEFAULT '[]',
  created_at       TIMESTAMPTZ DEFAULT NOW()
);

-- alerts table
CREATE TABLE IF NOT EXISTS alerts (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  alert_type  TEXT,
  description TEXT,
  severity    TEXT,
  source      TEXT,
  metadata    JSONB       DEFAULT '{}',
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- [10] SYSTEM INITIALIZATION & REPAIR
-- ============================================================

-- Audit Log Table
CREATE TABLE IF NOT EXISTS audit_log (
  id      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  action  TEXT        NOT NULL,
  detail  JSONB       DEFAULT '{}',
  ts      TIMESTAMPTZ DEFAULT NOW()
);

-- Ensure blockchain_records has correct mapping
-- (Table already exists at line 157, but adding status column check if missing)
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='blockchain_records' AND column_name='status') THEN
        ALTER TABLE blockchain_records ADD COLUMN status TEXT DEFAULT 'confirmed';
    END IF;
END $$;

-- [11] DEMO MODE: DISABLE RLS
-- ============================================================
ALTER TABLE users               DISABLE ROW LEVEL SECURITY;
ALTER TABLE documents           DISABLE ROW LEVEL SECURITY;
ALTER TABLE document_verifications DISABLE ROW LEVEL SECURITY;
ALTER TABLE firs                DISABLE ROW LEVEL SECURITY;
ALTER TABLE fir_versions        DISABLE ROW LEVEL SECURITY;
ALTER TABLE blockchain_records  DISABLE ROW LEVEL SECURITY;
ALTER TABLE network_logs        DISABLE ROW LEVEL SECURITY;
ALTER TABLE alerts              DISABLE ROW LEVEL SECURITY;
ALTER TABLE events              DISABLE ROW LEVEL SECURITY;
ALTER TABLE ip_log              DISABLE ROW LEVEL SECURITY;
ALTER TABLE transactions        DISABLE ROW LEVEL SECURITY;
ALTER TABLE fraud_scores        DISABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log           DISABLE ROW LEVEL SECURITY;

-- [12] INITIAL DATA: SYSTEM AGENT
-- ============================================================
INSERT INTO users (id, badge_number, full_name, rank, department, role)
VALUES (
  '00000000-0000-0000-0000-000000000000',
  'AI-SENTINEL-001',
  'KAVACH AI AGENT',
  'SYSTEM',
  'INTELLIGENCE',
  'admin'
) ON CONFLICT (id) DO NOTHING;

-- (Redundant table/index definitions removed)

-- Redundant definitions removed

-- ============================================================
-- Add fraud-domain columns to alerts if not already there
-- ============================================================
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS account_id TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS transaction_id TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS channels TEXT[] DEFAULT '{}';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS fraud_score NUMERIC(5,2);

-- Add channel column to events
ALTER TABLE events ADD COLUMN IF NOT EXISTS channel TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS account_id TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS transaction_id TEXT;