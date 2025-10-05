-- PostgreSQL initialization script for Shells + Hera
-- This runs automatically when the PostgreSQL container starts

-- Shells core tables
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    type TEXT NOT NULL,
    profile TEXT,
    options TEXT,
    scheduled_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    status TEXT NOT NULL,
    error_message TEXT,
    worker_id TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    tool TEXT NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    evidence TEXT,
    solution TEXT,
    refs JSONB,
    metadata JSONB,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

-- Shells indexes
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);

-- Hera tables for phishing/threat detection
CREATE TABLE IF NOT EXISTS hera_detections (
    id TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    url TEXT,  -- Full URL (optional, privacy consideration)
    verdict TEXT NOT NULL,  -- 'SAFE', 'SUSPICIOUS', 'DANGEROUS', 'TRUSTED'
    reputation_score INTEGER,
    surprise_score REAL,
    patterns_detected JSONB,  -- Array of pattern names that triggered
    client_version TEXT,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_hera_detections_domain ON hera_detections(domain);
CREATE INDEX IF NOT EXISTS idx_hera_detections_verdict ON hera_detections(verdict);
CREATE INDEX IF NOT EXISTS idx_hera_detections_timestamp ON hera_detections(timestamp);

-- Hera domain reputation cache
CREATE TABLE IF NOT EXISTS hera_domain_reputation (
    domain TEXT PRIMARY KEY,
    tranco_rank INTEGER,
    category TEXT,  -- 'TECH', 'FINANCE', 'ECOMMERCE', 'DEV_TOOLS', etc.
    trust_score INTEGER CHECK (trust_score >= 0 AND trust_score <= 100),
    age_days INTEGER,
    owner TEXT,
    first_seen TIMESTAMP,
    last_updated TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_hera_reputation_rank ON hera_domain_reputation(tranco_rank);
CREATE INDEX IF NOT EXISTS idx_hera_reputation_category ON hera_domain_reputation(category);
CREATE INDEX IF NOT EXISTS idx_hera_reputation_trust_score ON hera_domain_reputation(trust_score);

-- Hera WHOIS cache (7 day TTL)
CREATE TABLE IF NOT EXISTS hera_whois_cache (
    domain TEXT PRIMARY KEY,
    registration_date TIMESTAMP,
    registrar TEXT,
    age_days INTEGER,
    nameservers TEXT[],
    raw_data JSONB,
    cached_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_hera_whois_expires ON hera_whois_cache(expires_at);
CREATE INDEX IF NOT EXISTS idx_hera_whois_age ON hera_whois_cache(age_days);

-- Hera threat intelligence cache (24 hour TTL)
CREATE TABLE IF NOT EXISTS hera_threat_intel (
    domain TEXT NOT NULL,
    source TEXT NOT NULL,  -- 'virustotal', 'phishtank', 'urlhaus', 'googleSafeBrowsing'
    verdict TEXT,  -- 'CLEAN', 'SUSPICIOUS', 'MALICIOUS', 'UNKNOWN'
    score INTEGER,  -- Source-specific score
    details JSONB,
    cached_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    PRIMARY KEY (domain, source)
);

CREATE INDEX IF NOT EXISTS idx_hera_threat_expires ON hera_threat_intel(expires_at);
CREATE INDEX IF NOT EXISTS idx_hera_threat_verdict ON hera_threat_intel(verdict);

-- Hera aggregate statistics (privacy-preserving analytics)
CREATE TABLE IF NOT EXISTS hera_stats (
    date DATE NOT NULL,
    verdict TEXT NOT NULL,
    reputation_bucket INTEGER,  -- 0-10, 10-20, etc.
    pattern TEXT,  -- Which pattern triggered (e.g., 'brand_impersonation', 'typosquatting')
    count INTEGER DEFAULT 1,
    PRIMARY KEY (date, verdict, reputation_bucket, pattern)
);

CREATE INDEX IF NOT EXISTS idx_hera_stats_date ON hera_stats(date);

-- Hera false positive reports (user feedback)
CREATE TABLE IF NOT EXISTS hera_feedback (
    id TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    original_verdict TEXT NOT NULL,
    user_verdict TEXT NOT NULL,  -- 'false_positive', 'false_negative', 'correct'
    reason TEXT,
    metadata JSONB,
    reported_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_hera_feedback_domain ON hera_feedback(domain);
CREATE INDEX IF NOT EXISTS idx_hera_feedback_verdict ON hera_feedback(user_verdict);
CREATE INDEX IF NOT EXISTS idx_hera_feedback_reported_at ON hera_feedback(reported_at);

-- Hera pattern performance tracking
CREATE TABLE IF NOT EXISTS hera_pattern_stats (
    pattern_name TEXT NOT NULL,
    date DATE NOT NULL,
    true_positives INTEGER DEFAULT 0,
    false_positives INTEGER DEFAULT 0,
    false_negatives INTEGER DEFAULT 0,
    avg_surprise_score REAL,
    PRIMARY KEY (pattern_name, date)
);

CREATE INDEX IF NOT EXISTS idx_hera_pattern_date ON hera_pattern_stats(date);

-- Seed some trust anchor data for common domains
INSERT INTO hera_domain_reputation (domain, tranco_rank, category, trust_score, owner) VALUES
    ('google.com', 1, 'TECH', 100, 'Google LLC'),
    ('youtube.com', 2, 'TECH', 100, 'Google LLC'),
    ('facebook.com', 3, 'SOCIAL', 100, 'Meta Platforms'),
    ('twitter.com', 4, 'SOCIAL', 100, 'X Corp'),
    ('instagram.com', 5, 'SOCIAL', 100, 'Meta Platforms'),
    ('baidu.com', 6, 'TECH', 100, 'Baidu Inc'),
    ('wikipedia.org', 7, 'REFERENCE', 100, 'Wikimedia Foundation'),
    ('yandex.ru', 8, 'TECH', 100, 'Yandex'),
    ('yahoo.com', 9, 'TECH', 100, 'Yahoo'),
    ('whatsapp.com', 10, 'SOCIAL', 100, 'Meta Platforms'),
    ('amazon.com', 11, 'ECOMMERCE', 100, 'Amazon'),
    ('zoom.us', 12, 'TECH', 100, 'Zoom Video Communications'),
    ('tiktok.com', 13, 'SOCIAL', 100, 'ByteDance'),
    ('linkedin.com', 14, 'SOCIAL', 100, 'Microsoft'),
    ('netflix.com', 15, 'STREAMING', 100, 'Netflix'),
    ('discord.com', 16, 'SOCIAL', 100, 'Discord Inc'),
    ('twitch.tv', 17, 'STREAMING', 100, 'Amazon'),
    ('reddit.com', 18, 'SOCIAL', 100, 'Reddit Inc'),
    ('office.com', 19, 'PRODUCTIVITY', 100, 'Microsoft'),
    ('microsoft.com', 20, 'TECH', 100, 'Microsoft'),
    ('github.com', 42, 'DEV_TOOLS', 100, 'Microsoft'),
    ('stackoverflow.com', 58, 'DEV_TOOLS', 95, 'Stack Exchange'),
    ('apple.com', 65, 'TECH', 100, 'Apple Inc'),
    ('paypal.com', 89, 'FINANCE', 100, 'PayPal'),
    ('dropbox.com', 156, 'PRODUCTIVITY', 95, 'Dropbox Inc')
ON CONFLICT (domain) DO NOTHING;

-- Create a function to clean up expired cache entries
CREATE OR REPLACE FUNCTION cleanup_expired_caches() RETURNS void AS $$
BEGIN
    DELETE FROM hera_whois_cache WHERE expires_at < NOW();
    DELETE FROM hera_threat_intel WHERE expires_at < NOW();
    DELETE FROM hera_stats WHERE date < CURRENT_DATE - INTERVAL '90 days';
    DELETE FROM hera_detections WHERE timestamp < NOW() - INTERVAL '30 days';
END;
$$ LANGUAGE plpgsql;

-- Comments for documentation
COMMENT ON TABLE hera_detections IS 'Stores every URL analysis performed by Hera extensions';
COMMENT ON TABLE hera_domain_reputation IS 'Cached domain reputation data from Tranco and other sources';
COMMENT ON TABLE hera_whois_cache IS 'Cached WHOIS lookup results with 7-day TTL';
COMMENT ON TABLE hera_threat_intel IS 'Cached threat intelligence from multiple sources with 24-hour TTL';
COMMENT ON TABLE hera_stats IS 'Privacy-preserving aggregate statistics (no URLs stored)';
COMMENT ON TABLE hera_feedback IS 'User-reported false positives/negatives for improving detection';
COMMENT ON TABLE hera_pattern_stats IS 'Performance metrics for each detection pattern';

COMMENT ON COLUMN hera_detections.url IS 'Full URL - consider privacy implications before storing';
COMMENT ON COLUMN hera_domain_reputation.trust_score IS 'Calculated trust score 0-100, higher = more trustworthy';
COMMENT ON COLUMN hera_stats.reputation_bucket IS 'Domains grouped by reputation (0-10, 10-20, etc.) for privacy';
