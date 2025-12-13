-- MalwareSnipper Database Schema
-- Atomic transactions, single source of truth for status

-- ═══════════════════════════════════════════════════════════════════════════
-- SCANS TABLE
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    risk_score REAL,
    category TEXT,
    ai_score REAL,
    js_score REAL,
    heuristics_score REAL,
    blacklist_score REAL,
    reputation_score REAL,
    sandbox_score REAL,
    threats TEXT,
    created_at INTEGER,
    updated_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_category ON scans(category);

-- ═══════════════════════════════════════════════════════════════════════════
-- SUMMARY STATUS TABLE
-- Single authoritative row (id = 1) that holds global state
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS summary_status (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    overall_risk_score REAL DEFAULT 0,
    category TEXT DEFAULT 'BENIGN',
    last_scan_id INTEGER,
    last_scan_url TEXT,
    last_scan_at INTEGER,
    total_scans INTEGER DEFAULT 0,
    malicious_count INTEGER DEFAULT 0,
    suspicious_count INTEGER DEFAULT 0,
    benign_count INTEGER DEFAULT 0,
    updated_at INTEGER
);

-- ═══════════════════════════════════════════════════════════════════════════
-- DEBUG & TESTING QUERIES
-- ═══════════════════════════════════════════════════════════════════════════

-- View all scans (newest first)
-- SELECT id, url, risk_score, category, created_at FROM scans ORDER BY created_at DESC;

-- View summary status (authoritative global state)
-- SELECT * FROM summary_status WHERE id = 1;

-- View last 5 scans
-- SELECT id, url, risk_score, category, created_at FROM scans ORDER BY created_at DESC LIMIT 5;

-- View scan counts by category
-- SELECT category, COUNT(*) as count FROM scans GROUP BY category;

-- Verify summary totals match scan counts
-- SELECT 
--   (SELECT COUNT(*) FROM scans) as total_scans,
--   (SELECT COUNT(*) FROM scans WHERE category = 'MALICIOUS') as malicious,
--   (SELECT COUNT(*) FROM scans WHERE category = 'SUSPICIOUS') as suspicious,
--   (SELECT COUNT(*) FROM scans WHERE category = 'BENIGN') as benign,
--   (SELECT total_scans FROM summary_status WHERE id = 1) as summary_total,
--   (SELECT malicious_count FROM summary_status WHERE id = 1) as summary_malicious,
--   (SELECT suspicious_count FROM summary_status WHERE id = 1) as summary_suspicious,
--   (SELECT benign_count FROM summary_status WHERE id = 1) as summary_benign;

-- View detector scores for last scan
-- SELECT id, url, ai_score, js_score, heuristics_score, blacklist_score, reputation_score 
-- FROM scans ORDER BY created_at DESC LIMIT 1;

-- ═══════════════════════════════════════════════════════════════════════════
-- MIGRATION: Ensure summary_status row exists
-- ═══════════════════════════════════════════════════════════════════════════

-- Run this after creating the table:
-- INSERT OR IGNORE INTO summary_status (id, overall_risk_score, category, updated_at)
-- VALUES (1, 0, 'BENIGN', strftime('%s', 'now'));
