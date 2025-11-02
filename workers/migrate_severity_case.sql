-- Migration Script: Normalize Finding Severity to Lowercase
--
-- Generated: 2025-10-30
-- Purpose: Fix Python findings with uppercase severity values
-- Impact: Makes Python findings queryable by Go CLI
--
-- IMPORTANT: This is a one-time migration for existing data.
-- New findings are automatically normalized to lowercase by database.py
--
-- Usage:
--   psql $DATABASE_DSN -f workers/migrate_severity_case.sql
--
-- Or with docker-compose:
--   docker-compose exec postgres psql -U shells -d shells -f /path/to/migrate_severity_case.sql

BEGIN;

-- Show current state (before migration)
SELECT 'BEFORE MIGRATION' as status;
SELECT
    tool,
    severity,
    COUNT(*) as count
FROM findings
GROUP BY tool, severity
ORDER BY tool, severity;

-- Identify findings with uppercase severity from Python tools
SELECT
    'Findings to migrate:' as info,
    COUNT(*) as count
FROM findings
WHERE tool IN ('graphcrawler', 'custom_idor')
  AND severity ~ '^[A-Z]';  -- Regex: starts with uppercase letter

-- Migrate severity values to lowercase
UPDATE findings
SET
    severity = LOWER(severity),
    updated_at = CURRENT_TIMESTAMP
WHERE
    severity ~ '^[A-Z]'  -- Only update uppercase values
    AND severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO');

-- Show migration results
SELECT
    'Migration Results:' as info,
    COUNT(*) as findings_updated
FROM findings
WHERE updated_at >= CURRENT_TIMESTAMP - INTERVAL '1 second';

-- Show final state (after migration)
SELECT 'AFTER MIGRATION' as status;
SELECT
    tool,
    severity,
    COUNT(*) as count
FROM findings
GROUP BY tool, severity
ORDER BY tool, severity;

-- Verify no uppercase severities remain
SELECT
    'Verification:' as info,
    COUNT(*) as uppercase_severities_remaining
FROM findings
WHERE severity ~ '^[A-Z]';

-- Expected result: 0 uppercase severities remaining

COMMIT;

-- Cleanup: Update statistics (optional, PostgreSQL only)
ANALYZE findings;

SELECT 'Migration completed successfully!' as status;
