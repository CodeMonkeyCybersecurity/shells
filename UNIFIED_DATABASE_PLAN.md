# Unified Database Plan: Python + Go Integration

**Created**: 2025-10-30
**Status**: PLANNING
**Goal**: Single PostgreSQL database shared by Go and Python workers with consistent schema and data types

---

## Current State Analysis

### Go Database Implementation
**Location**: `internal/database/store.go` (1,390 lines)

**Key Characteristics**:
- Uses `sqlx` library for database access
- PostgreSQL driver: `github.com/lib/pq`
- Named parameter queries (`:param`)
- Structured logging via `internal/logger`
- Transaction support with rollback
- Type-safe with Go structs (`types.Finding`)
- OpenTelemetry tracing integration

**Go Finding Structure** (`pkg/types/types.go:44-58`):
```go
type Finding struct {
    ID          string                 `json:"id" db:"id"`
    ScanID      string                 `json:"scan_id" db:"scan_id"`
    Tool        string                 `json:"tool" db:"tool"`
    Type        string                 `json:"type" db:"type"`
    Severity    Severity               `json:"severity" db:"severity"`  // lowercase enum
    Title       string                 `json:"title" db:"title"`
    Description string                 `json:"description" db:"description"`
    Evidence    string                 `json:"evidence,omitempty" db:"evidence"`
    Solution    string                 `json:"solution,omitempty" db:"solution"`
    References  []string               `json:"references,omitempty"`     // Stored as JSONB
    Metadata    map[string]interface{} `json:"metadata,omitempty"`       // Stored as JSONB
    CreatedAt   time.Time              `json:"created_at" db:"created_at"`
    UpdatedAt   time.Time              `json:"updated_at" db:"updated_at"`
}

// Severity constants
const (
    SeverityCritical Severity = "critical"  // lowercase
    SeverityHigh     Severity = "high"
    SeverityMedium   Severity = "medium"
    SeverityLow      Severity = "low"
    SeverityInfo     Severity = "info"
)
```

### Python Database Implementation
**Location**: `workers/service/database.py` (385 lines)

**Key Characteristics**:
- Uses `psycopg2` library for database access
- Positional parameter queries (`%s`)
- Context manager for connection pooling
- Basic Python error handling
- Type hints for function signatures
- Uses UPPERCASE severity values

**Python Finding Format**:
```python
def save_finding(
    scan_id: str,
    tool: str,
    finding_type: str,
    severity: str,              # UPPERCASE: "CRITICAL", "HIGH"
    title: str,
    description: str = "",
    evidence: str = "",
    solution: str = "",
    references: Optional[List[str]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> str:
    # Validates: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
```

### Schema Compatibility

**Database Schema** (`internal/database/store.go:247-261`):
```sql
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
```

---

## Problem Statement

### Issue 1: Severity Case Mismatch ⚠️

**Go expects**: `"critical"`, `"high"`, `"medium"`, `"low"`, `"info"` (lowercase)
**Python sends**: `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, `"LOW"`, `"INFO"` (uppercase)

**Impact**:
- Python findings have uppercase severity
- Go queries filter by lowercase severity
- Result: **Go CLI cannot find Python findings by severity**

Example broken query:
```bash
# Go CLI queries for lowercase
shells results query --severity critical

# SQL executed by Go:
SELECT * FROM findings WHERE severity = 'critical'

# But Python saved as:
INSERT INTO findings (..., severity, ...) VALUES (..., 'CRITICAL', ...)

# Result: 0 findings returned ❌
```

### Issue 2: Connection String Format Differences

**Go format** (DSN from `config.yaml`):
```
postgres://shells:password@postgres:5432/shells?sslmode=disable
```

**Python format** (psycopg2 DSN):
```
postgresql://shells:password@postgres:5432/shells
```

Both work, but inconsistent environment variables could cause confusion.

### Issue 3: Different Query Parameter Styles

**Go** (sqlx with named parameters):
```go
query := `INSERT INTO findings (...) VALUES (:id, :scan_id, :tool, ...)`
_, err := db.NamedExecContext(ctx, query, map[string]interface{}{
    "id": finding.ID,
    "scan_id": finding.ScanID,
})
```

**Python** (psycopg2 with positional parameters):
```python
query = "INSERT INTO findings (...) VALUES (%s, %s, %s, ...)"
cursor.execute(query, (finding_id, scan_id, tool, ...))
```

Not a compatibility issue (both work), but makes code harder to maintain across languages.

### Issue 4: Logging Integration

**Go**: Uses structured `otelzap` logger with OpenTelemetry tracing
**Python**: Uses basic `print()` for errors and warnings

No unified logging → hard to trace operations across Go and Python components.

### Issue 5: Transaction Semantics

**Go**: Uses explicit transactions with `BeginTxx()` and deferred rollback
**Python**: Uses context manager with auto-commit on success

Both are correct, but inconsistent error handling patterns.

---

## Recommended Solution: Unified Database Layer

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    PostgreSQL Database                       │
│                  (Single Source of Truth)                    │
└─────────────────────┬───────────────────────────────────────┘
                      │
        ┌─────────────┴─────────────┐
        │                           │
        ▼                           ▼
┌──────────────────┐      ┌──────────────────┐
│   Go Database    │      │  Python Database │
│   Client         │      │  Client          │
│                  │      │                  │
│ - sqlx           │      │ - psycopg2       │
│ - Named params   │      │ - Positional     │
│ - otelzap logs   │      │ - Basic logging  │
│                  │      │                  │
│ CANONICAL        │      │ ADAPTER          │
│ IMPLEMENTATION   │      │ (matches Go)     │
└──────────────────┘      └──────────────────┘
```

**Key Principle**: Go implementation is canonical, Python adapts to match.

**Why?**
1. Go has more mature implementation (1,390 lines vs 385 lines)
2. Go CLI is primary user interface
3. Go has OpenTelemetry tracing
4. Existing Go queries already deployed

---

## Implementation Plan

### Phase 1: Fix Python Severity Case (P0 - CRITICAL)

**Priority**: P0 - Breaks Go CLI query functionality
**Timeline**: 1 hour
**Effort**: Minimal (single file change)

#### Changes Required

**File**: `workers/service/database.py`

**Before**:
```python
def save_finding(
    ...
    severity: str,  # Accepts: "CRITICAL", "HIGH", etc.
    ...
):
    # Validate severity
    valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    if severity not in valid_severities:
        raise ValueError(f"Invalid severity '{severity}'")

    # Save to database as uppercase
    cursor.execute(query, (..., severity, ...))  # "CRITICAL"
```

**After**:
```python
def save_finding(
    ...
    severity: str,  # Accepts: "CRITICAL" or "critical" (for compatibility)
    ...
):
    # Normalize severity to lowercase (Go canonical format)
    severity_lower = severity.lower()

    # Validate severity
    valid_severities = ["critical", "high", "medium", "low", "info"]
    if severity_lower not in valid_severities:
        raise ValueError(
            f"Invalid severity '{severity}'. "
            f"Must be one of {valid_severities} (case-insensitive)"
        )

    # Save to database as lowercase (matches Go)
    cursor.execute(query, (..., severity_lower, ...))  # "critical"
```

**Impact**:
- ✅ Python findings queryable by Go CLI
- ✅ Consistent severity in database
- ✅ Backward compatible (accepts both cases)

**Testing**:
```python
# Unit test
def test_save_finding_normalizes_severity():
    db = get_db_client()

    # Test uppercase input
    finding_id = db.save_finding(
        scan_id="test",
        tool="test",
        finding_type="TEST",
        severity="CRITICAL",  # Uppercase input
        title="Test"
    )

    # Verify saved as lowercase
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT severity FROM findings WHERE id = %s",
            (finding_id,)
        )
        severity = cursor.fetchone()[0]
        assert severity == "critical"  # Lowercase in DB
```

**Migration for Existing Data**:
```sql
-- Fix existing Python findings (if any exist)
UPDATE findings
SET severity = LOWER(severity)
WHERE severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO');
```

#### Files to Modify

1. **workers/service/database.py** (lines 89-130)
   - Update `save_finding()` to normalize severity
   - Update `save_findings_batch()` to normalize severity
   - Update validation messages

2. **workers/service/tasks.py** (lines 280-298, 480-500)
   - Findings already use `.upper()` when parsing scanner output
   - No changes needed (normalization happens in database.py)

3. **workers/tests/test_database.py** (add tests)
   - Test uppercase input → lowercase storage
   - Test lowercase input → lowercase storage
   - Test mixed case input → lowercase storage

4. **workers/README.md** (update documentation)
   - Document severity normalization
   - Update examples to use lowercase

**Status**: ✅ **COMPLETE** (2025-10-30)

**Changes Applied**:
- ✅ `workers/service/database.py` - Severity normalization implemented
- ✅ `workers/tests/test_database.py` - 4 new unit tests added
- ✅ `workers/migrate_severity_case.sql` - Migration script created
- ✅ `workers/README.md` - Documentation updated with normalization section

**Test Results**:
- ✅ test_save_finding_normalizes_severity_uppercase
- ✅ test_save_finding_normalizes_severity_lowercase
- ✅ test_save_finding_normalizes_severity_mixedcase
- ✅ test_save_findings_batch_normalizes_severity

**Verification**:
```bash
# Run tests
pytest workers/tests/test_database.py::TestDatabaseClient::test_save_finding_normalizes_severity_uppercase -v

# Result: PASSED ✅
```

---

### Phase 2: Standardize Connection String Format (P1)

**Priority**: P1 - Minor issue, causes confusion
**Timeline**: 30 minutes
**Effort**: Minimal (environment variable rename)

#### Changes Required

**Unified Environment Variable**: `DATABASE_DSN`

**Before** (inconsistent):
```bash
# Go uses
WEBSCAN_DATABASE_DSN="postgres://shells:password@postgres:5432/shells?sslmode=disable"

# Python uses
POSTGRES_DSN="postgresql://shells:password@postgres:5432/shells"
```

**After** (consistent):
```bash
# Both use same variable and format
DATABASE_DSN="postgresql://shells:password@postgres:5432/shells?sslmode=disable"
```

**Format**: Use `postgresql://` scheme (standard, works with both)

#### Files to Modify

1. **workers/service/database.py** (line 25)
```python
# Before
self.dsn = dsn or os.getenv("POSTGRES_DSN", "postgresql://shells:shells@postgres:5432/shells")

# After
self.dsn = dsn or os.getenv("DATABASE_DSN", "postgresql://shells:shells@postgres:5432/shells?sslmode=disable")
```

2. **deployments/docker/docker-compose.yml** (lines 121, 144)
```yaml
# Before
POSTGRES_DSN: "postgresql://shells:${POSTGRES_PASSWORD:-shells_dev_password}@postgres:5432/shells"

# After
DATABASE_DSN: "postgresql://shells:${POSTGRES_PASSWORD:-shells_dev_password}@postgres:5432/shells?sslmode=disable"
```

3. **workers/README.md** (update all references)
```bash
# Before
export POSTGRES_DSN="postgresql://..."

# After
export DATABASE_DSN="postgresql://..."
```

---

### Phase 3: Add Python Structured Logging (P2)

**Priority**: P2 - Improves observability
**Timeline**: 2 hours
**Effort**: Medium (integrate Python logging library)

#### Recommended Approach

Use Python's `structlog` library (similar to Go's otelzap):

**Installation**:
```bash
pip install structlog
```

**Configuration** (`workers/service/logging.py` - NEW):
```python
"""
Structured logging for Python workers

Matches Go otelzap format for consistent log parsing.
"""
import structlog
import sys

def configure_logging(level: str = "INFO", format: str = "json"):
    """
    Configure structured logging

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR)
        format: Output format (json, console)
    """
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    if format == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

def get_logger(component: str):
    """Get structured logger for component"""
    return structlog.get_logger(component)
```

**Usage in database.py**:
```python
from workers.service.logging import get_logger

class DatabaseClient:
    def __init__(self, dsn: Optional[str] = None):
        self.dsn = dsn or os.getenv("DATABASE_DSN", ...)
        self.logger = get_logger("database")

    def save_finding(self, ...):
        self.logger.info(
            "saving_finding",
            scan_id=scan_id,
            tool=tool,
            severity=severity,
            finding_type=finding_type
        )

        try:
            # ... database operations

            self.logger.info(
                "finding_saved",
                finding_id=finding_id,
                scan_id=scan_id
            )
            return finding_id

        except Exception as e:
            self.logger.error(
                "save_finding_failed",
                error=str(e),
                scan_id=scan_id,
                tool=tool
            )
            raise
```

**Benefits**:
- ✅ Consistent log format with Go
- ✅ Structured fields for parsing
- ✅ Easy to integrate with log aggregation (ELK, Datadog)
- ✅ Supports OpenTelemetry traces (with additional config)

#### Files to Modify

1. **workers/service/logging.py** (NEW - 100 lines)
2. **workers/service/database.py** (integrate structured logging)
3. **workers/service/tasks.py** (integrate structured logging)
4. **workers/requirements.txt** (add structlog>=23.0.0)

---

### Phase 4: Schema Validation Layer (P2)

**Priority**: P2 - Prevents schema drift
**Timeline**: 3 hours
**Effort**: Medium (create validation tools)

#### Recommended Approach

Create shared schema definition that both Go and Python validate against.

**File**: `schema/findings.schema.json` (NEW):
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Finding",
  "type": "object",
  "required": ["id", "scan_id", "tool", "type", "severity", "title", "created_at", "updated_at"],
  "properties": {
    "id": {
      "type": "string",
      "format": "uuid",
      "description": "Unique finding identifier"
    },
    "scan_id": {
      "type": "string",
      "description": "Reference to parent scan"
    },
    "tool": {
      "type": "string",
      "enum": [
        "nmap", "zap", "nuclei", "graphcrawler", "custom_idor",
        "saml", "oauth2", "webauthn", "scim", "smuggling"
      ],
      "description": "Tool that discovered finding"
    },
    "type": {
      "type": "string",
      "description": "Vulnerability type (e.g., IDOR, XSS, SQLi)"
    },
    "severity": {
      "type": "string",
      "enum": ["critical", "high", "medium", "low", "info"],
      "description": "Severity level (lowercase)"
    },
    "title": {
      "type": "string",
      "minLength": 1,
      "maxLength": 255,
      "description": "Short finding title"
    },
    "description": {
      "type": "string",
      "description": "Detailed description"
    },
    "evidence": {
      "type": "string",
      "description": "Evidence of vulnerability"
    },
    "solution": {
      "type": "string",
      "description": "Remediation guidance"
    },
    "references": {
      "type": "array",
      "items": {"type": "string", "format": "uri"},
      "description": "Reference URLs (CVE, CWE, etc.)"
    },
    "metadata": {
      "type": "object",
      "description": "Tool-specific metadata"
    },
    "created_at": {
      "type": "string",
      "format": "date-time"
    },
    "updated_at": {
      "type": "string",
      "format": "date-time"
    }
  }
}
```

**Python Validation** (`workers/service/schema.py` - NEW):
```python
import jsonschema
import json

# Load schema
with open("schema/findings.schema.json") as f:
    FINDING_SCHEMA = json.load(f)

def validate_finding(finding: dict) -> None:
    """Validate finding against schema"""
    try:
        jsonschema.validate(finding, FINDING_SCHEMA)
    except jsonschema.ValidationError as e:
        raise ValueError(f"Finding validation failed: {e.message}")
```

**Go Validation** (use existing struct tags):
```go
// Already validated via struct tags in pkg/types/types.go
// No changes needed
```

---

### Phase 5: Integration Testing (P1)

**Priority**: P1 - Ensures compatibility
**Timeline**: 2 hours
**Effort**: Medium (create cross-language tests)

#### Test Scenarios

**Test 1: Python Save → Go Query**
```python
# Python: Save finding
db = get_db_client()
finding_id = db.save_finding(
    scan_id="integration-test-001",
    tool="custom_idor",
    finding_type="IDOR",
    severity="critical",  # lowercase
    title="Test finding from Python"
)
```

```bash
# Go: Query finding
shells results query --scan-id integration-test-001 --severity critical

# Expected output:
# 1 finding(s) found
# - [critical] Test finding from Python (custom_idor)
```

**Test 2: Go Save → Python Query**
```go
// Go: Save finding
finding := types.Finding{
    ID: uuid.New().String(),
    ScanID: "integration-test-002",
    Tool: "nmap",
    Type: "open_port",
    Severity: types.SeverityCritical,  // lowercase
    Title: "Test finding from Go",
}
store.SaveFindings(ctx, []types.Finding{finding})
```

```python
# Python: Query finding
db = get_db_client()
findings = db.get_findings_by_severity("integration-test-002", "critical")

assert len(findings) == 1
assert findings[0]["title"] == "Test finding from Go"
assert findings[0]["tool"] == "nmap"
```

**Test 3: Concurrent Operations**
```python
# Test Python and Go writing simultaneously
# Verify no deadlocks or conflicts
```

#### Files to Create

1. **tests/integration/test_python_go_database.py** (NEW)
2. **tests/integration/test_go_python_database_test.go** (NEW)
3. **tests/integration/run_cross_language_tests.sh** (NEW)

---

## Summary of Changes

### Files to Create (7 files)

1. `workers/service/logging.py` (100 lines)
2. `schema/findings.schema.json` (80 lines)
3. `workers/service/schema.py` (50 lines)
4. `tests/integration/test_python_go_database.py` (200 lines)
5. `tests/integration/test_go_python_database_test.go` (200 lines)
6. `tests/integration/run_cross_language_tests.sh` (50 lines)
7. `UNIFIED_DATABASE_PLAN.md` (this file)

### Files to Modify (8 files)

1. `workers/service/database.py`
   - Normalize severity to lowercase
   - Use DATABASE_DSN environment variable
   - Integrate structured logging

2. `workers/service/tasks.py`
   - Integrate structured logging
   - No severity changes (normalization in database.py)

3. `workers/tests/test_database.py`
   - Add severity normalization tests
   - Test both uppercase and lowercase input

4. `workers/requirements.txt`
   - Add structlog>=23.0.0
   - Add jsonschema>=4.19.0

5. `deployments/docker/docker-compose.yml`
   - Rename POSTGRES_DSN → DATABASE_DSN

6. `workers/README.md`
   - Update environment variable name
   - Document severity normalization
   - Add cross-language integration section

7. `ROADMAP.md`
   - Add unified database section to Phase 5

8. `pkg/types/types.go`
   - Document that severity must be lowercase
   - Add comment about Python compatibility

---

## Timeline and Priorities

### Priority Breakdown

**P0 - CRITICAL** (Must fix immediately):
- Phase 1: Fix Python severity case (1 hour)
  - **Impact**: Go CLI cannot query Python findings
  - **Risk**: High - breaks primary user interface

**P1 - HIGH** (Should fix this week):
- Phase 2: Standardize connection string (30 min)
- Phase 5: Integration testing (2 hours)
  - **Impact**: Prevents future compatibility issues
  - **Risk**: Medium - catches problems early

**P2 - MEDIUM** (Should fix next week):
- Phase 3: Add Python structured logging (2 hours)
- Phase 4: Schema validation layer (3 hours)
  - **Impact**: Improves observability and maintainability
  - **Risk**: Low - nice to have

### Total Effort

**Critical Path** (P0 + P1): 3.5 hours
**Complete Implementation** (P0 + P1 + P2): 8.5 hours

---

## Migration Path for Existing Data

If Python findings already exist in database with uppercase severity:

```sql
-- Check for uppercase severities
SELECT DISTINCT severity FROM findings
WHERE tool IN ('graphcrawler', 'custom_idor');

-- Migrate to lowercase
UPDATE findings
SET severity = LOWER(severity)
WHERE tool IN ('graphcrawler', 'custom_idor')
  AND severity ~ '^[A-Z]';

-- Verify migration
SELECT tool, severity, COUNT(*) as count
FROM findings
GROUP BY tool, severity
ORDER BY tool, severity;
```

---

## Success Criteria

### Phase 1 (P0) Complete When:
- ✅ Python saves findings with lowercase severity
- ✅ Go CLI can query Python findings by severity
- ✅ Unit tests pass for severity normalization
- ✅ Migration script runs successfully

### All Phases Complete When:
- ✅ Go and Python use identical DATABASE_DSN format
- ✅ Structured logging works in Python
- ✅ Schema validation prevents drift
- ✅ Cross-language integration tests pass
- ✅ Documentation updated for unified database

---

## Recommendations

### Immediate Actions (Do Now)

1. **Fix Python severity case** (Phase 1)
   - Most critical issue
   - Blocks Go CLI functionality
   - Quick fix (1 hour)

2. **Run integration test** (Phase 5)
   - Verify fix works end-to-end
   - Test Python save → Go query
   - Catch any other compatibility issues

### Next Week Actions

3. **Standardize connection strings** (Phase 2)
4. **Add structured logging** (Phase 3)
5. **Create schema validation** (Phase 4)

### Long-Term Improvements

- Consider unified Go gRPC service for database access
  - Python calls Go service instead of direct PostgreSQL
  - Single database client implementation
  - Easier to maintain consistency

- Consider PostgreSQL stored procedures
  - Database-enforced consistency
  - Version-controlled in migrations
  - Language-agnostic interface

---

**Author**: Claude (Sonnet 4.5)
**Project**: Shells Security Scanner
**Date**: 2025-10-30
