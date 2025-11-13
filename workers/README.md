# Shells Python Worker Service

Python-based scanner service for Shells security scanner, providing REST API access to IDORD and GraphCrawler scanners with Redis Queue (RQ) job management.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Shells Go CLI/API                         │
│                  (pkg/workers/client.go)                     │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTP REST API
                         ▼
            ┌────────────────────────────┐
            │  FastAPI Server            │
            │  (service/main_rq.py)      │
            │  Port 8000                 │
            └────────────┬───────────────┘
                         │ Enqueue jobs
                         ▼
            ┌────────────────────────────┐
            │  Redis Queue (RQ)          │
            │  Queue: shells-scanners    │
            └────────────┬───────────────┘
                         │ Pop jobs
                         ▼
       ┌─────────────────────────────────────┐
       │  RQ Workers (4 processes)           │
       │  (service/tasks.py)                 │
       │  - run_graphql_scan()               │
       │  - run_idord_scan()                 │
       └─────────────────┬───────────────────┘
                         │ Execute
        ┌────────────────┴────────────────┐
        │                                 │
        ▼                                 ▼
┌───────────────────┐         ┌──────────────────┐
│  GraphCrawler     │         │  Custom IDOR     │
│  (GraphQL)        │         │  (IDOR Testing)  │
└─────────┬─────────┘         └────────┬─────────┘
          │                            │
          └────────────┬───────────────┘
                       │ Save findings
                       ▼
            ┌────────────────────────────┐
            │  PostgreSQL Database       │
            │  (findings table)          │
            └────────────────────────────┘
```

## Features

- **PostgreSQL Integration**: All findings automatically saved to PostgreSQL
- **Persistent Job Storage**: Redis Queue ensures jobs survive service restarts
- **Horizontal Scaling**: Run multiple RQ workers independently
- **Live Progress Tracking**: Job metadata updated during scan execution
- **Server-Sent Events**: Real-time result streaming via `/jobs/{id}/stream`
- **Comprehensive IDOR Testing**: UUID, numeric, and alphanumeric ID support
- **GraphQL Introspection**: Full GraphQL schema analysis

## Quick Start

### Local Development (Docker Compose)

```bash
# Build and start services
cd deployments/docker
docker-compose up -d shells-python-api shells-rq-workers

# Check health
curl http://localhost:8000/health

# Submit IDOR scan
curl -X POST http://localhost:8000/idor/scan \
  -H "Content-Type: application/json" \
  -d '{
    "endpoint": "https://api.example.com/users/{id}",
    "tokens": ["Bearer token1", "Bearer token2"],
    "start_id": 1,
    "end_id": 100,
    "id_type": "numeric"
  }'

# Get job status
curl http://localhost:8000/jobs/{job_id}

# Stream live results (SSE)
curl -N http://localhost:8000/jobs/{job_id}/stream
```

### Production Deployment (Nomad)

```bash
# Deploy to Nomad cluster
nomad job run deployments/nomad/shells-python-workers.nomad

# Check deployment status
nomad job status shells-python-workers

# Scale RQ workers
nomad job scale shells-python-workers workers 8

# Check worker logs
nomad alloc logs -f <alloc-id> rq-worker
```

### Manual Setup (Development)

```bash
# Install dependencies
cd workers
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Initialize git submodules (scanner tools)
git submodule update --init --recursive

# Start Redis (if not running)
docker run -d -p 6379:6379 redis:7-alpine

# Terminal 1: Start FastAPI server
cd workers
uvicorn service.main_rq:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2-5: Start RQ workers (4 processes)
cd workers
rq worker shells-scanners --url redis://localhost:6379
```

## API Endpoints

### GET /
Root endpoint with service information

### GET /health
Health check endpoint

**Response:**
```json
{
  "status": "healthy",
  "service": "Shells Worker Service",
  "version": "2.0.0",
  "redis": "healthy",
  "tools": {
    "idord": "available",
    "graphcrawler": "available"
  }
}
```

### POST /graphql/scan
Submit GraphQL scan job

**Request:**
```json
{
  "endpoint": "https://api.example.com/graphql",
  "auth_header": "Bearer token123",
  "output_file": "/tmp/scan-result.json"
}
```

**Response:**
```json
{
  "job_id": "abc-123-def-456",
  "status": "queued",
  "created_at": "2025-10-30T12:00:00Z"
}
```

### POST /idor/scan
Submit IDOR scan job

**Request:**
```json
{
  "endpoint": "https://api.example.com/users/{id}",
  "tokens": ["Bearer token1", "Bearer token2"],
  "start_id": 1,
  "end_id": 1000,
  "id_type": "uuid"
}
```

**Response:**
```json
{
  "job_id": "xyz-789-abc-123",
  "status": "queued",
  "created_at": "2025-10-30T12:00:00Z"
}
```

**ID Types:**
- `numeric`: Sequential numeric IDs (1, 2, 3, ...)
- `uuid`: UUID format (550e8400-e29b-41d4-a716-446655440000)
- `alphanumeric`: Mixed alphanumeric IDs (abc123, user_42)

### GET /jobs/{job_id}
Get job status and results

**Response:**
```json
{
  "job_id": "abc-123-def-456",
  "status": "finished",
  "created_at": "2025-10-30T12:00:00Z",
  "completed_at": "2025-10-30T12:05:00Z",
  "result": {
    "findings_count": 5,
    "findings": [...]
  },
  "meta": {
    "progress": 100,
    "findings_count": 5
  }
}
```

**Job Statuses:**
- `queued`: Job submitted, waiting for worker
- `started`: Worker picked up job, execution in progress
- `finished`: Job completed successfully
- `failed`: Job failed with error

### GET /jobs/{job_id}/stream
Stream job updates via Server-Sent Events (SSE)

**Example (curl):**
```bash
curl -N http://localhost:8000/jobs/{job_id}/stream
```

**Response (SSE format):**
```
data: {"job_id":"abc-123","status":"started","progress":10}

data: {"job_id":"abc-123","status":"started","progress":50,"findings_count":3}

data: {"job_id":"abc-123","status":"finished","progress":100,"findings_count":5}
```

### GET /jobs
List all jobs (with optional filtering)

**Query Parameters:**
- `status`: Filter by status (queued, finished, failed)
- `limit`: Max number of jobs to return (default: 100)

**Example:**
```bash
curl "http://localhost:8000/jobs?status=finished&limit=10"
```

## Go Client Integration

```go
import "github.com/CodeMonkeyCybersecurity/artemis/pkg/workers"

// Create client
client := workers.NewClient("http://localhost:8000")

// Submit IDOR scan
ctx := context.Background()
status, err := client.ScanIDOR(ctx, "https://api.example.com/users/{id}",
    []string{"token1", "token2"}, 1, 100)

// Poll for completion
finalStatus, err := client.WaitForCompletion(ctx, status.JobID, 2*time.Second)

// Stream results (real-time)
ch, err := client.StreamJobResults(ctx, status.JobID)
for update := range ch {
    fmt.Printf("Progress: %d%%, Findings: %d\n",
        update.Meta["progress"], update.Meta["findings_count"])
}
```

## Scanner Tool Details

### IDORD (Insecure Direct Object Reference Detector)

**Location:** `workers/tools/idord/`

**Capabilities:**
- Numeric ID testing (1, 2, 3, ...)
- UUID testing (550e8400-e29b-41d4-a716-446655440000)
- Alphanumeric ID testing (user_42, abc123)
- Smart fuzzing (ID mutations: ±1, ±10, *2, /2)
- Custom header/cookie support
- Multi-user token comparison

**Usage via API:**
```bash
curl -X POST http://localhost:8000/idor/scan \
  -H "Content-Type: application/json" \
  -d '{
    "endpoint": "https://api.example.com/api/v1/users/{id}/profile",
    "tokens": [
      "Bearer user1_token",
      "Bearer user2_token"
    ],
    "start_id": 1,
    "end_id": 1000,
    "id_type": "uuid"
  }'
```

### GraphCrawler (GraphQL Schema Crawler)

**Location:** `workers/tools/graphcrawler/`

**Capabilities:**
- GraphQL introspection query
- Schema enumeration
- Query/mutation discovery
- Type analysis
- Authentication-aware crawling

**Usage via API:**
```bash
curl -X POST http://localhost:8000/graphql/scan \
  -H "Content-Type: application/json" \
  -d '{
    "endpoint": "https://api.example.com/graphql",
    "auth_header": "Bearer admin_token"
  }'
```

## PostgreSQL Integration

All findings discovered by Python scanners are automatically saved to the Shells PostgreSQL database.

### Database Schema

Findings are saved to the `findings` table with this structure:

```sql
CREATE TABLE findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id),
    tool TEXT NOT NULL,              -- "graphcrawler" or "custom_idor"
    type TEXT NOT NULL,              -- "IDOR", "GraphQL_Finding"
    severity TEXT NOT NULL,          -- "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    title TEXT NOT NULL,
    description TEXT,
    evidence TEXT,
    solution TEXT,
    refs JSONB,                      -- Reference URLs/CVEs
    metadata JSONB,                  -- Scanner-specific metadata
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);
```

### Environment Variables

Set `POSTGRES_DSN` environment variable for database connection:

```bash
# Docker Compose (automatic)
POSTGRES_DSN=postgresql://shells:password@postgres:5432/shells

# Manual setup
export POSTGRES_DSN=postgresql://user:password@localhost:5432/shells
```

### Querying Findings

Use Shells Go CLI to query findings saved by Python workers:

```bash
# Query all findings from Python scanners
shells results query --tool graphcrawler
shells results query --tool custom_idor

# Query by severity
shells results query --severity CRITICAL

# Query by scan ID
shells results query --scan-id abc-123-def-456

# Export findings to JSON
shells results export scan-123 --format json
```

### Database Client API

Python workers use `workers/service/database.py` for PostgreSQL operations:

```python
from workers.service.database import get_db_client

db = get_db_client()

# Save single finding
# Note: Severity is automatically normalized to lowercase (matches Go format)
finding_id = db.save_finding(
    scan_id="scan-123",
    tool="custom_idor",
    finding_type="IDOR",
    severity="HIGH",  # Accepts uppercase, lowercase, or mixed case
    title="User can access other users' data",
    description="User B can read User A's profile",
    evidence="GET /api/users/123 -> 200 OK",
    metadata={"user_id": 123, "endpoint": "/api/users/{id}"}
)
# Saves as "high" in database (lowercase)

# Save multiple findings in batch
findings = [{"type": "IDOR", "severity": "HIGH", "title": "..."}]
finding_ids = db.save_findings_batch(scan_id, "custom_idor", findings)

# Query findings (use lowercase severity)
critical_findings = db.get_findings_by_severity(scan_id, "critical")
total_count = db.get_scan_findings_count(scan_id)
```

#### Severity Normalization

**IMPORTANT**: All severity values are automatically normalized to lowercase before saving to the database.

**Why?** Go uses lowercase severity constants (`"critical"`, `"high"`, `"medium"`, `"low"`, `"info"`), and the Go CLI queries with lowercase values. This ensures Python findings are queryable by Go.

**Compatibility**:
- ✅ Accepts: `"CRITICAL"`, `"critical"`, `"CrItIcAl"` (all work)
- ✅ Saves as: `"critical"` (always lowercase in database)
- ✅ Go CLI: `shells results query --severity critical` (finds Python findings)

**Valid Severity Values** (case-insensitive):
- `critical` / `CRITICAL`
- `high` / `HIGH`
- `medium` / `MEDIUM`
- `low` / `LOW`
- `info` / `INFO`

**Migration for Existing Data**:

If you have existing findings with uppercase severity values:

```bash
# Run migration script
psql $DATABASE_DSN -f workers/migrate_severity_case.sql

# Or with docker-compose
docker-compose exec postgres psql -U shells -d shells -f /app/workers/migrate_severity_case.sql
```

## Troubleshooting

### PostgreSQL Connection Failed

```bash
# Check PostgreSQL is running
docker ps | grep postgres

# Test PostgreSQL connection
psql postgresql://shells:password@localhost:5432/shells -c "SELECT 1"

# Check environment variable
echo $POSTGRES_DSN
```

### Redis Connection Failed

```bash
# Check Redis is running
docker ps | grep redis

# Test Redis connection
redis-cli -h localhost -p 6379 ping
# Should return: PONG

# Check Redis URL in environment
echo $REDIS_URL
```

### Scanner Tools Not Found

```bash
# Verify git submodules are initialized
git submodule status

# Should show:
# 8b2ae878276ab588232477ef8a95e60fb2b50242 workers/tools/graphcrawler (v1.2-16-g8b2ae87)
# be3c49b20af263bf510ebec847b60ac2a4f47171 workers/tools/idord (1.0.0-8-gbe3c49b)

# If not initialized:
git submodule update --init --recursive
```

### RQ Workers Not Processing Jobs

```bash
# Check RQ worker status
rq info --url redis://localhost:6379

# Should show:
# shells-scanners |█████████ 0
# 4 workers, ...

# Check worker logs
docker-compose logs -f shells-rq-workers

# Manually start worker with verbose logging
rq worker shells-scanners --url redis://localhost:6379 --verbose
```

## Testing

### Running Unit Tests

Unit tests use mocked dependencies and don't require external services:

```bash
# Run all unit tests
./workers/run_tests.sh

# Run with coverage report
./workers/run_tests.sh --cov

# Run specific test
./workers/run_tests.sh -k test_validate_url

# Run specific test file
pytest workers/tests/test_database.py -v
```

**Test Coverage**:
- `tests/test_database.py` - Database client unit tests (mocked PostgreSQL)
- `tests/test_tasks.py` - Scanner task unit tests (mocked subprocess, Redis, PostgreSQL)
- `tests/test_integration_e2e.py` - End-to-end integration tests (requires services)

### Running Integration Tests

Integration tests require Redis and PostgreSQL:

```bash
# Start services
docker-compose up -d redis postgres

# Set environment variable
export POSTGRES_DSN="postgresql://shells:password@localhost:5432/shells"

# Run integration tests
pytest workers/tests/ -v -m integration

# Run specific integration test
pytest workers/tests/test_integration_e2e.py::TestEndToEndWorkflow::test_graphql_scan_full_workflow -v
```

### Manual Testing

Test database integration directly:

```bash
# Test database connection and operations
python3 workers/test_database.py

# Expected output:
# ✓ Database connection successful
# ✓ Finding saved successfully
# ✓ Batch saved successfully
# Passed: 5/5
```

Test API endpoints with curl:

```bash
# Submit GraphQL scan
curl -X POST http://localhost:8000/graphql/scan \
  -H "Content-Type: application/json" \
  -d '{"endpoint": "https://api.github.com/graphql"}'

# Check job status
curl http://localhost:8000/jobs/{job_id}

# Stream live results
curl -N http://localhost:8000/jobs/{job_id}/stream
```

### Job Failed with Timeout

IDORD and GraphCrawler scans have timeouts:
- GraphQL scan: 30 minutes
- IDOR scan: 60 minutes

Adjust timeouts in `workers/service/tasks.py`:
```python
result = subprocess.run(
    cmd,
    timeout=3600,  # Increase to 60 minutes
    ...
)
```

## Monitoring

### RQ Dashboard (Optional)

```bash
# Install RQ Dashboard
pip install rq-dashboard

# Run dashboard
rq-dashboard --redis-url redis://localhost:6379

# Access at http://localhost:9181
```

### Prometheus Metrics (Coming Soon)

Future integration with Prometheus for:
- Job queue depth
- Worker utilization
- Scan success/failure rates
- Average scan duration

## Development

### Running Tests

```bash
cd workers
pytest tests/
```

### Adding New Scanner

1. Add scanner tool as git submodule:
```bash
git submodule add https://github.com/user/scanner workers/tools/scanner
```

2. Create task function in `workers/service/tasks.py`:
```python
def run_scanner_scan(target: str):
    job = get_current_job()
    # ... implementation
```

3. Add API endpoint in `workers/service/main_rq.py`:
```python
@app.post("/scanner/scan")
async def scan_scanner(request: ScannerRequest):
    job = job_queue.enqueue("workers.service.tasks.run_scanner_scan", ...)
    return JobStatus(job_id=job.id, ...)
```

4. Update Dockerfile to install scanner dependencies

## License

See main Shells project LICENSE.
