# Docker Architecture

## Container Network Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                     Docker Network: shells                       │
│                                                                   │
│  ┌──────────────┐           ┌────────────────────────────┐      │
│  │   User       │──HTTP───► │     shells-api:8080        │      │
│  │   Browser    │           │  - Web Dashboard (/)       │      │
│  └──────────────┘           │  - API (/api/v1)           │      │
│                             │  - Hera Extension API      │      │
│                             └────┬─────────────┬─────────┘      │
│                                  │             │                 │
│                             ┌────▼─────┐  ┌───▼──────┐         │
│                             │PostgreSQL│  │  Redis   │         │
│                             │  :5432   │  │  :6379   │         │
│  ┌──────────────┐           └────┬─────┘  └───┬──────┘         │
│  │webscan-worker│◄───reads/writes─┘           │                │
│  │  (replica 1) │                              │                │
│  └──────┬───────┘           ┌──────────────────▼────┐          │
│         │                   │  otel-collector        │          │
│  ┌──────▼───────┐           │  - Metrics :8888       │          │
│  │webscan-worker│───logs───►│  - Traces  :4317       │          │
│  │  (replica 2) │           └────────────────────────┘          │
│  └──────┬───────┘                                                │
│         │                   ┌──────────────────────┐            │
│  ┌──────▼───────┐           │  nmap                │            │
│  │webscan-worker│──calls───►│  Network scanning    │            │
│  │  (replica 3) │           └──────────────────────┘            │
│  └──────────────┘                                                │
│                             ┌──────────────────────┐            │
│                             │  zap :8090           │            │
│                             │  OWASP ZAP Proxy     │            │
│                             └──────────────────────┘            │
└─────────────────────────────────────────────────────────────────┘
```

## Data Flow

### 1. User Initiates Scan (via Web Dashboard)
```
Browser → shells-api:8080 → PostgreSQL (creates scan record)
                          → Redis (enqueues job)
```

### 2. Worker Picks Up Job
```
webscan-worker → Redis (dequeues job)
               → PostgreSQL (updates scan status to "running")
               → nmap/zap (executes security tests)
               → PostgreSQL (saves findings)
```

### 3. User Views Results
```
Browser → shells-api:8080/api/dashboard/scans
        ← PostgreSQL (retrieves scan + findings)
        ← JSON response with findings
```

## Key Architectural Decisions

### Single PostgreSQL Instance
**Problem**: Running PostgreSQL in a container and shells natively would create two separate databases.

**Solution**: Docker Compose architecture ensures:
- All containers connect to the same `postgres` service
- Connection string: `postgres://shells:password@postgres:5432/shells`
- Persistent volume: `postgres_data` survives container restarts
- No data duplication between API and workers

### Worker Architecture
**Why 3 replicas?**
- Parallel scanning of multiple targets
- Fault tolerance (if one worker crashes, others continue)
- Can scale to 10+ workers: `docker-compose up -d --scale webscan-worker=10`

**Worker coordination via Redis**:
- Workers poll Redis for jobs
- Atomic job dequeue prevents duplicate work
- Status updates written to PostgreSQL

### Network Isolation
All containers run in the same Docker network:
- Internal DNS: `postgres`, `redis`, `otel-collector` resolve automatically
- No need for hardcoded IPs
- Containers can't be accessed from outside except via exposed ports

## Deployment Scenarios

### Development (Native)
```bash
# Run PostgreSQL in Docker
docker run -d --name postgres -p 5432:5432 -e POSTGRES_PASSWORD=shells_password postgres:15

# Run shells natively
./shells serve --port 8080
```

**Pros**: Fast iteration, easy debugging
**Cons**: Single worker, manual PostgreSQL setup

### Production (Docker Compose)
```bash
cd deployments/docker
docker-compose up -d
```

**Pros**: Full stack, scalable, persistent storage
**Cons**: Slower iteration (rebuild on code changes)

### Hybrid (PostgreSQL in Docker, shells native)
```bash
# Start only PostgreSQL
docker-compose up -d postgres

# Run shells natively
./shells serve --port 8080
```

**Pros**: Fast iteration + persistent database
**Cons**: Still single worker

## Environment Variables

All containers accept these environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `WEBSCAN_DATABASE_DRIVER` | `postgres` | Database driver |
| `WEBSCAN_DATABASE_DSN` | `postgres://shells:password@postgres:5432/shells?sslmode=disable` | PostgreSQL connection string |
| `WEBSCAN_REDIS_ADDR` | `redis:6379` | Redis address for job queue |
| `WEBSCAN_TELEMETRY_ENDPOINT` | `otel-collector:4317` | OpenTelemetry collector endpoint |
| `POSTGRES_PASSWORD` | `shells_dev_password` | PostgreSQL password (set via `.env` file) |

## Monitoring

### Check container health
```bash
docker-compose ps
```

### View real-time logs
```bash
# All containers
docker-compose logs -f

# Specific service
docker-compose logs -f shells-api
docker-compose logs -f webscan-worker
```

### Database access
```bash
# Connect to PostgreSQL
docker-compose exec postgres psql -U shells -d shells

# Run SQL query
docker-compose exec postgres psql -U shells -d shells -c "SELECT COUNT(*) FROM scans;"
```

### Redis queue status
```bash
# Connect to Redis
docker-compose exec redis redis-cli

# Check queue length
redis> LLEN scan_queue
```

## Troubleshooting

### "Database is readonly"
**Cause**: Running shells natively while pointing to SQLite instead of PostgreSQL

**Fix**: Update `.shells.yaml`:
```yaml
database:
  driver: postgres
  dsn: "postgres://shells:shells_password@localhost:5432/shells?sslmode=disable"
```

### "Connection refused to PostgreSQL"
**Cause**: PostgreSQL container not running or wrong host

**Fix**:
```bash
# Check if PostgreSQL is running
docker-compose ps postgres

# If not running, start it
docker-compose up -d postgres

# Verify connection
docker-compose exec postgres pg_isready -U shells
```

### "Workers not picking up jobs"
**Cause**: Redis connection issue or no workers running

**Fix**:
```bash
# Check worker logs
docker-compose logs webscan-worker

# Restart workers
docker-compose restart webscan-worker

# Verify Redis is accessible
docker-compose exec redis redis-cli ping
```

## Scaling

### Horizontal scaling (more workers)
```bash
# Scale to 10 workers
docker-compose up -d --scale webscan-worker=10

# Verify
docker-compose ps webscan-worker
```

### Vertical scaling (more resources)
Edit `docker-compose.yml`:
```yaml
webscan-worker:
  deploy:
    resources:
      limits:
        cpus: '2'
        memory: 4G
```

## Data Persistence

### Volumes
- `postgres_data`: PostgreSQL data directory
- `redis_data`: Redis persistence

### Backup PostgreSQL
```bash
# Export database
docker-compose exec postgres pg_dump -U shells shells > backup.sql

# Restore database
docker-compose exec -T postgres psql -U shells shells < backup.sql
```

### Reset everything
```bash
# Stop and remove all data
docker-compose down -v

# Start fresh
docker-compose up -d
```
