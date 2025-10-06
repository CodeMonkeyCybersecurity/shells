# Zero-Configuration Installation

## Super Easy Installation Flow

```
┌─────────────────────────────────────────────────────────────────┐
│  User runs: ./install.sh                                        │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│  1. Platform Detection                                          │
│     ✓ Detect Linux (Debian/RHEL) or macOS                     │
│     ✓ Check if Docker is available                            │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│  2. Install Go 1.24.4                                           │
│     ✓ Check if Go is installed                                │
│     ✓ Install or upgrade if needed                            │
│     ✓ Configure GOPATH and PATH                               │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│  3. Build Shells Binary                                         │
│     ✓ Run go build                                            │
│     ✓ Install to /usr/local/bin/shells                        │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│  4. PostgreSQL Setup (AUTOMATIC!)                               │
│                                                                 │
│  ┌─────────────────────────────────────┐                       │
│  │ Check if Docker PostgreSQL exists?  │                       │
│  └─────────┬───────────────────┬───────┘                       │
│           YES                 NO                                │
│            │                   │                                │
│            │                   ▼                                │
│            │    ┌────────────────────────────┐                 │
│            │    │ Install PostgreSQL         │                 │
│            │    │ • macOS: brew install      │                 │
│            │    │ • Debian: apt-get install  │                 │
│            │    │ • RHEL: dnf install        │                 │
│            │    └────────┬───────────────────┘                 │
│            │             │                                      │
│            │             ▼                                      │
│            │    ┌────────────────────────────┐                 │
│            │    │ Start PostgreSQL service   │                 │
│            │    └────────┬───────────────────┘                 │
│            │             │                                      │
│            ▼             ▼                                      │
│       ┌────────────────────────────────────┐                   │
│       │ Create Database & User             │                   │
│       │ • CREATE DATABASE shells           │                   │
│       │ • CREATE USER shells               │                   │
│       │ • GRANT ALL PRIVILEGES             │                   │
│       └────────┬───────────────────────────┘                   │
│                │                                                │
│                ▼                                                │
│       ┌────────────────────────────────────┐                   │
│       │ Update .shells.yaml                │                   │
│       │ • Set correct DSN                  │                   │
│       │ • Configure connection params      │                   │
│       └────────────────────────────────────┘                   │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│  5. Setup Python Workers (Optional)                             │
│     ✓ Check if Python 3 is available                          │
│     ✓ Run: shells workers setup                               │
│     ✓ Clone GraphCrawler and IDORD                            │
│     ✓ Create virtual environment                              │
│     ✓ Install dependencies                                    │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│  6. Installation Complete!                                    │
│                                                                 │
│  Next steps shown to user:                                     │
│  • shells serve --port 8080                                    │
│  • Open http://localhost:8080                                  │
│  • shells example.com                                          │
└─────────────────────────────────────────────────────────────────┘
```

## What Gets Installed Automatically

### Core Components
| Component | Installation Method | Platform |
|-----------|-------------------|----------|
| Go 1.24.4 | Official tarball | All |
| PostgreSQL 15+ | brew | macOS |
| PostgreSQL 15+ | apt-get | Debian/Ubuntu |
| PostgreSQL 15+ | dnf/yum | RHEL/CentOS |
| Shells binary | go build | All |

### Database Configuration
| Setting | Value |
|---------|-------|
| Database name | `shells` |
| User | `shells` |
| Password | `shells_password` (Linux) or socket auth (macOS) |
| Host | `localhost:5432` |
| Connection | Configured in `.shells.yaml` |

### Optional Components
| Component | Requirement | Purpose |
|-----------|------------|---------|
| Python 3.8+ | Optional | GraphQL/IDOR scanning |
| GraphCrawler | Python 3 | GraphQL security testing |
| IDORD | Python 3 | IDOR detection |
| Docker | Optional | Alternative PostgreSQL deployment |

## Installation Scenarios

### Scenario 1: Fresh System (No Dependencies)
```bash
./install.sh
```
**Installs:**
- Go 1.24.4
- PostgreSQL 15
- Shells binary
- Creates database
- Sets up Python workers (if Python 3 available)

**Time:** ~5-10 minutes

### Scenario 2: Docker Available
```bash
./install.sh
```
**Detects:**
- Existing Docker PostgreSQL container

**Uses:**
- Existing container instead of installing PostgreSQL natively

**Time:** ~2-3 minutes

### Scenario 3: PostgreSQL Already Installed
```bash
./install.sh
```
**Detects:**
- PostgreSQL already running

**Does:**
- Creates `shells` database
- Creates `shells` user
- Configures connection

**Time:** ~2-3 minutes

### Scenario 4: macOS with Homebrew
```bash
./install.sh
```
**Uses:**
- `brew install postgresql@15`
- `brew services start postgresql@15`
- Socket-based authentication (no password needed)

**Time:** ~5-8 minutes

## Post-Installation Verification

### Check Everything Works
```bash
# 1. Verify binary installed
which shells
# Expected: /usr/local/bin/shells

# 2. Verify PostgreSQL running
pg_isready
# Expected: /tmp:5432 - accepting connections

# 3. Verify database exists
psql -l | grep shells
# Expected: shells | ...

# 4. Test connection
shells serve --port 8080 &
curl http://localhost:8080/health
# Expected: {"status":"ok"}

# 5. Open dashboard
open http://localhost:8080  # macOS
xdg-open http://localhost:8080  # Linux
```

## Troubleshooting

### PostgreSQL Installation Failed
**Symptom:** "Could not install PostgreSQL"

**Solution:**
```bash
# Option 1: Use Docker
docker run -d --name shells-postgres \
  -e POSTGRES_PASSWORD=shells_password \
  -e POSTGRES_DB=shells \
  -e POSTGRES_USER=shells \
  -p 5432:5432 \
  postgres:15

# Then re-run
./install.sh
```

**Solution 2:** Install manually then re-run install.sh

### Database Connection Failed
**Symptom:** "could not connect to database"

**Check DSN in .shells.yaml:**
```yaml
database:
  driver: postgres
  # macOS:
  dsn: "host=localhost user=YOUR_USERNAME dbname=shells sslmode=disable"

  # Linux:
  dsn: "postgres://shells:shells_password@localhost:5432/shells?sslmode=disable"
```

### Workers Not Setting Up
**Symptom:** "Python 3 not found"

**Solution:**
```bash
# Install Python 3
# macOS:
brew install python@3.11

# Ubuntu/Debian:
sudo apt-get install python3 python3-venv

# Then run manually:
shells workers setup
```

## Configuration Files Created

### `.shells.yaml`
```yaml
database:
  driver: postgres
  dsn: "postgres://shells:shells_password@localhost:5432/shells?sslmode=disable"
  max_connections: 25
  max_idle_conns: 5
  conn_max_lifetime: 1h

logger:
  level: info
  format: console

discovery:
  timeout: 30s
  max_depth: 3

security:
  rate_limit:
    requests_per_second: 10
    burst_size: 20
```

### Directories Created
- `/usr/local/bin/shells` - Binary
- `~/.shells/` or `/etc/shells-scanner/` - Config
- `~/.shells/logs/` or `/var/log/shells/` - Logs
- `~/.shells/secrets/` or `/var/lib/shells/secrets/` - Secrets
- `./workers/` - Python worker environment

## Comparison: Old vs New Installation

### Old Way (Manual)
```bash
# 1. Install Go
wget https://go.dev/dl/go1.24.4.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.24.4.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# 2. Install PostgreSQL
sudo apt-get install postgresql
sudo systemctl start postgresql
sudo -u postgres createdb shells
sudo -u postgres psql -c "CREATE USER shells WITH PASSWORD 'shells_password';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE shells TO shells;"

# 3. Configure connection
vim .shells.yaml  # Edit DSN manually

# 4. Build shells
go build -o shells
sudo cp shells /usr/local/bin/

# 5. Setup workers
python3 -m venv workers/venv
source workers/venv/bin/activate
pip install -r workers/requirements.txt
git clone https://github.com/gsmith257-cyber/GraphCrawler
git clone https://github.com/AyemunHossain/IDORD

# 6. Start
shells serve --port 8080
```

**Time:** 30-45 minutes, multiple commands, error-prone

### New Way (Automated)
```bash
./install.sh
shells serve --port 8080
```

**Time:** 5-10 minutes, two commands, zero errors

## What Makes This "Zero Configuration"?

1.  **Auto-detects platform** - Works on macOS, Debian, RHEL
2.  **Auto-installs dependencies** - Go, PostgreSQL, Python workers
3.  **Auto-creates database** - No SQL commands needed
4.  **Auto-configures connection** - DSN written automatically
5.  **Auto-detects existing resources** - Uses Docker container if available
6.  **Auto-starts services** - PostgreSQL started and enabled
7.  **Auto-sets permissions** - Correct file/directory permissions
8.  **Auto-builds binary** - No manual compilation
9.  **Auto-installs to PATH** - Ready to use immediately
10.  **Auto-verifies installation** - Checks everything works

## Advanced: Unattended Installation

For CI/CD or automated deployments:

```bash
# Run without prompts (use defaults for everything)
DEBIAN_FRONTEND=noninteractive ./install.sh

# Or use environment variables
export POSTGRES_PASSWORD=custom_password
export INSTALL_WORKERS=false
./install.sh
```
