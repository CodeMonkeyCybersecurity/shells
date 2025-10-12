# Self-Update Feature

## Overview

Shells includes a built-in self-update mechanism that safely updates your installation to the latest version from the git repository. The update process follows the **Assess → Intervene → Evaluate** pattern to ensure safe, reliable updates.

## Quick Usage

```bash
# Update to latest version from main branch
shells self update

# Update from a specific branch
shells self update --branch develop

# Update without creating backup (not recommended)
shells self update --skip-backup

# Use custom source directory
shells self update --source /path/to/shells/repo
```

## How It Works

### 1. **Assess** - Current State Analysis
```
┌─────────────────────────────────────────────────────────────┐
│  Assess Phase                                               │
├─────────────────────────────────────────────────────────────┤
│  ✓ Check if source directory exists                        │
│  ✓ Verify it's a git repository                            │
│  ✓ Check if binary exists at /usr/local/bin/shells         │
│  ✓ Find existing backups                                   │
│  ✓ Get current git commit/version                          │
└─────────────────────────────────────────────────────────────┘
```

**What happens:**
- Checks if `/opt/shells` (or custom source) exists and is a git repo
- Verifies current binary location
- Counts existing backups
- Records current git commit SHA

**If checks fail:**
- Missing source → Error with instructions to clone repository
- Not a git repo → Error explaining repository requirement
- No binary → Warning (update will create new installation)

### 2. **Intervene** - Perform Update
```
┌─────────────────────────────────────────────────────────────┐
│  Intervene Phase                                            │
├─────────────────────────────────────────────────────────────┤
│  Step 1: Create backup                                     │
│    • Copy current binary to shells.backup.<timestamp>      │
│    • Cleanup old backups (keep 5 most recent)              │
│                                                             │
│  Step 2: Pull latest code                                  │
│    • git fetch origin <branch>                             │
│    • Check how many commits behind                         │
│    • git pull origin <branch>                              │
│                                                             │
│  Step 3: Build new binary                                  │
│    • Run go mod tidy                                       │
│    • Detect target architecture                            │
│    • Build to temporary location                           │
│    • Verify binary size (must be ≥10MB)                    │
│    • Set execute permissions                               │
└─────────────────────────────────────────────────────────────┘
```

**What happens:**

**Step 1 - Backup:**
- Creates `/usr/local/bin/shells.backup.1733123456` (timestamp)
- Keeps only 5 most recent backups
- Can be skipped with `--skip-backup` (not recommended)

**Step 2 - Pull Code:**
- Fetches latest changes from git
- Shows how many commits behind you are
- If already up-to-date, exits early
- Pulls changes to source directory

**Step 3 - Build:**
- Runs `go mod tidy` to update dependencies
- Builds to `/tmp/shells-update-<timestamp>`
- Validates binary is at least 10MB (catches build failures)
- Sets executable permissions (0755)

### 3. **Evaluate** - Validate & Install
```
┌─────────────────────────────────────────────────────────────┐
│  Evaluate Phase                                             │
├─────────────────────────────────────────────────────────────┤
│  Step 1: Validate binary                                   │
│    • Check it's a valid executable (file command)          │
│    • Run --version to test execution                       │
│    • Verify output contains "shells" markers               │
│                                                             │
│  Step 2: Install binary                                    │
│    • Atomic rename if on same filesystem                   │
│    • Or copy and delete if across filesystems              │
│    • Preserve permissions                                  │
│                                                             │
│  Step 3: Final verification                                │
│    • Run installed binary with --version                   │
│    • Confirm it works correctly                            │
└─────────────────────────────────────────────────────────────┘
```

**What happens:**

**Step 1 - Validation:**
- Uses `file` command to check it's a real executable
- Runs new binary with `--version` flag
- Checks output contains expected strings
- Can be skipped with `--skip-validation` (dangerous!)

**Step 2 - Installation:**
- Tries atomic rename first (instant, no race condition)
- Falls back to copy if rename fails (across filesystems)
- Removes temporary file after successful install

**Step 3 - Verification:**
- Runs newly installed binary
- Confirms it executes correctly
- Logs warning if verification fails (but update is complete)

## Update Process Flow

```
┌──────────────────────────────────────────────────────────────────────┐
│  User runs: shells self update                                      │
└────────────────┬─────────────────────────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│  ASSESS: Check current state                                         │
│  ✓ Source exists at /opt/shells                                     │
│  ✓ Is git repository                                                │
│  ✓ Binary exists at /usr/local/bin/shells                           │
│  ✓ Current version: abc1234                                         │
│  ✓ Found 3 backups                                                  │
└────────────────┬─────────────────────────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│  INTERVENE: Create backup                                            │
│  ✓ Created /usr/local/bin/shells.backup.1733123456                  │
│  ✓ Cleaned up 0 old backups (keeping 5)                             │
└────────────────┬─────────────────────────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│  INTERVENE: Pull latest code                                         │
│  ✓ git fetch origin main                                            │
│  ✓ You are 12 commits behind                                        │
│  ✓ git pull origin main                                             │
│  ✓ Pulled 12 commits                                                │
└────────────────┬─────────────────────────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│  INTERVENE: Build new binary                                         │
│  ✓ go mod tidy                                                      │
│  ✓ Building for linux/amd64                                         │
│  ✓ go build -o /tmp/shells-update-1733123456                        │
│  ✓ Binary size: 42.5 MB                                             │
│  ✓ Set execute permissions                                          │
└────────────────┬─────────────────────────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│  EVALUATE: Validate binary                                           │
│  ✓ file check: ELF 64-bit LSB executable                            │
│  ✓ Execution test: shells --version successful                      │
│  ✓ Output contains "shells" marker                                  │
└────────────────┬─────────────────────────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│  EVALUATE: Install binary                                            │
│  ✓ Atomic rename to /usr/local/bin/shells                           │
│  ✓ Removed temporary file                                           │
└────────────────┬─────────────────────────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│  EVALUATE: Final verification                                        │
│  ✓ shells --version works                                           │
│  ✓ Update completed successfully                                    │
└──────────────────────────────────────────────────────────────────────┘
```

## Command Line Options

| Flag | Default | Description |
|------|---------|-------------|
| `--branch` | `main` | Git branch to update from |
| `--source` | `/opt/shells` | Path to shells git repository |
| `--skip-backup` | `false` | Skip creating backup (not recommended) |
| `--skip-validation` | `false` | Skip validating new binary (dangerous!) |

## Examples

### Standard Update
```bash
shells self update
```
Output:
```
[INFO] Assessing Shells installation state
[INFO] Assessment complete source_exists=true git_repository=true binary_exists=true current_version=abc1234 backup_count=3
[INFO] Creating backup of current binary backup_path=/usr/local/bin/shells.backup.1733123456
[INFO] Backup created successfully backup_path=/usr/local/bin/shells.backup.1733123456 size_bytes=44567890
[INFO] Pulled latest changes from git repository branch=main source_dir=/opt/shells
[INFO] Updates available commits_behind=12
[INFO] Git pull completed output=Updating abc1234..def5678
[INFO] Building Shells binary temp_path=/tmp/shells-update-1733123456 source_dir=/opt/shells
[INFO] Building for architecture os=linux arch=amd64
[INFO] Binary built successfully size_bytes=44567890 size_mb=42.50 MB
[INFO] Validating new binary
[INFO] Binary validation successful has_shells_marker=true has_commands=true has_usage=true
[INFO] Installing new binary destination=/usr/local/bin/shells
[INFO] Binary installation completed successfully
[INFO] Verifying installed Shells binary
[INFO] Shells binary verified successfully
[INFO] Shells self-update completed successfully

 Shells updated successfully!
   Duration: 45s

Run 'shells --version' to verify the new version
```

### Update from Development Branch
```bash
shells self update --branch develop
```

### Update Without Backup (Dangerous!)
```bash
shells self update --skip-backup
```
 **Not recommended** - if the update fails, you won't be able to roll back.

### Custom Source Directory
```bash
shells self update --source ~/projects/shells
```

## What Gets Updated

| Component | Updated | Preserved |
|-----------|---------|-----------|
| Binary (`/usr/local/bin/shells`) |  Yes | Backup created |
| Source code (`/opt/shells`) |  Yes | Via git pull |
| Database |  No |  Preserved |
| Configuration (`.shells.yaml`) |  No |  Preserved |
| Logs |  No |  Preserved |
| Scan results |  No |  Preserved |
| Python workers |  No | Re-run `shells workers setup` if needed |

**Important:** Your data is safe! Updates only affect the binary and source code.

## Troubleshooting

### Error: "shells source directory not found"
**Cause:** Source directory doesn't exist or isn't a git repository

**Solution:**
```bash
# Clone the repository to /opt/shells
sudo mkdir -p /opt
sudo git clone https://github.com/CodeMonkeyCybersecurity/shells /opt/shells

# Then try update again
shells self update
```

### Error: "already up to date"
**Cause:** No new commits available on the branch

**Solution:** You're already on the latest version! If you want to force a rebuild:
```bash
cd /opt/shells
git pull origin main
go build -o /usr/local/bin/shells
```

### Error: "build failed"
**Cause:** Build errors in new code, or missing dependencies

**Solution:**
```bash
# Check what's wrong
cd /opt/shells
go build -o shells

# If dependencies are missing
go mod tidy
go build -o shells

# If that works, try update again
shells self update
```

### Error: "binary validation failed"
**Cause:** New binary doesn't execute or produces unexpected output

**Solution:**
```bash
# Test the binary manually
cd /opt/shells
go build -o shells-test
./shells-test --version

# If it works, try skipping validation (be careful!)
shells self update --skip-validation
```

### Rollback to Previous Version
If the update causes problems, restore from backup:

```bash
# Find latest backup
ls -lt /usr/local/bin/shells.backup.* | head -1

# Restore it
sudo cp /usr/local/bin/shells.backup.1733123456 /usr/local/bin/shells

# Verify
shells --version
```

## Safety Features

### 1. Automatic Backups
- Creates timestamped backup before every update
- Keeps 5 most recent backups (configurable in code)
- Backups stored in same directory as binary

### 2. Build Validation
- Checks binary size (must be ≥10MB)
- Runs `file` command to verify it's an executable
- Tests execution with `--version` flag
- Validates output contains expected markers

### 3. Atomic Installation
- Uses atomic rename when possible (no race condition)
- Falls back to copy + delete if needed
- Preserves file permissions

### 4. Git Safety
- Never runs destructive git commands
- Only fetches and pulls
- Doesn't modify git history
- Works with any branch

### 5. Rollback Capability
- Backups make it easy to roll back
- Database and config never touched
- Can restore in seconds

## Automation

### Cron Job for Auto-Update
```bash
# Update daily at 3am
0 3 * * * /usr/local/bin/shells self update >> /var/log/shells-update.log 2>&1
```

### Update on Boot
```bash
# systemd service
cat > /etc/systemd/system/shells-update.service << 'EOF'
[Unit]
Description=Shells Self-Update
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/shells self update
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Enable
sudo systemctl enable shells-update.service
```

## Security Considerations

### Source Trust
- Only pulls from configured git repository
- No automatic execution of downloaded code
- Build happens locally from source

### Binary Verification
- Validates binary before installation
- Tests execution in sandbox (just --version)
- Checks for expected output patterns

### Backup Strategy
- Always creates backup unless explicitly disabled
- Keeps multiple versions for safety
- Backups are full copies, not diffs

### Permissions
- Requires write access to binary location
- May need sudo if installed to `/usr/local/bin`
- Doesn't modify system packages or files

## Advanced Usage

### CI/CD Integration
```bash
#!/bin/bash
# update-shells.sh - CI/CD update script

set -e

# Pull latest
cd /opt/shells
git fetch origin main

# Check if updates available
BEHIND=$(git rev-list --count HEAD..origin/main)
if [ "$BEHIND" -eq 0 ]; then
  echo "Already up to date"
  exit 0
fi

echo "Updates available: $BEHIND commits"

# Backup current binary
cp /usr/local/bin/shells /backup/shells.$(date +%Y%m%d-%H%M%S)

# Update
shells self update

# Run tests
shells --version
shells --help > /dev/null

echo "Update successful"
```

### Multi-Server Deployment
```bash
# Update all servers in parallel
ansible all -m shell -a "shells self update"

# Or with fabric
fab production shells.update
```

## Comparison with install.sh

| Feature | `install.sh` | `shells self update` |
|---------|-------------|---------------------|
| **Installs Go** |  Yes |  No |
| **Installs PostgreSQL** |  Yes |  No |
| **Creates database** |  Yes |  No |
| **Updates binary** |  Yes |  Yes |
| **Pulls git updates** |  No |  Yes |
| **Creates backup** |  No |  Yes |
| **Validates binary** |  No |  Yes |
| **Automatic rollback** |  No |  Via backup |
| **Use case** | Initial install | Regular updates |

**When to use `install.sh`:** First-time installation or major version upgrades

**When to use `shells self update`:** Regular updates when dependencies haven't changed
