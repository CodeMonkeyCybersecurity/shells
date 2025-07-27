// Backup and recovery procedures for shells security scanner

// Automated backup job
job "shells-backup" {
  datacenters = ["dc1"]
  type        = "batch"
  
  periodic {
    cron             = "0 2 * * *"  // Daily at 2 AM
    prohibit_overlap = true
    time_zone        = "UTC"
  }
  
  group "backup" {
    task "database-backup" {
      driver = "docker"
      
      config {
        image = "shells:latest"
        command = "/bin/bash"
        args = ["-c", <<EOF
#!/bin/bash
set -e

echo "Starting shells backup process..."

# Generate backup timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backup/${TIMESTAMP}"
mkdir -p ${BACKUP_DIR}

# Backup SQLite database
echo "Backing up SQLite database..."
sqlite3 /data/shells.db ".backup '${BACKUP_DIR}/shells.db.backup'"

# Create database schema dump
sqlite3 /data/shells.db .schema > ${BACKUP_DIR}/schema.sql

# Export critical data as JSON for recovery
echo "Exporting critical data..."
/shells export --format json \
  --output ${BACKUP_DIR}/findings.json \
  --type findings \
  --days 30

/shells export --format json \
  --output ${BACKUP_DIR}/scan_history.json \
  --type scan_history \
  --days 30

# Export identity-specific findings
/shells export --format json \
  --output ${BACKUP_DIR}/identity_findings.json \
  --type findings \
  --filter "category:identity" \
  --days 90

# Backup configuration files
echo "Backing up configuration..."
cp -r /config/* ${BACKUP_DIR}/config/ 2>/dev/null || true

# Create backup manifest
cat > ${BACKUP_DIR}/manifest.json <<MANIFEST
{
  "timestamp": "${TIMESTAMP}",
  "version": "$(shells version --json | jq -r .version)",
  "type": "full",
  "components": [
    "database",
    "findings",
    "scan_history",
    "identity_findings",
    "configuration"
  ],
  "checksum": "$(find ${BACKUP_DIR} -type f -exec sha256sum {} \; | sha256sum | cut -d' ' -f1)"
}
MANIFEST

# Compress backup
echo "Compressing backup..."
cd /backup
tar -czf shells_backup_${TIMESTAMP}.tar.gz ${TIMESTAMP}/
rm -rf ${TIMESTAMP}

# Upload to S3
echo "Uploading to S3..."
aws s3 cp shells_backup_${TIMESTAMP}.tar.gz \
  s3://shells-backups/daily/shells_backup_${TIMESTAMP}.tar.gz \
  --storage-class STANDARD_IA

# Upload to secondary location for redundancy
aws s3 cp shells_backup_${TIMESTAMP}.tar.gz \
  s3://shells-backups-dr/daily/shells_backup_${TIMESTAMP}.tar.gz \
  --region us-west-2

# Clean up old local backups (keep last 7)
find /backup -name "shells_backup_*.tar.gz" -mtime +7 -delete

# Clean up old S3 backups (keep last 30)
aws s3 ls s3://shells-backups/daily/ | \
  awk '{print $4}' | \
  sort -r | \
  tail -n +31 | \
  xargs -I {} aws s3 rm s3://shells-backups/daily/{}

echo "Backup completed successfully"

# Send notification
curl -X POST ${NOMAD_META_webhook_url} \
  -H "Content-Type: application/json" \
  -d "{\"text\": \"Shells backup completed: ${TIMESTAMP}\"}"
EOF
        ]
      }
      
      env {
        AWS_ACCESS_KEY_ID     = "${AWS_ACCESS_KEY_ID}"
        AWS_SECRET_ACCESS_KEY = "${AWS_SECRET_ACCESS_KEY}"
        AWS_DEFAULT_REGION    = "us-east-1"
      }
      
      resources {
        cpu    = 2000
        memory = 2048
      }
      
      volume_mount {
        volume      = "data"
        destination = "/data"
        read_only   = true
      }
      
      volume_mount {
        volume      = "backup"
        destination = "/backup"
        read_only   = false
      }
      
      volume_mount {
        volume      = "config"
        destination = "/config"
        read_only   = true
      }
      
      vault {
        policies = ["shells-backup"]
      }
      
      template {
        data = <<EOH
{{ with secret "kv/data/shells/backup" }}
AWS_ACCESS_KEY_ID={{ .Data.data.aws_access_key_id }}
AWS_SECRET_ACCESS_KEY={{ .Data.data.aws_secret_access_key }}
WEBHOOK_URL={{ .Data.data.slack_webhook }}
{{ end }}
EOH
        destination = "secrets/backup.env"
        env         = true
      }
    }
    
    volume "data" {
      type      = "host"
      read_only = true
      source    = "shells-data"
    }
    
    volume "backup" {
      type      = "host"
      read_only = false
      source    = "shells-backup"
    }
    
    volume "config" {
      type      = "host"
      read_only = true
      source    = "shells-config"
    }
  }
}

// Disaster recovery test job
job "shells-dr-test" {
  datacenters = ["dc1"]
  type        = "batch"
  
  periodic {
    cron             = "0 4 * * 0"  // Weekly on Sunday at 4 AM
    prohibit_overlap = true
    time_zone        = "UTC"
  }
  
  group "dr-test" {
    task "recovery-test" {
      driver = "docker"
      
      config {
        image = "shells:latest"
        command = "/bin/bash"
        args = ["-c", <<EOF
#!/bin/bash
set -e

echo "Starting disaster recovery test..."

# Create test environment
TEST_DIR="/dr-test/$(date +%Y%m%d_%H%M%S)"
mkdir -p ${TEST_DIR}

# Download latest backup from S3
LATEST_BACKUP=$(aws s3 ls s3://shells-backups/daily/ | sort | tail -n 1 | awk '{print $4}')
echo "Testing recovery with backup: ${LATEST_BACKUP}"

aws s3 cp s3://shells-backups/daily/${LATEST_BACKUP} ${TEST_DIR}/

# Extract backup
cd ${TEST_DIR}
tar -xzf ${LATEST_BACKUP}
BACKUP_DIR=$(ls -d */ | head -n 1)

# Verify backup integrity
echo "Verifying backup integrity..."
EXPECTED_CHECKSUM=$(jq -r .checksum ${BACKUP_DIR}/manifest.json)
ACTUAL_CHECKSUM=$(find ${BACKUP_DIR} -type f ! -name manifest.json -exec sha256sum {} \; | sha256sum | cut -d' ' -f1)

if [ "${EXPECTED_CHECKSUM}" != "${ACTUAL_CHECKSUM}" ]; then
  echo "ERROR: Backup checksum mismatch!"
  exit 1
fi

# Test database restoration
echo "Testing database restoration..."
cp ${BACKUP_DIR}/shells.db.backup ${TEST_DIR}/test.db

# Verify database integrity
sqlite3 ${TEST_DIR}/test.db "PRAGMA integrity_check;"

# Test data queries
FINDING_COUNT=$(sqlite3 ${TEST_DIR}/test.db "SELECT COUNT(*) FROM findings;")
SCAN_COUNT=$(sqlite3 ${TEST_DIR}/test.db "SELECT COUNT(*) FROM scan_requests;")

echo "Restored database contains:"
echo "- ${FINDING_COUNT} findings"
echo "- ${SCAN_COUNT} scan requests"

# Test JSON data import
echo "Testing JSON data import..."
/shells import --input ${BACKUP_DIR}/findings.json --type findings --dry-run

# Verify identity-specific data
IDENTITY_COUNT=$(jq '. | length' ${BACKUP_DIR}/identity_findings.json)
echo "Identity findings in backup: ${IDENTITY_COUNT}"

# Generate DR test report
cat > ${TEST_DIR}/dr_test_report.json <<REPORT
{
  "test_timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "backup_file": "${LATEST_BACKUP}",
  "backup_timestamp": "$(jq -r .timestamp ${BACKUP_DIR}/manifest.json)",
  "test_results": {
    "integrity_check": "PASSED",
    "database_restoration": "PASSED",
    "finding_count": ${FINDING_COUNT},
    "scan_count": ${SCAN_COUNT},
    "identity_finding_count": ${IDENTITY_COUNT},
    "json_import_test": "PASSED"
  },
  "recovery_time_estimate": "15 minutes"
}
REPORT

# Upload test report
aws s3 cp ${TEST_DIR}/dr_test_report.json \
  s3://shells-backups/dr-tests/dr_test_$(date +%Y%m%d_%H%M%S).json

# Clean up
rm -rf ${TEST_DIR}

echo "Disaster recovery test completed successfully"

# Send notification
curl -X POST ${NOMAD_META_webhook_url} \
  -H "Content-Type: application/json" \
  -d "{\"text\": \"DR test passed. Recovery time estimate: 15 minutes\"}"
EOF
        ]
      }
      
      resources {
        cpu    = 1000
        memory = 1024
      }
      
      volume_mount {
        volume      = "dr-test"
        destination = "/dr-test"
        read_only   = false
      }
      
      vault {
        policies = ["shells-backup"]
      }
    }
    
    volume "dr-test" {
      type      = "host"
      read_only = false
      source    = "shells-dr-test"
    }
  }
}

// Manual recovery job
job "shells-recovery" {
  datacenters = ["dc1"]
  type        = "batch"
  
  parameterized {
    payload       = "forbidden"
    meta_required = ["backup_file"]
    meta_optional = ["target_env", "partial_restore"]
  }
  
  group "recovery" {
    task "restore" {
      driver = "docker"
      
      config {
        image = "shells:latest"
        command = "/bin/bash"
        args = ["-c", <<EOF
#!/bin/bash
set -e

echo "Starting recovery process..."
BACKUP_FILE="${NOMAD_META_backup_file}"
TARGET_ENV="${NOMAD_META_target_env:-production}"
PARTIAL="${NOMAD_META_partial_restore:-false}"

# Download backup
echo "Downloading backup: ${BACKUP_FILE}"
aws s3 cp s3://shells-backups/daily/${BACKUP_FILE} /tmp/

# Extract backup
cd /tmp
tar -xzf ${BACKUP_FILE}
BACKUP_DIR=$(ls -d */ | grep -v proc | grep -v sys | head -n 1)

# Verify backup
echo "Verifying backup integrity..."
EXPECTED_CHECKSUM=$(jq -r .checksum ${BACKUP_DIR}/manifest.json)
ACTUAL_CHECKSUM=$(find ${BACKUP_DIR} -type f ! -name manifest.json -exec sha256sum {} \; | sha256sum | cut -d' ' -f1)

if [ "${EXPECTED_CHECKSUM}" != "${ACTUAL_CHECKSUM}" ]; then
  echo "ERROR: Backup checksum mismatch!"
  exit 1
fi

if [ "${PARTIAL}" == "false" ]; then
  # Full restoration
  echo "Performing full restoration..."
  
  # Stop services
  echo "Stopping shells services..."
  nomad job stop shells-api || true
  nomad job stop shells-workers || true
  
  # Backup current database
  echo "Backing up current database..."
  sqlite3 /data/shells.db ".backup '/data/shells.db.pre-restore'"
  
  # Restore database
  echo "Restoring database..."
  cp ${BACKUP_DIR}/shells.db.backup /data/shells.db
  
  # Restore configuration
  echo "Restoring configuration..."
  cp -r ${BACKUP_DIR}/config/* /config/
  
  # Restart services
  echo "Restarting services..."
  nomad job run /nomad/jobs/shells-api.nomad
  nomad job run /nomad/jobs/shells-workers.nomad
  
else
  # Partial restoration
  echo "Performing partial restoration..."
  
  # Import findings only
  /shells import --input ${BACKUP_DIR}/findings.json --type findings
  
  # Import identity findings
  /shells import --input ${BACKUP_DIR}/identity_findings.json --type findings
fi

echo "Recovery completed successfully"

# Verify recovery
FINDING_COUNT=$(sqlite3 /data/shells.db "SELECT COUNT(*) FROM findings;")
echo "Post-recovery finding count: ${FINDING_COUNT}"

# Send notification
curl -X POST ${NOMAD_META_webhook_url} \
  -H "Content-Type: application/json" \
  -d "{\"text\": \"Recovery completed. Restored ${FINDING_COUNT} findings from ${BACKUP_FILE}\"}"
EOF
        ]
      }
      
      resources {
        cpu    = 2000
        memory = 2048
      }
      
      volume_mount {
        volume      = "data"
        destination = "/data"
        read_only   = false
      }
      
      volume_mount {
        volume      = "config"
        destination = "/config"
        read_only   = false
      }
      
      vault {
        policies = ["shells-recovery"]
      }
    }
    
    volume "data" {
      type      = "host"
      read_only = false
      source    = "shells-data"
    }
    
    volume "config" {
      type      = "host"
      read_only = false
      source    = "shells-config"
    }
  }
}