// Performance optimization configurations for large-scale scanning

// High-performance scanner configuration
job "shells-hp-scanner" {
  datacenters = ["dc1"]
  type        = "service"
  
  // Spread across multiple nodes for better resource utilization
  spread {
    attribute = "${node.unique.id}"
    weight    = 100
  }
  
  group "hp-workers" {
    count = 20  // Base count, will autoscale
    
    // Aggressive scaling policy
    scaling {
      enabled = true
      min     = 20
      max     = 100
      
      policy {
        cooldown = "20s"
        
        check "queue_depth" {
          source = "prometheus"
          query  = "shells_job_queue_depth{queue='scan'}"
          
          strategy "target-value" {
            target = 5  // Keep queue depth low
          }
        }
        
        check "scan_rate" {
          source = "prometheus"
          query  = "rate(shells_scans_completed_total[1m])"
          
          strategy "threshold" {
            upper_bound = 50
            delta       = 10
          }
        }
      }
    }
    
    network {
      port "metrics" {
        to = 9090
      }
    }
    
    service {
      name = "shells-hp-worker"
      tags = ["high-performance"]
    }
    
    task "hp-scanner" {
      driver = "docker"
      
      config {
        image = "shells:latest"
        ports = ["metrics"]
        command = "/shells"
        args = [
          "worker",
          "--concurrency", "10",          // High concurrency per worker
          "--queue", "scan",
          "--batch-size", "50",           // Process multiple jobs at once
          "--prefetch", "100",            // Aggressive job prefetching
          "--performance-mode"
        ]
        
        // Performance optimizations
        ulimit {
          nofile = "65536:65536"  // Increase file descriptor limit
        }
        
        cpu_hard_limit = true  // Enforce CPU limits
      }
      
      env {
        SHELLS_LOG_LEVEL = "warn"  // Reduce logging overhead
        SHELLS_LOG_FORMAT = "json"
        SHELLS_DATABASE_DRIVER = "sqlite3"
        SHELLS_DATABASE_DSN = "/data/shells.db?cache=shared&mode=rwc&_journal_mode=WAL"
        REDIS_ADDR = "${NOMAD_UPSTREAM_ADDR_redis}"
        
        // Performance tuning
        GOMAXPROCS = "16"
        GOMEMLIMIT = "7GiB"
        GOGC = "100"
        
        // Scanner optimizations
        SHELLS_PARALLEL_SCANS = "10"
        SHELLS_CONNECTION_POOL_SIZE = "100"
        SHELLS_HTTP_TIMEOUT = "30s"
        SHELLS_SCAN_TIMEOUT = "300s"
        SHELLS_RATE_LIMIT_BURST = "100"
        SHELLS_DNS_CACHE_SIZE = "10000"
        SHELLS_RESULT_BATCH_SIZE = "100"
        
        // Identity scanner optimizations
        PROWLER_PARALLEL_JOBS = "20"
        INTERACTSH_BATCH_SIZE = "50"
        SAML_CONCURRENT_TESTS = "10"
        OAUTH2_CONNECTION_POOL = "50"
      }
      
      resources {
        cpu    = 8000
        memory = 8192
        
        // Reserve network bandwidth
        network {
          mbits = 100
        }
      }
      
      volume_mount {
        volume      = "data"
        destination = "/data"
        read_only   = false
      }
      
      volume_mount {
        volume      = "cache"
        destination = "/cache"
        read_only   = false
      }
    }
    
    volume "data" {
      type      = "host"
      read_only = false
      source    = "shells-data-ssd"  // Use SSD storage
    }
    
    volume "cache" {
      type      = "host"
      read_only = false
      source    = "shells-cache-nvme"  // Use NVMe for cache
    }
  }
}

// Distributed queue sharding for high throughput
job "shells-queue-shards" {
  datacenters = ["dc1"]
  type        = "service"
  
  group "queue-shards" {
    count = 5  // 5 queue shards
    
    task "queue-shard" {
      driver = "docker"
      
      config {
        image = "shells:latest"
        command = "/shells"
        args = [
          "queue-manager",
          "--shard-id", "${NOMAD_ALLOC_INDEX}",
          "--total-shards", "5",
          "--mode", "distributed"
        ]
      }
      
      env {
        REDIS_ADDR = "${NOMAD_UPSTREAM_ADDR_redis}"
        SHARD_KEY_PREFIX = "shells:queue:shard:${NOMAD_ALLOC_INDEX}"
      }
      
      resources {
        cpu    = 1000
        memory = 1024
      }
    }
  }
}

// Result aggregator for high-volume processing
job "shells-result-aggregator" {
  datacenters = ["dc1"]
  type        = "service"
  
  group "aggregators" {
    count = 3
    
    task "aggregator" {
      driver = "docker"
      
      config {
        image = "shells:latest"
        command = "/shells"
        args = [
          "aggregator",
          "--mode", "stream",
          "--buffer-size", "10000",
          "--flush-interval", "5s"
        ]
      }
      
      env {
        SHELLS_DATABASE_DRIVER = "sqlite3"
        SHELLS_DATABASE_DSN = "/data/shells.db?cache=shared&mode=rwc&_journal_mode=WAL"
        REDIS_ADDR = "${NOMAD_UPSTREAM_ADDR_redis}"
        
        // Batch processing settings
        AGGREGATOR_BATCH_SIZE = "1000"
        AGGREGATOR_WORKER_POOL = "20"
        AGGREGATOR_CHANNEL_BUFFER = "10000"
      }
      
      resources {
        cpu    = 4000
        memory = 4096
      }
      
      volume_mount {
        volume      = "data"
        destination = "/data"
        read_only   = false
      }
    }
    
    volume "data" {
      type      = "host"
      read_only = false
      source    = "shells-data-ssd"
    }
  }
}

// Cache warmer for frequently accessed data
job "shells-cache-warmer" {
  datacenters = ["dc1"]
  type        = "batch"
  
  periodic {
    cron             = "*/15 * * * *"  // Every 15 minutes
    prohibit_overlap = true
  }
  
  group "cache-warmer" {
    task "warm-cache" {
      driver = "docker"
      
      config {
        image = "shells:latest"
        command = "/shells"
        args = ["cache", "warm"]
      }
      
      env {
        REDIS_ADDR = "${NOMAD_UPSTREAM_ADDR_redis}"
        CACHE_TARGETS = "dns_records,certificate_chains,vulnerability_db,identity_providers"
        CACHE_TTL = "3600"
      }
      
      resources {
        cpu    = 2000
        memory = 2048
      }
    }
  }
}

// Database optimization job
job "shells-db-optimizer" {
  datacenters = ["dc1"]
  type        = "batch"
  
  periodic {
    cron             = "0 3 * * *"  // Daily at 3 AM
    prohibit_overlap = true
  }
  
  group "optimizer" {
    task "optimize-db" {
      driver = "docker"
      
      config {
        image = "shells:latest"
        command = "/bin/bash"
        args = ["-c", <<EOF
#!/bin/bash
set -e

echo "Starting database optimization..."

# Analyze and optimize SQLite database
sqlite3 /data/shells.db <<SQL
-- Update statistics
ANALYZE;

-- Rebuild indexes
REINDEX;

-- Vacuum to reclaim space
VACUUM;

-- Optimize write-ahead log
PRAGMA wal_checkpoint(TRUNCATE);

-- Set performance pragmas
PRAGMA cache_size = 100000;
PRAGMA temp_store = MEMORY;
PRAGMA mmap_size = 30000000000;
PRAGMA page_size = 4096;
SQL

# Create materialized views for common queries
sqlite3 /data/shells.db <<SQL
-- Drop old views
DROP VIEW IF EXISTS identity_findings_summary;
DROP VIEW IF EXISTS recent_critical_findings;
DROP VIEW IF EXISTS scan_performance_stats;

-- Create optimized views
CREATE VIEW identity_findings_summary AS
SELECT 
  type,
  severity,
  COUNT(*) as count,
  MAX(created_at) as last_seen
FROM findings
WHERE type IN ('SAML_GOLDEN_TICKET', 'JWT_ALGORITHM_CONFUSION', 'OAUTH_REDIRECT_BYPASS')
GROUP BY type, severity;

CREATE VIEW recent_critical_findings AS
SELECT 
  id,
  type,
  title,
  target,
  created_at
FROM findings
WHERE severity = 'critical'
  AND created_at > datetime('now', '-7 days')
ORDER BY created_at DESC;

CREATE VIEW scan_performance_stats AS
SELECT 
  type,
  AVG(julianday(completed_at) - julianday(started_at)) * 24 * 60 as avg_duration_minutes,
  COUNT(*) as total_scans,
  SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as successful_scans
FROM scan_requests
WHERE started_at IS NOT NULL
GROUP BY type;
SQL

# Create additional indexes for performance
sqlite3 /data/shells.db <<SQL
-- Identity-specific indexes
CREATE INDEX IF NOT EXISTS idx_findings_identity ON findings(type, severity) 
  WHERE type LIKE '%SAML%' OR type LIKE '%JWT%' OR type LIKE '%OAUTH%';

-- Time-based indexes
CREATE INDEX IF NOT EXISTS idx_findings_recent ON findings(created_at DESC) 
  WHERE created_at > datetime('now', '-30 days');

-- Composite indexes for common queries
CREATE INDEX IF NOT EXISTS idx_scan_status_time ON scan_requests(status, created_at);
CREATE INDEX IF NOT EXISTS idx_findings_severity_time ON findings(severity, created_at);
SQL

echo "Database optimization completed"

# Report statistics
TOTAL_SIZE=$(du -h /data/shells.db | cut -f1)
FINDING_COUNT=$(sqlite3 /data/shells.db "SELECT COUNT(*) FROM findings;")
INDEX_COUNT=$(sqlite3 /data/shells.db "SELECT COUNT(*) FROM sqlite_master WHERE type='index';")

echo "Database statistics:"
echo "- Size: ${TOTAL_SIZE}"
echo "- Findings: ${FINDING_COUNT}"
echo "- Indexes: ${INDEX_COUNT}"
EOF
        ]
      }
      
      resources {
        cpu    = 4000
        memory = 4096
      }
      
      volume_mount {
        volume      = "data"
        destination = "/data"
        read_only   = false
      }
    }
    
    volume "data" {
      type      = "host"
      read_only = false
      source    = "shells-data"
    }
  }
}

// Load balancer for API distribution
job "shells-lb" {
  datacenters = ["dc1"]
  type        = "service"
  
  group "loadbalancer" {
    count = 2
    
    network {
      port "http" {
        static = 80
      }
      port "https" {
        static = 443
      }
    }
    
    service {
      name = "shells-lb"
      port = "https"
      
      check {
        type     = "http"
        path     = "/health"
        port     = "http"
        interval = "10s"
        timeout  = "2s"
      }
    }
    
    task "haproxy" {
      driver = "docker"
      
      config {
        image = "haproxy:2.8-alpine"
        ports = ["http", "https"]
      }
      
      template {
        data = <<EOH
global
  maxconn 10000
  nbthread 4
  cpu-map auto:1/1-4 0-3
  stats socket /var/run/haproxy.sock mode 660 level admin
  tune.ssl.default-dh-param 2048

defaults
  mode http
  timeout connect 5s
  timeout client 30s
  timeout server 30s
  option httplog
  option forwardfor
  option http-server-close

frontend shells_frontend
  bind *:80
  bind *:443 ssl crt /etc/ssl/shells.pem
  redirect scheme https if !{ ssl_fc }
  
  # Rate limiting
  stick-table type ip size 100k expire 30s store http_req_rate(10s)
  http-request track-sc0 src
  http-request deny if { sc_http_req_rate(0) gt 100 }
  
  # Security headers
  http-response set-header X-Frame-Options DENY
  http-response set-header X-Content-Type-Options nosniff
  http-response set-header X-XSS-Protection "1; mode=block"
  
  # Route to appropriate backend
  use_backend shells_api if { path_beg /api }
  use_backend shells_metrics if { path_beg /metrics }
  default_backend shells_api

backend shells_api
  balance leastconn
  option httpchk GET /health
  
  # Circuit breaker
  option redispatch
  retries 3
  
  # Connection pooling
  http-reuse safe
  
  {{ range service "shells-api" }}
  server {{ .Node }}_{{ .Port }} {{ .Address }}:{{ .Port }} check maxconn 100 weight 100
  {{ end }}

backend shells_metrics
  balance roundrobin
  {{ range service "shells-metrics" }}
  server {{ .Node }}_{{ .Port }} {{ .Address }}:{{ .Port }} check
  {{ end }}

listen stats
  bind *:8404
  stats enable
  stats uri /stats
  stats refresh 30s
EOH
        destination = "local/haproxy.cfg"
      }
      
      resources {
        cpu    = 2000
        memory = 1024
      }
    }
  }
}