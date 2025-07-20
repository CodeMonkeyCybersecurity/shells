job "shells-scheduled-scans" {
  datacenters = ["dc1"]
  type        = "batch"
  
  periodic {
    cron             = "0 * * * *"  # Run every hour
    prohibit_overlap = true
  }
  
  group "hourly-scans" {
    count = 1
    
    restart {
      attempts = 1
      interval = "1h"
      delay    = "15s"
      mode     = "fail"
    }
    
    task "scanner" {
      driver = "docker"
      
      config {
        image = "shells:latest"
        command = "/shells"
        args = [
          "workflow",
          "run",
          "--scheduled",
          "--duration", "55m",  # Run for 55 minutes (5min buffer)
          "--output", "/results/scheduled-${NOMAD_JOB_ID}.json"
        ]
      }
      
      env {
        SHELLS_LOG_LEVEL = "info"
        SHELLS_LOG_FORMAT = "json"
        SHELLS_DATABASE_DRIVER = "sqlite3"
        SHELLS_DATABASE_DSN = "/data/shells.db"
        OTEL_EXPORTER_OTLP_ENDPOINT = "http://otel-collector:4317"
        SHELLS_SCHEDULED_MODE = "true"
        SHELLS_MAX_DURATION = "55m"
        SHELLS_USE_NOMAD = "true"
        NOMAD_ADDR = "http://${attr.unique.network.ip-address}:4646"
      }
      
      resources {
        cpu    = 800
        memory = 768
      }
      
      volume_mount {
        volume      = "data"
        destination = "/data"
      }
      
      volume_mount {
        volume      = "results"
        destination = "/results"
      }
    }
    
    volume "data" {
      type   = "host"
      source = "shells-data"
    }
    
    volume "results" {
      type   = "host"
      source = "shells-results"
    }
  }
}