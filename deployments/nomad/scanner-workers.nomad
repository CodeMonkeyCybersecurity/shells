job "shells-scanner-workers" {
  datacenters = ["dc1"]
  type        = "batch"
  
  parameterized {
    payload       = "forbidden"
    meta_required = ["target", "scan_id"]
    meta_optional = ["scan_type", "options", "timeout", "auth_token"]
  }
  
  group "workers" {
    count = 3
    
    restart {
      attempts = 2
      interval = "30m"
      delay    = "15s"
      mode     = "fail"
    }
    
    task "scanner" {
      driver = "docker"
      
      config {
        image = "shells:latest"
        command = "/shells"
        args = [
          "scan",
          "${NOMAD_META_target}",
          "--scan-id", "${NOMAD_META_scan_id}",
          "--output", "/results/${NOMAD_META_scan_id}.json"
        ]
      }
      
      env {
        SHELLS_LOG_LEVEL = "info" 
        SHELLS_LOG_FORMAT = "json"
        SHELLS_DATABASE_DRIVER = "sqlite3"
        SHELLS_DATABASE_DSN = "/data/shells.db"
        OTEL_EXPORTER_OTLP_ENDPOINT = "http://otel-collector:4317"
        SHELLS_SCAN_TARGET = "${NOMAD_META_target}"
        SHELLS_SCAN_ID = "${NOMAD_META_scan_id}"
        SHELLS_SCAN_TYPE = "${NOMAD_META_scan_type}"
        SHELLS_OPTIONS = "${NOMAD_META_options}"
      }
      
      template {
        data = <<EOH
{{- range service "shells-database" }}
SHELLS_DATABASE_HOST={{ .Address }}
SHELLS_DATABASE_PORT={{ .Port }}
{{- end }}
EOH
        destination = "local/db.env"
        env         = true
      }
      
      resources {
        cpu    = 1000
        memory = 1024
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