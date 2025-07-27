// Complete Nomad deployment configuration for shells security scanner
// with identity-focused security capabilities

// Main API service for shells
job "shells-api" {
  datacenters = ["dc1"]
  type        = "service"
  
  update {
    max_parallel      = 1
    min_healthy_time  = "30s"
    healthy_deadline  = "5m"
    progress_deadline = "10m"
    auto_revert       = true
    canary            = 1
  }
  
  group "api" {
    count = 3
    
    network {
      port "http" {
        to = 8080
      }
      port "metrics" {
        to = 9090
      }
    }
    
    service {
      name = "shells-api"
      port = "http"
      tags = ["urlprefix-/api"]
      
      check {
        type     = "http"
        path     = "/health"
        interval = "10s"
        timeout  = "2s"
      }
      
      check {
        type     = "http"
        path     = "/ready"
        interval = "10s"
        timeout  = "2s"
      }
    }
    
    service {
      name = "shells-metrics"
      port = "metrics"
      tags = ["prometheus"]
      
      check {
        type     = "http"
        path     = "/metrics"
        interval = "30s"
        timeout  = "5s"
      }
    }
    
    task "api" {
      driver = "docker"
      
      config {
        image = "shells:latest"
        ports = ["http", "metrics"]
        command = "/shells"
        args = ["api", "--port", "${NOMAD_PORT_http}", "--metrics-port", "${NOMAD_PORT_metrics}"]
        
        logging {
          type = "json-file"
          config {
            max-size = "100m"
            max-file = "10"
          }
        }
      }
      
      env {
        SHELLS_LOG_LEVEL = "info"
        SHELLS_LOG_FORMAT = "json"
        SHELLS_DATABASE_DRIVER = "sqlite3"
        SHELLS_DATABASE_DSN = "/data/shells.db"
        REDIS_ADDR = "${NOMAD_UPSTREAM_ADDR_redis}"
        OTEL_EXPORTER_OTLP_ENDPOINT = "${NOMAD_UPSTREAM_ADDR_otel-collector}"
        OTEL_SERVICE_NAME = "shells-api"
        OTEL_RESOURCE_ATTRIBUTES = "deployment.environment=production,service.version=${NOMAD_META_version}"
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
      
      vault {
        policies = ["shells-api"]
        
        change_mode   = "restart"
        change_signal = "SIGUSR1"
      }
      
      template {
        data = <<EOH
{{ with secret "kv/data/shells/api" }}
API_KEY={{ .Data.data.api_key }}
JWT_SECRET={{ .Data.data.jwt_secret }}
OAUTH_CLIENT_ID={{ .Data.data.oauth_client_id }}
OAUTH_CLIENT_SECRET={{ .Data.data.oauth_client_secret }}
AWS_ACCESS_KEY_ID={{ .Data.data.aws_access_key_id }}
AWS_SECRET_ACCESS_KEY={{ .Data.data.aws_secret_access_key }}
{{ end }}
EOH
        destination = "secrets/api.env"
        env         = true
      }
    }
    
    volume "data" {
      type      = "host"
      read_only = false
      source    = "shells-data"
    }
  }
}

// Scanner workers for distributed scanning
job "shells-workers" {
  datacenters = ["dc1"]
  type        = "service"
  
  update {
    max_parallel      = 2
    min_healthy_time  = "30s"
    healthy_deadline  = "5m"
    progress_deadline = "10m"
    auto_revert       = true
  }
  
  group "workers" {
    count = 10
    
    scaling {
      enabled = true
      min     = 5
      max     = 50
      
      policy {
        cooldown = "30s"
        
        check "queue_depth" {
          source = "prometheus"
          query  = "shells_job_queue_depth{queue='scan'}"
          
          strategy "target-value" {
            target = 10
          }
        }
        
        check "cpu_usage" {
          source = "prometheus"
          query  = "avg(nomad_client_allocs_cpu_user{job='shells-workers'})"
          
          strategy "target-value" {
            target = 70
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
      name = "shells-worker"
      
      check {
        type     = "script"
        command  = "/shells"
        args     = ["worker", "health"]
        interval = "30s"
        timeout  = "5s"
      }
    }
    
    service {
      name = "shells-worker-metrics"
      port = "metrics"
      tags = ["prometheus"]
    }
    
    task "worker" {
      driver = "docker"
      
      config {
        image = "shells:latest"
        ports = ["metrics"]
        command = "/shells"
        args = ["worker", "--concurrency", "3", "--queue", "scan"]
        
        security_opt = [
          "no-new-privileges:true",
          "seccomp=default"
        ]
        
        logging {
          type = "json-file"
          config {
            max-size = "100m"
            max-file = "10"
          }
        }
      }
      
      env {
        SHELLS_LOG_LEVEL = "info"
        SHELLS_LOG_FORMAT = "json"
        SHELLS_DATABASE_DRIVER = "sqlite3"
        SHELLS_DATABASE_DSN = "/data/shells.db"
        REDIS_ADDR = "${NOMAD_UPSTREAM_ADDR_redis}"
        OTEL_EXPORTER_OTLP_ENDPOINT = "${NOMAD_UPSTREAM_ADDR_otel-collector}"
        OTEL_SERVICE_NAME = "shells-worker"
        WORKER_ID = "${NOMAD_ALLOC_ID}"
        
        // Identity-focused scanner configurations
        ENABLE_IDENTITY_SCANNERS = "true"
        PROWLER_DOCKER_IMAGE = "toniblyx/prowler:latest"
        INTERACTSH_SERVER_URL = "https://oast.fun"
        SAML_SCANNER_ENABLED = "true"
        OAUTH2_SCANNER_ENABLED = "true"
        WEBAUTHN_SCANNER_ENABLED = "true"
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
      
      volume_mount {
        volume      = "tools"
        destination = "/tools"
        read_only   = true
      }
      
      vault {
        policies = ["shells-worker"]
        
        change_mode   = "restart"
        change_signal = "SIGUSR1"
      }
      
      template {
        data = <<EOH
{{ with secret "kv/data/shells/scanner" }}
AWS_ACCESS_KEY_ID={{ .Data.data.aws_access_key_id }}
AWS_SECRET_ACCESS_KEY={{ .Data.data.aws_secret_access_key }}
INTERACTSH_AUTH_TOKEN={{ .Data.data.interactsh_auth_token }}
{{ end }}
EOH
        destination = "secrets/scanner.env"
        env         = true
      }
    }
    
    volume "data" {
      type      = "host"
      read_only = false
      source    = "shells-data"
    }
    
    volume "tools" {
      type      = "host"
      read_only = true
      source    = "shells-tools"
    }
  }
}

// Scheduled scan coordinator
job "shells-scheduler" {
  datacenters = ["dc1"]
  type        = "service"
  
  group "scheduler" {
    count = 1
    
    network {
      port "http" {
        to = 8081
      }
    }
    
    service {
      name = "shells-scheduler"
      port = "http"
      
      check {
        type     = "http"
        path     = "/health"
        interval = "30s"
        timeout  = "5s"
      }
    }
    
    task "scheduler" {
      driver = "docker"
      
      config {
        image = "shells:latest"
        ports = ["http"]
        command = "/shells"
        args = ["scheduler", "--port", "${NOMAD_PORT_http}"]
      }
      
      env {
        SHELLS_LOG_LEVEL = "info"
        SHELLS_LOG_FORMAT = "json"
        SHELLS_DATABASE_DRIVER = "sqlite3"
        SHELLS_DATABASE_DSN = "/data/shells.db"
        REDIS_ADDR = "${NOMAD_UPSTREAM_ADDR_redis}"
        NOMAD_ADDR = "http://${attr.unique.network.ip-address}:4646"
      }
      
      resources {
        cpu    = 500
        memory = 512
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

// Identity-specific scanner workers
job "shells-identity-workers" {
  datacenters = ["dc1"]
  type        = "service"
  
  group "identity-workers" {
    count = 5
    
    network {
      port "metrics" {
        to = 9090
      }
    }
    
    service {
      name = "shells-identity-worker"
      tags = ["identity", "scanner"]
    }
    
    task "identity-scanner" {
      driver = "docker"
      
      config {
        image = "shells:latest"
        ports = ["metrics"]
        command = "/shells"
        args = ["worker", "--concurrency", "2", "--queue", "identity", "--specialized"]
        
        // Mount Docker socket for Prowler
        mounts = [
          {
            type   = "bind"
            source = "/var/run/docker.sock"
            target = "/var/run/docker.sock"
          }
        ]
      }
      
      env {
        SHELLS_LOG_LEVEL = "debug"
        SHELLS_LOG_FORMAT = "json"
        SHELLS_DATABASE_DRIVER = "sqlite3"
        SHELLS_DATABASE_DSN = "/data/shells.db"
        REDIS_ADDR = "${NOMAD_UPSTREAM_ADDR_redis}"
        WORKER_TYPE = "identity"
        
        // Identity scanner specific configs
        PROWLER_ENABLED = "true"
        PROWLER_PARALLEL_JOBS = "10"
        INTERACTSH_ENABLED = "true"
        INTERACTSH_POLL_DURATION = "300s"
        SAML_DEEP_SCAN = "true"
        OAUTH2_FLOW_TESTING = "true"
        JWT_ALGORITHM_TESTING = "true"
        WEBAUTHN_VIRTUAL_TESTING = "true"
      }
      
      resources {
        cpu    = 6000
        memory = 8192
      }
      
      volume_mount {
        volume      = "data"
        destination = "/data"
        read_only   = false
      }
      
      volume_mount {
        volume      = "aws-config"
        destination = "/root/.aws"
        read_only   = true
      }
      
      vault {
        policies = ["shells-identity-scanner"]
      }
      
      template {
        data = <<EOH
{{ with secret "kv/data/shells/identity" }}
AWS_DEFAULT_REGION={{ .Data.data.aws_region }}
SAML_TEST_IDP_URL={{ .Data.data.saml_test_idp }}
OAUTH2_TEST_PROVIDER={{ .Data.data.oauth2_test_provider }}
{{ end }}
EOH
        destination = "secrets/identity.env"
        env         = true
      }
    }
    
    volume "data" {
      type      = "host"
      read_only = false
      source    = "shells-data"
    }
    
    volume "aws-config" {
      type      = "host"
      read_only = true
      source    = "shells-aws-config"
    }
  }
}

// Results processor and reporting service
job "shells-processor" {
  datacenters = ["dc1"]
  type        = "service"
  
  group "processor" {
    count = 2
    
    task "processor" {
      driver = "docker"
      
      config {
        image = "shells:latest"
        command = "/shells"
        args = ["processor", "--mode", "stream"]
      }
      
      env {
        SHELLS_LOG_LEVEL = "info"
        SHELLS_DATABASE_DRIVER = "sqlite3"
        SHELLS_DATABASE_DSN = "/data/shells.db"
        REDIS_ADDR = "${NOMAD_UPSTREAM_ADDR_redis}"
        
        // Result processing configs
        ENABLE_AI_ANALYSIS = "true"
        ENABLE_CVSS_SCORING = "true"
        ENABLE_ATTACK_CHAIN_ANALYSIS = "true"
        IDENTITY_VULNERABILITY_PRIORITY = "high"
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
    }
    
    volume "data" {
      type      = "host"
      read_only = false
      source    = "shells-data"
    }
  }
}

// Batch job definitions for specific scan types
job "shells-scan-full" {
  datacenters = ["dc1"]
  type        = "batch"
  
  parameterized {
    payload       = "forbidden"
    meta_required = ["target", "scan_id"]
    meta_optional = ["profile", "auth_token", "include_identity"]
  }
  
  group "scanner" {
    task "full-scan" {
      driver = "docker"
      
      config {
        image = "shells:latest"
        command = "/shells"
        args = [
          "scan",
          "full",
          "${NOMAD_META_target}",
          "--scan-id", "${NOMAD_META_scan_id}",
          "--profile", "${NOMAD_META_profile}",
          "--include-identity", "${NOMAD_META_include_identity}"
        ]
      }
      
      resources {
        cpu    = 8000
        memory = 8192
      }
      
      volume_mount {
        volume      = "data"
        destination = "/data"
      }
    }
    
    volume "data" {
      type   = "host"
      source = "shells-data"
    }
  }
}

job "shells-scan-identity" {
  datacenters = ["dc1"]
  type        = "batch"
  
  parameterized {
    payload       = "forbidden"
    meta_required = ["target", "scan_id"]
    meta_optional = ["auth_type", "client_id", "idp_url"]
  }
  
  group "identity-scanner" {
    task "identity-scan" {
      driver = "docker"
      
      config {
        image = "shells:latest"
        command = "/shells"
        args = [
          "auth",
          "all",
          "--target", "${NOMAD_META_target}",
          "--scan-id", "${NOMAD_META_scan_id}",
          "--auth-type", "${NOMAD_META_auth_type}",
          "--save-report"
        ]
      }
      
      resources {
        cpu    = 4000
        memory = 4096
      }
      
      volume_mount {
        volume      = "data"
        destination = "/data"
      }
    }
    
    volume "data" {
      type   = "host"
      source = "shells-data"
    }
  }
}