job "shells-scanner-web" {
  datacenters = ["dc1"]
  type        = "service"
  
  group "web" {
    count = 1
    
    network {
      port "http" {
        static = 8080
      }
    }
    
    service {
      name = "shells-scanner-web"
      port = "http"
      
      check {
        type     = "http"
        path     = "/health"
        interval = "30s"
        timeout  = "5s"
      }
    }
    
    task "scanner-web" {
      driver = "docker"
      
      config {
        image = "shells:latest"
        ports = ["http"]
        command = "/shells"
        args = ["scan", "--web-mode", "--port", "8080"]
      }
      
      env {
        SHELLS_LOG_LEVEL = "info"
        SHELLS_LOG_FORMAT = "json"
        SHELLS_DATABASE_DRIVER = "sqlite3"
        SHELLS_DATABASE_DSN = "/data/shells.db"
        OTEL_EXPORTER_OTLP_ENDPOINT = "http://otel-collector:4317"
      }
      
      resources {
        cpu    = 500
        memory = 512
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