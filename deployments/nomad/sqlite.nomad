job "shells-sqlite" {
  datacenters = ["dc1"]
  type = "service"
  
  group "sqlite" {
    count = 1
    
    volume "sqlite-data" {
      type      = "host"
      source    = "sqlite-data"
      read_only = false
    }
    
    network {
      port "app" {
        static = 8080
      }
    }
    
    service {
      name = "shells-sqlite"
      port = "app"
      
      check {
        type     = "tcp"
        interval = "30s"
        timeout  = "5s"
      }
    }
    
    task "shells" {
      driver = "docker"
      
      volume_mount {
        volume      = "sqlite-data"
        destination = "/data"
        read_only   = false
      }
      
      config {
        image = "shells:latest"
        ports = ["app"]
      }
      
      env {
        # SQLite database file location
        DATABASE_PATH = "/data/shells.db"
        # Use environment variable for sensitive config
        SHELLS_CONFIG_PATH = "${NOMAD_SECRETS_DIR}/config.yaml"
      }
      
      template {
        destination = "${NOMAD_SECRETS_DIR}/config.yaml"
        data = <<EOF
database:
  driver: "sqlite3"
  dsn: "/data/shells.db"
  max_connections: 1  # SQLite only supports 1 writer
  max_idle_conns: 1

security:
  enable_auth: true
  api_key: "{{ env "SHELLS_API_KEY" }}"
  
logger:
  level: "info"
  format: "json"
EOF
      }
      
      resources {
        cpu    = 200
        memory = 256
      }
      
      restart {
        attempts = 3
        interval = "30m"
        delay    = "15s"
        mode     = "fail"
      }
    }
  }
}