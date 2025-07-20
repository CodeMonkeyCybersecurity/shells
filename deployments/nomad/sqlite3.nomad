job "shells-sqlite3" {
  datacenters = ["dc1"]
  type        = "service"
  
  group "database" {
    count = 1
    
    network {
      port "db" {
        static = 8081
      }
    }
    
    service {
      name = "shells-database"
      port = "db"
      
      check {
        type     = "tcp"
        interval = "30s"
        timeout  = "5s"
      }
    }
    
    task "sqlite-server" {
      driver = "docker"
      
      config {
        image = "alpine:latest"
        command = "/bin/sh"
        args = ["-c", "while true; do sleep 3600; done"]
        ports = ["db"]
      }
      
      env {
        SHELLS_DATABASE_DRIVER = "sqlite3"
        SHELLS_DATABASE_DSN = "/data/shells.db"
      }
      
      resources {
        cpu    = 200
        memory = 256
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