job "shells-postgres" {
  datacenters = ["dc1"]
  type = "service"
  
  group "postgres" {
    count = 1
    
    volume "postgres-data" {
      type      = "host"
      source    = "postgres-data"
      read_only = false
    }
    
    network {
      port "postgres" {
        static = 5432
      }
    }
    
    service {
      name = "shells-postgres"
      port = "postgres"
      
      check {
        type     = "tcp"
        interval = "30s"
        timeout  = "5s"
      }
    }
    
    task "postgres" {
      driver = "docker"
      
      volume_mount {
        volume      = "postgres-data"
        destination = "/var/lib/postgresql/data"
        read_only   = false
      }
      
      config {
        image = "postgres:15-alpine"
        ports = ["postgres"]
        
        auth {
          username = ""
          password = ""
        }
      }
      
      env {
        POSTGRES_DB       = "shells"
        POSTGRES_USER     = "shells"
        POSTGRES_PASSWORD = "shells"
        PGDATA           = "/var/lib/postgresql/data/pgdata"
      }
      
      resources {
        cpu    = 500
        memory = 512
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