# Shells Python Worker Service - Nomad Job Definition
# Deploys Python-based scanner workers (IDORD, GraphCrawler) with Redis Queue

job "shells-python-workers" {
  datacenters = ["dc1"]
  type        = "service"

  # Update strategy
  update {
    max_parallel     = 2
    min_healthy_time = "30s"
    healthy_deadline = "5m"
    auto_revert      = true
  }

  # FastAPI API Server
  group "api" {
    count = 1

    network {
      port "http" {
        to = 8000
      }
    }

    service {
      name = "shells-python-api"
      port = "http"
      tags = ["python", "fastapi", "scanner-api"]

      check {
        type     = "http"
        path     = "/health"
        interval = "30s"
        timeout  = "5s"
      }
    }

    task "fastapi" {
      driver = "docker"

      config {
        image = "shells/python-workers:latest"
        ports = ["http"]

        # Mount for scan outputs
        mount {
          type   = "bind"
          source = "local"
          target = "/tmp/scan-outputs"
        }
      }

      env {
        REDIS_URL    = "redis://${NOMAD_IP_redis}:6379"
        PYTHONPATH   = "/app"
        LOG_LEVEL    = "info"
      }

      resources {
        cpu    = 500  # 500 MHz
        memory = 512  # 512 MB
      }

      # Logging
      logs {
        max_files     = 5
        max_file_size = 10
      }
    }
  }

  # RQ Worker Processes
  group "workers" {
    count = 4  # 4 RQ worker processes

    # Spread workers across available nodes
    spread {
      attribute = "${node.unique.id}"
      weight    = 100
    }

    task "rq-worker" {
      driver = "docker"

      config {
        image   = "shells/python-workers:latest"
        command = "rq"
        args    = [
          "worker",
          "shells-scanners",
          "--url", "${REDIS_URL}",
          "--name", "${NOMAD_ALLOC_ID}",
          "--with-scheduler"
        ]

        # Mount for scan outputs
        mount {
          type   = "bind"
          source = "local"
          target = "/tmp/scan-outputs"
        }
      }

      env {
        REDIS_URL  = "redis://${NOMAD_IP_redis}:6379"
        PYTHONPATH = "/app"
        LOG_LEVEL  = "info"
      }

      resources {
        cpu    = 1000  # 1000 MHz (1 CPU core)
        memory = 1024  # 1 GB
      }

      # Logging
      logs {
        max_files     = 5
        max_file_size = 10
      }

      # Restart policy for workers
      restart {
        attempts = 3
        delay    = "30s"
        interval = "5m"
        mode     = "fail"
      }
    }

    # Service registration for worker health
    service {
      name = "shells-rq-worker"
      tags = ["python", "rq", "scanner-worker"]

      # Worker health check via RQ
      check {
        type     = "script"
        name     = "rq-worker-health"
        command  = "/bin/sh"
        args     = ["-c", "rq info --url ${REDIS_URL} | grep -q 'workers'"]
        interval = "60s"
        timeout  = "10s"
      }
    }
  }

  # Redis dependency (assumed to be running)
  # If Redis is managed by Nomad, uncomment this section:
  #
  # group "redis" {
  #   count = 1
  #
  #   network {
  #     port "redis" {
  #       static = 6379
  #     }
  #   }
  #
  #   service {
  #     name = "shells-redis"
  #     port = "redis"
  #
  #     check {
  #       type     = "tcp"
  #       interval = "10s"
  #       timeout  = "2s"
  #     }
  #   }
  #
  #   task "redis" {
  #     driver = "docker"
  #
  #     config {
  #       image = "redis:7-alpine"
  #       ports = ["redis"]
  #     }
  #
  #     resources {
  #       cpu    = 500
  #       memory = 256
  #     }
  #   }
  # }
}
