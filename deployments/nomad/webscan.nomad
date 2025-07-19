job "webscan" {
  datacenters = ["dc1"]
  type        = "service"

  update {
    max_parallel     = 1
    min_healthy_time = "30s"
    healthy_deadline = "5m"
    progress_deadline = "10m"
    auto_revert      = true
    canary           = 1
  }

  group "infrastructure" {
    count = 1

    network {
      port "redis" {
        static = 6379
      }
      port "otel" {
        static = 4317
      }
    }

    task "redis" {
      driver = "docker"

      config {
        image = "redis:7-alpine"
        ports = ["redis"]
        volumes = [
          "local/redis.conf:/usr/local/etc/redis/redis.conf",
        ]
        command = "redis-server"
        args = [
          "/usr/local/etc/redis/redis.conf"
        ]
      }

      template {
        data = <<EOF
bind 0.0.0.0
protected-mode no
port 6379
tcp-backlog 511
timeout 0
tcp-keepalive 300
daemonize no
supervised no
pidfile /var/run/redis_6379.pid
loglevel notice
databases 16
save 900 1
save 300 10
save 60 10000
stop-writes-on-bgsave-error yes
rdbcompression yes
rdbchecksum yes
dbfilename dump.rdb
dir /data
EOF
        destination = "local/redis.conf"
      }

      resources {
        cpu    = 500
        memory = 512
      }

      service {
        name = "webscan-redis"
        port = "redis"
        tags = ["webscan", "redis", "cache"]

        check {
          type     = "tcp"
          interval = "10s"
          timeout  = "2s"
        }
      }
    }

    task "sqlite-volume" {
      driver = "docker"

      config {
        image = "alpine:latest"
        command = "/bin/sh"
        args = ["-c", "mkdir -p /data && touch /data/webscan.db && sleep infinity"]
        volumes = [
          "webscan-data:/data"
        ]
      }

      resources {
        cpu    = 100
        memory = 128
      }

      service {
        name = "webscan-sqlite"
        tags = ["webscan", "sqlite", "database"]
      }
    }

    task "otel-collector" {
      driver = "docker"

      config {
        image = "otel/opentelemetry-collector:latest"
        ports = ["otel"]
        args = [
          "--config=/etc/otel-collector-config.yaml"
        ]
      }

      template {
        data = <<EOF
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317

processors:
  batch:
    timeout: 10s

exporters:
  logging:
    loglevel: info

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [logging]
    metrics:
      receivers: [otlp]
      processors: [batch]
      exporters: [logging]
EOF
        destination = "local/otel-collector-config.yaml"
      }

      resources {
        cpu    = 500
        memory = 512
      }

      service {
        name = "webscan-otel"
        port = "otel"
        tags = ["webscan", "telemetry", "otel"]

        check {
          type     = "http"
          path     = "/health"
          port     = 13133
          interval = "10s"
          timeout  = "2s"
        }
      }
    }
  }

  group "workers" {
    count = 3

    scaling {
      enabled = true
      min     = 1
      max     = 10

      policy {
        cooldown = "180s"

        check "queue_depth" {
          source = "prometheus"
          query  = "webscan_queue_pending_jobs"

          strategy "target-value" {
            target = 10
          }
        }
      }
    }

    network {
      port "metrics" {
        to = 8080
      }
    }

    task "worker" {
      driver = "docker"

      config {
        image = "webscan:latest"
        ports = ["metrics"]
        command = "webscan"
        args = [
          "worker",
          "--config", "/local/config.yaml"
        ]
        cap_add = ["NET_ADMIN", "NET_RAW"]
        volumes = [
          "webscan-data:/data"
        ]
      }

      template {
        data = <<EOF
logger:
  level: {{ env "WEBSCAN_LOG_LEVEL" | default "info" }}
  format: json

database:
  driver: sqlite3
  dsn: "/data/webscan.db"

redis:
  addr: "{{ range service "webscan-redis" }}{{ .Address }}:{{ .Port }}{{ end }}"
  db: 0

worker:
  count: 1
  queue_poll_interval: 5s

telemetry:
  enabled: true
  service_name: webscan-worker
  endpoint: "{{ range service "webscan-otel" }}{{ .Address }}:{{ .Port }}{{ end }}"

tools:
  nmap:
    binary_path: /usr/bin/nmap
    timeout: 30m
  ssl:
    timeout: 10s
EOF
        destination = "local/config.yaml"
      }

      env {
        WEBSCAN_WORKER_ID = "${NOMAD_ALLOC_ID}"
      }

      resources {
        cpu    = 2000
        memory = 2048
      }

      service {
        name = "webscan-worker"
        port = "metrics"
        tags = ["webscan", "worker"]

        check {
          type     = "http"
          path     = "/health"
          interval = "30s"
          timeout  = "5s"
        }
      }
    }
  }

  group "tools" {
    count = 1

    network {
      port "zap" {
        static = 8090
      }
    }

    task "zap" {
      driver = "docker"

      config {
        image = "owasp/zap2docker-stable:latest"
        ports = ["zap"]
        command = "zap.sh"
        args = [
          "-daemon",
          "-port", "8090",
          "-host", "0.0.0.0",
          "-config", "api.key=webscan-api-key"
        ]
      }

      resources {
        cpu    = 2000
        memory = 4096
      }

      service {
        name = "webscan-zap"
        port = "zap"
        tags = ["webscan", "scanner", "zap"]

        check {
          type     = "http"
          path     = "/JSON/core/view/version/"
          interval = "30s"
          timeout  = "5s"
        }
      }
    }
  }
}