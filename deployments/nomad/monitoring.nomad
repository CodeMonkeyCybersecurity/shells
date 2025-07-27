// Monitoring and alerting stack for shells security scanner

// Prometheus for metrics collection
job "prometheus" {
  datacenters = ["dc1"]
  type        = "service"
  
  group "prometheus" {
    count = 1
    
    network {
      port "http" {
        static = 9090
      }
    }
    
    service {
      name = "prometheus"
      port = "http"
      tags = ["urlprefix-/prometheus"]
      
      check {
        type     = "http"
        path     = "/-/healthy"
        interval = "10s"
        timeout  = "2s"
      }
    }
    
    task "prometheus" {
      driver = "docker"
      
      config {
        image = "prom/prometheus:latest"
        ports = ["http"]
        args = [
          "--config.file=/etc/prometheus/prometheus.yml",
          "--storage.tsdb.path=/prometheus",
          "--web.console.libraries=/usr/share/prometheus/console_libraries",
          "--web.console.templates=/usr/share/prometheus/consoles",
          "--web.enable-lifecycle",
          "--storage.tsdb.retention.time=30d"
        ]
      }
      
      template {
        data = <<EOH
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    monitor: 'shells-monitor'
    environment: 'production'

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

rule_files:
  - /etc/prometheus/alerts/*.yml

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'shells-api'
    consul_sd_configs:
      - server: '{{ env "CONSUL_HTTP_ADDR" }}'
        services: ['shells-metrics']
    relabel_configs:
      - source_labels: [__meta_consul_service]
        target_label: job
      - source_labels: [__meta_consul_node]
        target_label: instance

  - job_name: 'shells-workers'
    consul_sd_configs:
      - server: '{{ env "CONSUL_HTTP_ADDR" }}'
        services: ['shells-worker-metrics']
    relabel_configs:
      - source_labels: [__meta_consul_service]
        target_label: job
      - source_labels: [__meta_consul_node]
        target_label: instance

  - job_name: 'nomad'
    consul_sd_configs:
      - server: '{{ env "CONSUL_HTTP_ADDR" }}'
        services: ['nomad-client', 'nomad']
    relabel_configs:
      - source_labels: ['__meta_consul_tags']
        regex: '(.*)http(.*)'
        action: keep
    metrics_path: /v1/metrics
    params:
      format: ['prometheus']
EOH
        destination = "local/prometheus.yml"
      }
      
      template {
        data = <<EOH
groups:
  - name: shells_alerts
    interval: 30s
    rules:
      # Identity scanner specific alerts
      - alert: IdentityScannerHighErrorRate
        expr: rate(shells_scanner_errors_total{scanner=~"saml|oauth2|jwt|webauthn"}[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
          category: identity
        annotations:
          summary: "High error rate in identity scanner {{ $labels.scanner }}"
          description: "{{ $labels.scanner }} scanner has error rate of {{ $value }} errors/sec"
      
      - alert: ProwlerScanTimeout
        expr: shells_prowler_scan_duration_seconds > 3600
        for: 10m
        labels:
          severity: warning
          category: cloud-security
        annotations:
          summary: "Prowler scan taking too long"
          description: "Prowler scan for {{ $labels.profile }} has been running for over 1 hour"
      
      - alert: InteractshNoInteractions
        expr: rate(shells_interactsh_interactions_total[30m]) == 0 and shells_interactsh_payloads_injected > 0
        for: 15m
        labels:
          severity: info
          category: oob
        annotations:
          summary: "No OOB interactions detected"
          description: "Interactsh has injected payloads but received no interactions in 30 minutes"
      
      # General scanner alerts
      - alert: ScanQueueBacklog
        expr: shells_job_queue_depth{queue="scan"} > 100
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Scan queue backlog detected"
          description: "Scan queue has {{ $value }} pending jobs"
      
      - alert: WorkerHighMemoryUsage
        expr: container_memory_usage_bytes{name=~"shells-worker.*"} / container_spec_memory_limit_bytes > 0.9
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Worker high memory usage"
          description: "Worker {{ $labels.name }} is using {{ $value | humanizePercentage }} of memory limit"
      
      - alert: DatabaseConnectionErrors
        expr: rate(shells_database_errors_total[5m]) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Database connection errors"
          description: "Database error rate is {{ $value }} errors/sec"
      
      - alert: APIHighLatency
        expr: histogram_quantile(0.95, rate(shells_api_request_duration_seconds_bucket[5m])) > 2
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "API high latency"
          description: "95th percentile API latency is {{ $value }}s"
      
      - alert: CriticalVulnerabilityFound
        expr: increase(shells_findings_total{severity="critical"}[1h]) > 0
        labels:
          severity: high
          category: security
        annotations:
          summary: "Critical vulnerability found"
          description: "{{ $value }} new critical vulnerabilities found in the last hour"
      
      - alert: AuthenticationBypassDetected
        expr: shells_findings_total{type=~"SAML_GOLDEN_TICKET|JWT_ALGORITHM_CONFUSION|OAUTH_REDIRECT_BYPASS"} > 0
        labels:
          severity: critical
          category: identity
        annotations:
          summary: "Authentication bypass vulnerability detected"
          description: "Critical authentication bypass found: {{ $labels.type }}"
EOH
        destination = "local/alerts.yml"
      }
      
      resources {
        cpu    = 1000
        memory = 2048
      }
      
      volume_mount {
        volume      = "prometheus-data"
        destination = "/prometheus"
      }
    }
    
    volume "prometheus-data" {
      type      = "host"
      read_only = false
      source    = "prometheus-data"
    }
  }
}

// Grafana for visualization
job "grafana" {
  datacenters = ["dc1"]
  type        = "service"
  
  group "grafana" {
    count = 1
    
    network {
      port "http" {
        static = 3000
      }
    }
    
    service {
      name = "grafana"
      port = "http"
      tags = ["urlprefix-/grafana"]
      
      check {
        type     = "http"
        path     = "/api/health"
        interval = "10s"
        timeout  = "2s"
      }
    }
    
    task "grafana" {
      driver = "docker"
      
      config {
        image = "grafana/grafana:latest"
        ports = ["http"]
      }
      
      env {
        GF_SERVER_ROOT_URL = "http://grafana.service.consul:3000"
        GF_SECURITY_ADMIN_PASSWORD = "admin"
        GF_INSTALL_PLUGINS = "grafana-piechart-panel"
        GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH = "/etc/grafana/dashboards/shells-overview.json"
      }
      
      template {
        data = <<EOH
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus.service.consul:9090
    isDefault: true
    
  - name: Loki
    type: loki
    access: proxy
    url: http://loki.service.consul:3100
EOH
        destination = "local/datasources.yaml"
      }
      
      template {
        data = <<EOH
{
  "dashboard": {
    "title": "Shells Security Scanner - Identity Focus",
    "panels": [
      {
        "title": "Identity Vulnerabilities by Type",
        "type": "piechart",
        "targets": [{
          "expr": "sum by (type) (shells_findings_total{category=\"identity\"})"
        }]
      },
      {
        "title": "Authentication Scanner Performance",
        "type": "graph",
        "targets": [{
          "expr": "rate(shells_scanner_scans_completed_total{scanner=~\"saml|oauth2|jwt|webauthn\"}[5m])"
        }]
      },
      {
        "title": "Prowler Identity Checks",
        "type": "stat",
        "targets": [{
          "expr": "sum(shells_prowler_checks_total{category=\"identity\"})"
        }]
      },
      {
        "title": "OOB Interactions",
        "type": "timeseries",
        "targets": [{
          "expr": "rate(shells_interactsh_interactions_total[5m])"
        }]
      }
    ]
  }
}
EOH
        destination = "local/dashboards/shells-identity.json"
      }
      
      resources {
        cpu    = 500
        memory = 512
      }
      
      volume_mount {
        volume      = "grafana-data"
        destination = "/var/lib/grafana"
      }
    }
    
    volume "grafana-data" {
      type      = "host"
      read_only = false
      source    = "grafana-data"
    }
  }
}

// AlertManager for alert routing
job "alertmanager" {
  datacenters = ["dc1"]
  type        = "service"
  
  group "alertmanager" {
    count = 1
    
    network {
      port "http" {
        static = 9093
      }
    }
    
    service {
      name = "alertmanager"
      port = "http"
      
      check {
        type     = "http"
        path     = "/-/healthy"
        interval = "10s"
        timeout  = "2s"
      }
    }
    
    task "alertmanager" {
      driver = "docker"
      
      config {
        image = "prom/alertmanager:latest"
        ports = ["http"]
        args = [
          "--config.file=/etc/alertmanager/alertmanager.yml",
          "--storage.path=/alertmanager"
        ]
      }
      
      template {
        data = <<EOH
global:
  resolve_timeout: 5m
  slack_api_url: '{{ key "shells/alertmanager/slack_webhook" }}'
  pagerduty_url: 'https://events.pagerduty.com/v2/enqueue'

route:
  group_by: ['alertname', 'category']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'default'
  routes:
  - match:
      category: identity
    receiver: identity-team
  - match:
      severity: critical
    receiver: oncall
  - match:
      category: security
    receiver: security-team

receivers:
- name: 'default'
  slack_configs:
  - channel: '#shells-alerts'
    title: 'Shells Alert'
    text: '{{ range .Alerts }}{{ .Annotations.summary }}\n{{ .Annotations.description }}{{ end }}'

- name: 'identity-team'
  slack_configs:
  - channel: '#identity-security'
    title: 'Identity Security Alert'
    text: '{{ range .Alerts }}{{ .Annotations.summary }}\n{{ .Annotations.description }}{{ end }}'
  email_configs:
  - to: 'identity-team@company.com'
    headers:
      Subject: 'Identity Security Alert: {{ .GroupLabels.alertname }}'

- name: 'oncall'
  pagerduty_configs:
  - service_key: '{{ key "shells/alertmanager/pagerduty_key" }}'
    description: '{{ range .Alerts }}{{ .Annotations.summary }}{{ end }}'

- name: 'security-team'
  webhook_configs:
  - url: 'http://security-webhook.service.consul/alerts'
    send_resolved: true
EOH
        destination = "local/alertmanager.yml"
      }
      
      resources {
        cpu    = 200
        memory = 256
      }
      
      volume_mount {
        volume      = "alertmanager-data"
        destination = "/alertmanager"
      }
    }
    
    volume "alertmanager-data" {
      type      = "host"
      read_only = false
      source    = "alertmanager-data"
    }
  }
}

// Loki for log aggregation
job "loki" {
  datacenters = ["dc1"]
  type        = "service"
  
  group "loki" {
    count = 1
    
    network {
      port "http" {
        static = 3100
      }
    }
    
    service {
      name = "loki"
      port = "http"
      
      check {
        type     = "http"
        path     = "/ready"
        interval = "10s"
        timeout  = "2s"
      }
    }
    
    task "loki" {
      driver = "docker"
      
      config {
        image = "grafana/loki:latest"
        ports = ["http"]
        args = [
          "-config.file=/etc/loki/loki.yaml"
        ]
      }
      
      template {
        data = <<EOH
auth_enabled: false

server:
  http_listen_port: 3100

ingester:
  lifecycler:
    address: 127.0.0.1
    ring:
      kvstore:
        store: inmemory
      replication_factor: 1
    final_sleep: 0s

schema_config:
  configs:
    - from: 2020-10-24
      store: boltdb-shipper
      object_store: filesystem
      schema: v11
      index:
        prefix: index_
        period: 24h

storage_config:
  boltdb_shipper:
    active_index_directory: /loki/boltdb-shipper-active
    cache_location: /loki/boltdb-shipper-cache
    cache_ttl: 24h
    shared_store: filesystem
  filesystem:
    directory: /loki/chunks

limits_config:
  enforce_metric_name: false
  reject_old_samples: true
  reject_old_samples_max_age: 168h

chunk_store_config:
  max_look_back_period: 0s

table_manager:
  retention_deletes_enabled: false
  retention_period: 0s
EOH
        destination = "local/loki.yaml"
      }
      
      resources {
        cpu    = 500
        memory = 1024
      }
      
      volume_mount {
        volume      = "loki-data"
        destination = "/loki"
      }
    }
    
    volume "loki-data" {
      type      = "host"
      read_only = false
      source    = "loki-data"
    }
  }
}