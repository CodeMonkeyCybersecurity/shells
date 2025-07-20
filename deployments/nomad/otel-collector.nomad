job "otel-collector" {
  datacenters = ["dc1"]
  type        = "service"
  
  group "collector" {
    count = 1
    
    network {
      port "otlp-grpc" {
        static = 4317
      }
      port "otlp-http" {
        static = 4318
      }
      port "metrics" {
        static = 8888
      }
    }
    
    service {
      name = "otel-collector"
      port = "otlp-grpc"
      
      check {
        type     = "tcp"
        interval = "30s"
        timeout  = "5s"
      }
    }
    
    task "collector" {
      driver = "docker"
      
      config {
        image = "otel/opentelemetry-collector-contrib:latest"
        ports = ["otlp-grpc", "otlp-http", "metrics"]
        args = ["--config", "/local/otel-config.yaml"]
      }
      
      template {
        data = <<EOH
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318

processors:
  batch:
  resource:
    attributes:
      - key: service.name
        value: shells
        action: upsert
      - key: deployment.environment
        value: nomad
        action: upsert

exporters:
  logging:
    loglevel: info
  
  # Uncomment to export to Jaeger
  # jaeger:
  #   endpoint: http://jaeger:14250
  #   tls:
  #     insecure: true
  
  # Uncomment to export to Prometheus
  # prometheus:
  #   endpoint: "0.0.0.0:8889"

service:
  telemetry:
    metrics:
      address: 0.0.0.0:8888
  
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch, resource]
      exporters: [logging]
    
    metrics:
      receivers: [otlp]
      processors: [batch, resource]
      exporters: [logging]
    
    logs:
      receivers: [otlp]
      processors: [batch, resource]
      exporters: [logging]
EOH
        destination = "local/otel-config.yaml"
      }
      
      resources {
        cpu    = 300
        memory = 512
      }
    }
  }
}