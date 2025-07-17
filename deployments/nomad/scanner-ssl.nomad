job "shells-scan-ssl" {
  datacenters = ["dc1"]
  type = "batch"
  
  parameterized {
    payload = "required"
    meta_required = ["target", "scan_id", "options"]
  }
  
  group "scanner" {
    count = 1
    
    restart {
      attempts = 2
      interval = "30m"
      delay = "15s"
      mode = "fail"
    }
    
    task "ssl-scan" {
      driver = "docker"
      
      config {
        image = "shells-ssl:latest"
        command = "/bin/bash"
        args = ["-c", "echo | openssl s_client -connect ${NOMAD_META_TARGET}:${NOMAD_META_PORT:-443} ${NOMAD_META_OPTIONS} > /tmp/results.txt 2>&1 && cat /tmp/results.txt"]
        
        # Mount for result output
        volumes = [
          "/opt/nomad/results:/tmp/results"
        ]
      }
      
      env {
        TARGET = "${NOMAD_META_TARGET}"
        SCAN_ID = "${NOMAD_META_SCAN_ID}"
        SCAN_TYPE = "ssl"
        PORT = "${NOMAD_META_PORT:-443}"
      }
      
      resources {
        cpu    = 100
        memory = 128
      }
      
      # Timeout after 5 minutes
      kill_timeout = "10s"
      
      constraint {
        attribute = "${attr.kernel.name}"
        value     = "linux"
      }
    }
  }
}