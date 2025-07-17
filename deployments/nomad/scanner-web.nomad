job "shells-scan-web" {
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
    
    task "web-scan" {
      driver = "docker"
      
      config {
        image = "shells-web:latest"
        command = "/bin/bash"
        args = ["-c", "httpx -u ${NOMAD_META_TARGET} ${NOMAD_META_OPTIONS} -o /tmp/results.txt && cat /tmp/results.txt"]
        
        # Mount for result output
        volumes = [
          "/opt/nomad/results:/tmp/results"
        ]
      }
      
      env {
        TARGET = "${NOMAD_META_TARGET}"
        SCAN_ID = "${NOMAD_META_SCAN_ID}"
        SCAN_TYPE = "web"
      }
      
      resources {
        cpu    = 300
        memory = 512
      }
      
      # Timeout after 15 minutes
      kill_timeout = "10s"
      
      constraint {
        attribute = "${attr.kernel.name}"
        value     = "linux"
      }
    }
  }
}