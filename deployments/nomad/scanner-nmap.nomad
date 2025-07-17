job "shells-scan-nmap" {
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
    
    task "nmap-scan" {
      driver = "docker"
      
      config {
        image = "shells-nmap:latest"
        command = "/bin/bash"
        args = ["-c", "nmap ${NOMAD_META_OPTIONS} ${NOMAD_META_TARGET} > /tmp/results.txt 2>&1 && cat /tmp/results.txt"]
        
        # Mount for result output
        volumes = [
          "/opt/nomad/results:/tmp/results"
        ]
      }
      
      env {
        TARGET = "${NOMAD_META_TARGET}"
        SCAN_ID = "${NOMAD_META_SCAN_ID}"
        SCAN_TYPE = "port"
      }
      
      resources {
        cpu    = 200
        memory = 256
      }
      
      # Timeout after 10 minutes
      kill_timeout = "10s"
      
      constraint {
        attribute = "${attr.kernel.name}"
        value     = "linux"
      }
    }
  }
}