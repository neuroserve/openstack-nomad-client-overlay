data_dir           = "/opt/nomad"                                                                                                                                                                                   
enable_syslog      = true
region             = "${ps_region}"
datacenter         = "${datacenter_name}"
name               = "${node_name}"
client {
  enabled          = true
# node_pool        = ""
  cni_path         = "/opt/cni/bin"
  cni_config_dir   = "/opt/cni/config"
  server_join {
    retry_join     = [ "100.100.0.10", "100.100.0.11", "100.100.0.12" ] 
    retry_max      = 5
    retry_interval = "15s"
  }
  host_network "overlay" {
    interface = "defined1"
  }
  host_network "internal" {
    interface = "ens3"
  }
  host_network "local" {
    interface = "lo"
  }
}

advertise {
  # Defaults to the first private IP address.
  http = "{{ GetInterfaceIP \"defined1\" }}" # must be reachable by Nomad CLI clients
  rpc  = "{{ GetInterfaceIP \"defined1\" }}" # must be reachable by Nomad client nodes
  serf = "{{ GetInterfaceIP \"defined1\" }}" # must be reachable by Nomad server nodes
}

tls {
  http = true
  rpc  = true
  ca_file   = "/etc/nomad/certificates/ca.pem"
  cert_file = "/etc/nomad/certificates/cert.pem"
  key_file  = "/etc/nomad/certificates/private_key.pem"

  verify_server_hostname = false
  verify_https_client    = false
}

telemetry {
  collection_interval = "1s"
  disable_hostname = true
  prometheus_metrics = true
  publish_allocation_metrics = true
  publish_node_metrics = true
}

plugin "docker" {
  config {
    allow_privileged = true
  }
}
