data_dir           = "/opt/nomad"                                                                                                                                                                                   
enable_syslog      = true
region             = "${ps_region}"
datacenter         = "${datacenter_name}"

advertise {
  # Defaults to the first private IP address.
  http = "{{ GetInterfaceIP \"defined1\" }}" # must be reachable by Nomad CLI clients
  rpc  = "{{ GetInterfaceIP \"defined1\" }}" # must be reachable by Nomad client nodes
  serf = "{{ GetInterfaceIP \"defined1\" }}" # must be reachable by Nomad server nodes
}

ports {
  http = 4646
  rpc  = 4647
  serf = 4648
}

server {
  enabled          = true
  encrypt          = "${nomad_encryption_key}"
# authoritative_region = "${auth_region}"  
  bootstrap_expect = 3
  server_join {
    retry_join     = [ "100.100.0.10", "100.100.0.11", "100.100.0.12" ] 
    retry_max      = 5
    retry_interval = "15s"
  }
}

client {
  enabled = false
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

# Enable and configure ACLs
acl {
  enabled    = true
  token_ttl  = "500s"
  policy_ttl = "500s"
  role_ttl   = "500s"
}

telemetry {
  collection_interval = "1s"
  disable_hostname = true
  prometheus_metrics = true
  publish_allocation_metrics = true
  publish_node_metrics = true
}

autopilot {
    cleanup_dead_servers      = true
    last_contact_threshold    = "200ms"
    max_trailing_logs         = 250
    server_stabilization_time = "10s"
    enable_redundancy_zones   = false
    disable_upgrade_migration = false
    enable_custom_upgrades    = false
}

