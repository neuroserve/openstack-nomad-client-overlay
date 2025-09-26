datacenter = "${ps_region}"
data_dir   =  "/opt/consul"
log_level  =  "INFO"
server     =  false
leave_on_terminate = true

retry_join = ["100.102.0.30", "100.102.0.31", "100.102.0.32"]
encrypt    = "${encryption_key}"

ca_file    = "/etc/consul/certificates/ca.pem"
cert_file  = "/etc/consul/certificates/cert.pem"
key_file   = "/etc/consul/certificates/private_key.pem"

bind_addr      = "{{ GetInterfaceIP \"defined1\" }}"
advertise_addr = "{{ GetInterfaceIP \"defined1\" }}"
client_addr    = "{{ GetInterfaceIP \"defined1\" }}"

addresses {
   http     = "{{ GetInterfaceIP \"defined1\" }}"
   https    = "{{ GetInterfaceIP \"defined1\" }}"
   grpc     = "{{ GetInterfaceIP \"defined1\" }}"
}

recursors = ["62.138.222.111","62.138.222.222"]



