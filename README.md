## Nomad client without Consul but on a defined.net overlay network

This repo sets up one Nomad client in one OpenStack environment. It uses [defined-systemd-units](https://github.com/quickvm/defined-systemd-units) to automatically install and enroll a host in an overlay network. 
All Nomad clients in the overlay network will get IP addresses dynamically assigned to them. 

Nomad clients should "unenroll" from the defined.net network. That's why you should set DN_SKIP_UNENROLL to "false". 
