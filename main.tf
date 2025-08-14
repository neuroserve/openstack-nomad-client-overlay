locals {
    nomad_version="1.10.3"
    cni_version="1.7.1"
    consul_cni_version="1.8.0"
    podman_version="0.6.3"
    nvidia_version="1.1.0"
    traefik_version="3.5.0"
    traefik_checksum="2ecdcb14492481749176710bce15434bcc22c3124f32867233bb00f4160de661"
    autoscaler_version="0.4.7"
}

variable "auth_url" {
  type    = string
  default = "https://myauthurl5000" 
}

variable "user_name" {
  type    = string
  default = "username" 
}

variable "password" {
  type    = string
  default = "totalgeheim" 
}

variable "tenant_name" {
  type    = string
  default = "myproject"
}

variable "user_domain_name" {
  type    = string
  default = "mydomain"
}

variable "region" {
  type   = string
  default = "myregion"
}


#
# This assumes, that you already have a CA - see "nomad tls ca -help" if you don't have one yet
#

resource "tls_private_key" "nomad" {
    count = var.config.client_nodes
    algorithm = "RSA"
    rsa_bits  = "4096"
}

resource "tls_cert_request" "nomad" {
    count = "${var.config.client_nodes}"
#   key_algorithm   = "${element(tls_private_key.nomad.*.algorithm, count.index)}"
    private_key_pem = "${element(tls_private_key.nomad.*.private_key_pem, count.index)}"

    dns_names = [
        "nomad",
        "nomad.local",
        "server.${var.config.datacenter_name}.nomad",
        "nomad.service.${var.config.domain_name}",
        "nomad-client-${count.index}.server.${var.config.domain_name}.nomad",
        "localhost",
        "127.0.0.1",
    ]

    ip_addresses = [
        "127.0.0.1",
    ]

    subject {
        common_name = "server.${var.config.datacenter_name}.nomad"
        organization = var.config.organization.name
    }
}

resource "tls_locally_signed_cert" "nomad" {
    count = var.config.client_nodes
    cert_request_pem = "${element(tls_cert_request.nomad.*.cert_request_pem, count.index)}"
#   ca_key_algorithm = "{(element(tls_cert_request.nomad.*.key_algorithm)}"

    ca_private_key_pem = file("${var.config.private_key_pem}")
    ca_cert_pem        = file("${var.config.certificate_pem}")

    validity_period_hours = 8760

    allowed_uses = [
        "cert_signing",
        "client_auth",
        "digital_signature",
        "key_encipherment",
        "server_auth",
    ]
}

data "openstack_images_image_v2" "os" {
  name        = "debian-11-consul"
  most_recent = "true"
}

resource "openstack_compute_keypair_v2" "user_keypair" {
  name       = "tf_nomad-client"
  public_key = file("${var.config.keypair}")
}

resource "openstack_networking_secgroup_v2" "sg_nomad_client3" {
  name        = "sg_nomad_client3"
  description = "Security Group for servergroup"
}

resource "openstack_networking_secgroup_rule_v2" "sr_ssh" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.sg_nomad_client3.id
}

resource "openstack_networking_secgroup_rule_v2" "sr_dns1" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 53
  port_range_max    = 53
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.sg_nomad_client3.id
}

resource "openstack_networking_secgroup_rule_v2" "sr_dns2" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "udp"
  port_range_min    = 53
  port_range_max    = 53
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.sg_nomad_client3.id
}

resource "openstack_networking_secgroup_rule_v2" "sr_4646tcp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 4646
  port_range_max    = 4646
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.sg_nomad_client3.id
}

resource "openstack_networking_secgroup_rule_v2" "sr_4647tcp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 4647
  port_range_max    = 4647
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.sg_nomad_client3.id
}

resource "openstack_networking_secgroup_rule_v2" "sr_4648tcp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 4648
  port_range_max    = 4648
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.sg_nomad_client3.id
}

resource "openstack_networking_secgroup_rule_v2" "sr_4648udp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "udp"
  port_range_min    = 4648
  port_range_max    = 4648
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.sg_nomad_client3.id
}


#resource "openstack_networking_rbac_policy_v2" "net_rbac_policy" {
#  action        = "access_as_shared"
#  #action        = "access_as_external"
#  object_id     = var.config.instance_network_uuid
#  object_type   = "network"
#  target_tenant = var.config.target_tenant
#}

#resource "openstack_networking_router_route_v2" "route_shared_network" {
#  router_id        = "dc1476af-3c58-4ebc-bd53-c201db538a34"
#  destination_cidr = "192.168.1.0/24"
#  next_hop         = "192.168.0.139"
#}

resource "openstack_networking_floatingip_v2" "client_flip" {
  count = var.config.client_nodes
  pool  = "ext01"
}

resource "openstack_compute_floatingip_associate_v2" "client_flip" {
   count       = var.config.client_nodes
   floating_ip = "${element(openstack_networking_floatingip_v2.client_flip.*.address, count.index)}"
   instance_id = "${element(openstack_compute_instance_v2.nomad.*.id, count.index)}"
}

resource "openstack_compute_instance_v2" "nomad" {
  name            = "nomad-client-${var.config.datacenter_name}-${count.index}"
  image_id        = data.openstack_images_image_v2.os.id
  flavor_name     = var.config.flavor_name
  key_pair        = openstack_compute_keypair_v2.user_keypair.name
  count           = var.config.client_nodes
  security_groups = ["sg_nomad_client3", "default"]   
  scheduler_hints {
    group = openstack_compute_servergroup_v2.nomadcluster.id
  }

#  network {
#    uuid = var.config.instance_backnet_uuid
#  }

  network {
    uuid = var.config.instance_network_uuid
  }
  
  metadata = {
     nomad-role = "client"
     public-ipv4 = "${element(openstack_networking_floatingip_v2.client_flip.*.address, count.index)}"
     ps_restart_after_maint = "true"
  }

  connection {
       type = "ssh"
       user = "root" 
       private_key = file("${var.config.connkey}")
       agent = "true" 
       bastion_host = "${var.config.bastionhost}"
       bastion_user = "debian" 
       bastion_private_key = file("${var.config.connkey}")
       host = self.access_ip_v4
  }

  provisioner "remote-exec" {
        inline = [
            "sudo apt-get update",
            "sudo mkdir -p /etc/nomad/certificates",
            "sudo mkdir -p /opt/nomad",
            "sudo chown root /opt/nomad",
            "sudo chgrp root /opt/nomad",
            "sudo mkdir -p /etc/nomad-autoscaler",
            "sudo mkdir -p /opt/nomad-autoscaler/plugins",
        ]
   }

   provisioner "remote-exec" {
        inline = [
            "sudo mkdir -p /opt/cni/bin",
            "sudo mkdir -p /opt/cni/config",
            "cd /opt/cni/bin ; wget --no-check-certificate https://github.com/containernetworking/plugins/releases/download/v${local.cni_version}/cni-plugins-linux-amd64-v${local.cni_version}.tgz ",
            "cd /opt/cni/bin ; tar -xvf cni-plugins-linux-amd64-v${local.cni_version}.tgz",
#           "echo 1 | sudo tee /proc/sys/net/bridge/bridge-nf-call-arptables && echo 1 | sudo tee /proc/sys/net/bridge/bridge-nf-call-ip6tables && echo 1 | sudo tee /proc/sys/net/bridge/bridge-nf-call-iptables",
#           "cd /opt/cni/bin ; rm /opt/cni/bin/cni-plugins-linux-adm64-v${local.cni_version}.tgz",
        ]
   }

   provisioner "remote-exec" {
        inline = [
            "cd /opt/cni/bin ; wget --no-check-certificate https://releases.hashicorp.com/consul-cni/${local.consul_cni_version}/consul-cni_${local.consul_cni_version}_linux_amd64.zip ",
            "cd /opt/cni/bin ; unzip consul-cni_${local.consul_cni_version}_linux_amd64.zip",
#           "echo 1 | sudo tee /proc/sys/net/bridge/bridge-nf-call-arptables && echo 1 | sudo tee /proc/sys/net/bridge/bridge-nf-call-ip6tables && echo 1 | sudo tee /proc/sys/net/bridge/bridge-nf-call-iptables",
#           "cd /opt/cni/bin ; rm /opt/cni/bin/cni-plugins-linux-adm64-v${local.cni_version}.tgz",
        ]
   }

   provisioner "remote-exec" {
        inline = [
            "sudo apt-get install -y ca-certificates curl gnupg tmux telnet dnsutils jq git",
            "sudo install -m 0755 -d /etc/apt/keyrings",
            "curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg",
            "sudo chmod a+r /etc/apt/keyrings/docker.gpg",
        ]
   }

   provisioner "file" {
        content = file("${path.module}/files/docker.list") 
        destination = "/etc/apt/sources.list.d/docker.list"
   }

   provisioner "file" {
        content = file("${path.module}/files/bridge.conf")
        destination = "/etc/sysctl.d/bridge.conf"
   }

   provisioner "file" {
        content = file("${var.config.certificate_pem}")
        destination = "/etc/nomad/certificates/ca.pem"
   }

   provisioner "file" {
        content = tls_locally_signed_cert.nomad[count.index].cert_pem
        destination = "/etc/nomad/certificates/cert.pem"
   }

   provisioner "file" {
        content = tls_private_key.nomad[count.index].private_key_pem
        destination = "/etc/nomad/certificates/private_key.pem"
   }

   provisioner "file" {
        content = file("${path.module}/files/nomad.service") 
        destination = "/etc/systemd/system/nomad.service"
   }

   provisioner "remote-exec" {
      inline = [
        "sudo mkdir -p /etc/systemd/resolved.conf.d",
      ]
   }

   provisioner "file" {
    source = "${path.root}/files/docker.conf"
    destination = "/etc/systemd/resolved.conf.d/docker.conf"
   }

   provisioner "file" {
    source = "${path.root}/files/daemon.json"
    destination = "/etc/docker/daemon.json"
   }

   provisioner "file" {
        content = templatefile("${path.module}/templates/nomad.hcl.tpl", {
            datacenter_name = var.config.datacenter_name,
            domain_name = var.config.domain_name,
            os_domain_name = var.config.os_domain_name,
            node_name = "nomad-client-${count.index}",
            bootstrap_expect = var.config.client_nodes,
            upstream_dns_servers = var.config.dns_servers,
            auth_url = "${var.auth_url}",
            user_name = "${var.user_name}",
            password = "${var.password}",
            os_region   = "${var.config.os_region}",
            ps_region   = "${var.config.ps_region}",
            token = "${var.config.nomad_client_token}"
        })
        destination = "/etc/nomad/nomad.hcl"
   }

  provisioner "remote-exec" {
       inline = [
#           "cd /tmp ; curl -O https://dl.defined.net/845e340d/v0.8.1./linux/amd64/dnclient",
#           "sudo chmod +x /tmp/dnclient ; mv /tmp/dnclient /usr/local/bin",
           "cd /tmp ; git clone https://github.com/neuroserve/defined-systemd-units.git",
           "cd /tmp/defined-systemd-units ; sudo ./install",
       ]
 
  }

  provisioner "file" {
       content = templatefile("${path.module}/templates/dnctl.tpl", {
           dn_api_key = var.config.dnkey,
           dn_network_id = var.config.dnnetid,
           dn_role_id = var.config.dnroleid,
           dn_skip_unenroll = var.config.dnunenroll,
           dn_name = "nomad-${var.config.datacenter_name}-${count.index}",
           dn_tags = var.config.dntags,
       })
       destination = "/etc/defined/dnctl"
  }

  provisioner "remote-exec" {
       inline = [
           "dnctl enable",
#          "dnctl start",
       ]
  }

  provisioner "remote-exec" {
        inline = [
            "sudo apt-get update",
            "sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin",
        ]
  }

  provisioner "remote-exec" {
        inline = [
            "cd /tmp ; curl -sLO https://github.com/traefik/traefik/releases/download/v${local.traefik_version}/traefik_v${local.traefik_version}_linux_amd64.tar.gz", 
            "echo '${local.traefik_checksum} traefik_v${local.traefik_version}_linux_amd64.tar.gz' | /usr/bin/sha256sum -c --quiet",
            "cd /tmp ; sudo tar zxvf traefik_v${local.traefik_version}_linux_amd64.tar.gz -C /usr/local/bin", 
            "rm /tmp/traefik_v${local.traefik_version}_linux_amd64.tar.gz",
            "sudo chmod +x /usr/local/bin/traefik",
        ]
  }

  provisioner "remote-exec" {
        inline = [
            "sudo apt-get install -y podman",
            "sudo mkdir -p /opt/nomad/plugins",
            "cd /tmp ; wget --no-check-certificate https://releases.hashicorp.com/nomad-driver-podman/${local.podman_version}/nomad-driver-podman_${local.podman_version}_linux_amd64.zip",
            "cd /tmp ; unzip -n nomad-driver-podman_${local.podman_version}_linux_amd64.zip",
            "cd /tmp ; rm nomad-driver-podman_${local.podman_version}_linux_amd64.zip",
            "mv /tmp/nomad-driver-podman /opt/nomad/plugins/nomad-driver-podman",
        ]
  }

  provisioner "remote-exec" {
        inline = [
            "sudo mkdir -p /opt/nomad/plugins",
            "cd /tmp ; wget --no-check-certificate https://releases.hashicorp.com/nomad-device-nvidia/${local.nvidia_version}/nomad-device-nvidia_${local.nvidia_version}_linux_amd64.zip",
            "cd /tmp ; unzip -n nomad-device-nvidia_${local.nvidia_version}_linux_amd64.zip",
            "cd /tmp ; rm nomad-device-nvidia_${local.nvidia_version}_linux_amd64.zip",
            "mv /tmp/nomad-device-nvidia /opt/nomad/plugins/nomad-device-nvidia",
        ]
  }


  provisioner "remote-exec" {
       inline = [
           "cd /tmp ; wget --no-check-certificate https://releases.hashicorp.com/nomad-autoscaler/${local.autoscaler_version}/nomad-autoscaler_${local.autoscaler_version}_linux_amd64.zip",
           "cd /tmp ; unzip -n nomad-autoscaler_${local.autoscaler_version}_linux_amd64.zip",
           "cd /tmp ; rm nomad-autoscaler_${local.autoscaler_version}_linux_amd64.zip",

           "mv /tmp/nomad-autoscaler /usr/local/bin/nomad-autoscaler",
       ]
  }

  provisioner "remote-exec" {
       inline = [
           "cd /tmp ; wget --no-check-certificate https://github.com/jorgemarey/nomad-nova-autoscaler/releases/download/v0.6.0/nomad-nova-autoscaler-v0.6.0-linux-amd64.tar.gz",
           "cd /tmp ; tar -xvzf nomad-nova-autoscaler-v0.6.0-linux-amd64.tar.gz",
           "cd /tmp ; rm nomad-nova-autoscaler-v0.6.0-linux-amd64.tar.gz",
           
           "mv /tmp/os-nova /opt/nomad-autoscaler/plugins/",
       ]
  }

  provisioner "remote-exec" {
         inline = [
             "sudo apt-get install -y dnsmasq",
             "sudo systemctl disable systemd-resolved",
             "sudo systemctl stop systemd-resolved",
             "sudo systemctl enable dnsmasq",
         ]
   }

   provisioner "file" {
    source = "${path.root}/files/10-consul.dnsmasq"
    destination = "/etc/dnsmasq.d/10-consul"
   }

   provisioner "file" {
    source = "${path.root}/files/dnsmasq.conf"
    destination = "/etc/dnsmasq.conf"
   }

   provisioner "remote-exec" {
         inline = [
             "sudo systemctl start dnsmasq",
             "sudo systemctl daemon-reload",
         ]
   }

   provisioner "remote-exec" {
        inline = [
            "cd /tmp ; wget --no-check-certificate https://releases.hashicorp.com/nomad/${local.nomad_version}/nomad_${local.nomad_version}_linux_amd64.zip",
            "cd /tmp ; unzip -n -o nomad_${local.nomad_version}_linux_amd64.zip",
            "cd /tmp ; rm nomad_${local.nomad_version}_linux_amd64.zip",

            "mv /tmp/nomad /usr/local/bin/nomad",
            "sudo systemctl enable nomad",
#           "sudo systemctl start nomad",
        ]
   }

}


resource "openstack_compute_servergroup_v2" "nomadcluster" {
  name = "aaf-sg"
  policies = ["anti-affinity"]
}

