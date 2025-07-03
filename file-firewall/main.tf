terraform {
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
  }
}

provider "docker" {}

##############################################
# 1. Build and run your file-firewall image #
##############################################

resource "docker_image" "file_firewall_image" {
  name = "file-firewall:latest"

  build {
    context    = "${path.module}"
    dockerfile = "${path.module}/Dockerfile"
  }
}

resource "docker_container" "file_firewall_container" {
  name    = "file_firewall_container"
  image   = docker_image.file_firewall_image.name
  restart = "unless-stopped"

  ports {
    internal = 5000
    external = 8080
    ip       = "0.0.0.0"
  }
}

##############################################
# 2. Run Falco container for runtime security #
##############################################

resource "docker_image" "falco_image" {
  name = "falcosecurity/falco:latest"
}

resource "docker_container" "falco_container" {
  name  = "falco"
  image = docker_image.falco_image.name

  # Required for Falco to monitor host syscalls
  privileged = true
  restart    = "unless-stopped"
  network_mode = "host"

  mounts {
    target = "/host/var/run/docker.sock"
    source = "/var/run/docker.sock"
    type   = "bind"
    read_only = false
  }

  mounts {
    target = "/host/dev"
    source = "/dev"
    type   = "bind"
    read_only = false
  }

  mounts {
    target = "/host/proc"
    source = "/proc"
    type   = "bind"
    read_only = true
  }

  mounts {
    target = "/host/boot"
    source = "/boot"
    type   = "bind"
    read_only = true
  }

  mounts {
    target = "/host/lib/modules"
    source = "/lib/modules"
    type   = "bind"
    read_only = true
  }

  mounts {
    target = "/host/usr"
    source = "/usr"
    type   = "bind"
    read_only = true
  }

  # Optional: Falco runs before your app
  depends_on = [docker_container.file_firewall_container]
}
