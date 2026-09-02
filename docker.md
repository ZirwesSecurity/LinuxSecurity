[Back to main document](README.md)

# Docker

- [Installation and configuration](#installation-and-configuration)
- [Automated updates](#automated-updates)
  - [Automatically updating docker itself](#automatically-updating-docker-itself)
  - [Automatically updating docker containers](#automatically-updating-docker-containers)
- [Docker and firewalls](#docker-and-firewalls)
- [General guidelines and gotchas](#general-guidelines-and-gotchas)
- [Example service configuration](#example-service-configuration)
- [Appendix](#appendix)
  - [Cleaning up caches](#cleaning-up-caches)
  - [Configuring rootful docker (not recommended)](#configuring-rootful-docker)

Here, a security baseline for deploying docker containers is described. Tested with Ubuntu and Debian.

## Installation and configuration

To install docker, use the official docker convenience script:
```bash
sudo apt update
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh ./get-docker.sh
```
It is strongly recommended to run docker in rootless mode. Therefore, continue by sopping dockerd with
```bash
sudo rm /var/run/docker.sock
sudo apt install -y uidmap
dockerd-rootless-setuptool.sh install # run as non-root
docker info # shows "rootless" now
```
The docker socket is now at `$XDG_RUNTIME_DIR/docker.sock`. To enable running docker containers after reboot:
```bash
systemctl --user enable docker
sudo loginctl enable-linger $(whoami)
```
Set a baseline configuration for the docker daemon:
```bash
mkdir -p ~/.config/docker/
chmod -R 700 ~/.config/docker/
```
Then, in `~/.config/docker/daemon.json` set
```
{
  "debug": false,
  "allow-direct-routing": false,
  "ip-forward": true,
  "allow-nondistributable-artifacts": [],
  "default-cgroupns-mode": "private",
  "default-network-opts": {
    "bridge": {
      "com.docker.network.bridge.host_binding_ipv4": "127.0.0.1",
      "com.docker.network.bridge.trusted_host_interfaces": "false"
    }
  },
  "log-opts": {
    "cache-disabled": "false",
    "cache-max-file": "5",
    "cache-max-size": "20m",
    "cache-compress": "true",
    "max-file": "5",
    "max-size": "20m"
  },
  "no-new-privileges": true,
  "userland-proxy": false
}
```
Explanations:
 - `"com.docker.network.bridge.host_binding_ipv4": "127.0.0.1"`: prevents accidental exposure of published ports in all interfaces
 - `"userland-proxy": false`: required to see remote IPs inside the containers

```bash
chmod 400 ~/.config/docker/daemon.json
dockerd --validate --config-file ~/.config/docker/daemon.json
```
Enable networking:
```bash
sudo sysctl -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-rootless-docker.conf
sudo sysctl --system
```
To allow exposing privileged ports (if there are existing docker networks, they have to be removed beforehand):
```bash
sudo setcap cap_net_bind_service=ep $(which rootlesskit)
```
You might also have to run
```bash
sudo tee /etc/modules-load.d/docker.conf <<EOF >/dev/null
br_netfilter
EOF
sudo systemctl restart systemd-modules-load.service
```
Restart docker to apply changes
```bash
systemctl --user restart docker
```

## Automated updates

In order to ensure security updates are applied automatically, two things have to be considered
- Docker itself (docker daemon) has to be kept updated
- The docker images have to be updated

### Automatically updating docker itself

See [Third-party repositories and docker](AutomaticUpdates.md#third-party-repositories-and-docker#)

### Automatically updating docker containers

See [Automatic updates for docker containers](AutomaticUpdates.md#automatic-updates-for-docker-containers)

## Docker and firewalls

One important security aspect is that docker by default bypasses rules set up by software firewalls like ufw. See [ufw and docker](ufw.md#ufw-and-docker) for how to fix this.

## General guidelines and gotchas

- Only use [rootless docker](#installation-and-configuration)
- Do not publish ports like this: `ports: 80:8080`. If the port should be published on all interfaces, make the intention clear `ports: 0.0.0.0:80:8080/tcp`
- Docker bypasses ufw by default. See [ufw and docker](ufw.md#ufw-and-docker)
- Keep both docker itself and containers updated. See [Third-party repositories and docker](AutomaticUpdates.md#third-party-repositories-and-docker#) and [Automatic updates for docker containers](AutomaticUpdates.md#automatic-updates-for-docker-containers).
- Never start a container with
  - `privileged: true`
  - `userns_mode: host`
  - `uts: host`
  - `network_mode: host`
  Instead, always run an
  - `read_only: true`
  - `ipc: "none"`
  - `cgroup: "private"`
  - `tty: false`
  - `no-new-privileges:true`
  - `cap_drop: -ALL`
- Never expose the docker socket to a container (not even read-only!). Be careful when using a bind mount with a broad path that could contain the socket (e.g. `/`, `/var`, `/var/run` for rootful docker or `/`, `/run`, `/run/user` for rootless docker). Instead, always use a socket proxy (see [Example service configuration](#example-service-configuration)
- Limit the paths from the host that are exposed to the container. Always use `:ro,noexec,nosuid,nodev`. For writable storage, consider `tmpfs`
- Limit the amount of containers that have a connection to the outside world. Use internal networks as much as possible and segregate containers from one another by using separate networks

## Example service configuration

The following shows a deployment template for a webserver with `compose.yaml`:

## Appendix

### Cleaning up caches

```bash
docker builder prune -a -f
docker image prune -a -f
docker container prune -f
docker system prune -a -f --volumes
docker volume prune
```

### Configuring rootful docker (not recommended)

If rootful docker absolutely must be used, at least enable user namespace remapping:
In `/etc/docker/daemon.json`, write
```
{
  "debug": false,
  "allow-direct-routing": false,
  "ip-forward": true,
  "icc": false,
  "allow-nondistributable-artifacts": [],
  "default-cgroupns-mode": "private",
  "default-network-opts": {
    "bridge": {
      "com.docker.network.bridge.host_binding_ipv4": "127.0.0.1",
      "com.docker.network.bridge.enable_icc": "false",
      "com.docker.network.bridge.trusted_host_interfaces": "false"
    }
  },
  "log-opts": {
    "cache-disabled": "false",
    "cache-max-file": "5",
    "cache-max-size": "20m",
    "cache-compress": "true",
    "max-file": "5",
    "max-size": "20m"
  },
  "no-new-privileges": true,
  "userns-remap": "default"
}
```
The important part is `"userns-remap": "default"`. If a process breaks out of a container, it is at least not mapped to a real user on the host.


