[Back to main document](README.md)

# Docker

- [Installation and configuration](#installation-and-configuration)
- [Automated updates](#automated-updates)
  - [Automatically updating docker itself](#automatically-updating-docker-itself)
  - [Automatically updating docker containers](#automatically-updating-docker-containers)
- [Docker and firewalls](#docker-and-firewalls)
- [General guidelines and gotchas](#general-guidelines-and-gotchas)
- [Example service configuration](#example-service-configuration)
- [Secrets](#secrets)
- [Appendix](#appendix)
  - [Cleaning up caches](#cleaning-up-caches)
  - [Configuring rootful docker (not recommended)](#configuring-rootful-docker-not-recommended)

Here, a security baseline for deploying docker containers is described. Tested with Ubuntu and Debian. In [Example service configuration](#example-service-configuration),
a baseline configuration template is provided for a webserver running `nginx`, with `php` backend and `traefik` as reverse proxy.

## Installation and configuration

To install docker, use the official docker convenience script:
```bash
sudo apt update
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh ./get-docker.sh
```
It is strongly recommended to run docker in rootless mode. Therefore, continue by stopping dockerd and install rootless docker:
```bash
sudo systemctl disable --now docker.service docker.socket
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
 - `"com.docker.network.bridge.host_binding_ipv4": "127.0.0.1"`: prevents accidental exposure of published ports on all interfaces
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

See [Third-party repositories and docker](AutomaticUpdates.md#third-party-repositories-and-docker)

### Automatically updating docker containers

See [Automatic updates for docker containers](AutomaticUpdates.md#automatic-updates-for-docker-containers)

## Docker and firewalls

One important security aspect is that docker by default bypasses rules set up by software firewalls like ufw. See [ufw and docker](ufw.md#ufw-and-docker) for how to fix this.

## General guidelines and gotchas

- Only use [rootless docker](#installation-and-configuration)
- Do not publish ports like this: `ports: 80:8080`. If the port should be published on all interfaces, make the intention clear `ports: 0.0.0.0:80:8080/tcp`
- Docker bypasses ufw by default. See [ufw and docker](ufw.md#ufw-and-docker)
- Keep both docker itself and containers updated. See [Third-party repositories and docker](AutomaticUpdates.md#third-party-repositories-and-docker) and [Automatic updates for docker containers](AutomaticUpdates.md#automatic-updates-for-docker-containers).
- Never start a container with
  - `privileged: true`
  - `userns_mode: host`
  - `uts: host`
  - `network_mode: host`
  - `pid: host`
  
  Instead, always run with
  - `read_only: true`
  - `ipc: "none"`
  - `cgroup: "private"`
  - `tty: false`
  - `no-new-privileges:true`
  - `cap_drop: -ALL`
  - `user: "6000:6000"` # run as an arbitrary user, choose differnt UID for every service
- Never expose the docker socket to a container (not even read-only!). Be careful when using a bind mount with a broad path that could contain the socket (e.g. `/`, `/var`, `/var/run` for rootful docker or `/`, `/run`, `/run/user` for rootless docker). Instead, always use a socket proxy (see [Example service configuration](#example-service-configuration))
- Limit the paths from the host that are exposed to the container. Always use `:ro,noexec,nosuid,nodev`. For writable storage, consider `tmpfs`
- Limit the amount of containers that have a connection to the outside world. Use internal networks as much as possible and segregate containers from one another by using separate networks
- Prefer either `network: "none"` or user defined bridge networks
- Create a dedicated user for docker

## Example service configuration

The following shows a deployment template for a webserver running `nginx`, with `php` backend and `traefik` as reverse proxy, set up via `compose.yaml`:
```yaml
# compose.yaml

#hardening baseline
x-hardening: &hardening
  read_only: true
  ipc: "none"
  cgroup: "private"
  tty: false
  security_opt:
    - no-new-privileges:true
  cap_drop:
    - ALL

services:


  socketproxy:
    image: linuxserver/socket-proxy:latest
    container_name: socketproxy
    # apply hardening baseline
    <<: *hardening
    user: "0:0" # required to access the socket, otherwise, never run as 0:0
    restart: unless-stopped
    environment: # configure the socket proxy to reject dangerous actions
      - TZ="${TZ}"
      # allow
      - CONTAINERS=1
      - EVENTS=1
      - NETWORKS=1
      - PING=1
      - VERSION=1
      # disallow
      - ALLOW_ARCHIVE=0
      - ALLOW_CHANGES=0
      - ALLOW_EXPORT=0
      - ALLOW_LOGS=0
      - ALLOW_PAUSE=0
      - ALLOW_RESTARTS=0
      - ALLOW_STOP=0
      - ALLOW_START=0
      - ALLOW_TOP=0
      - ALLOW_UNPAUSE=0
      - AUTH=0
      - BUILD=0
      - COMMIT=0
      - CONFIGS=0
      - DISABLE_IPV6=0
      - DISTRIBUTION=0
      - EXEC=0
      - IMAGES=0
      - INFO=0
      - LOG_LEVEL=info
      - NODES=0
      - PLUGINS=0
      - POST=0 # important: makes access read-only
      - SECRETS=0
      - SERVICES=0
      - SESSION=0
      - SWARM=0
      - SYSTEM=0
      - TASKS=0
      - VOLUMES=0
   volumes: # expose the docker socket. Never do this other than for the socket proxy
      - /run/user/1000/docker.sock:/var/run/docker.sock:ro,noexec,nosuid,nodev
    tmpfs:
      - /run:rw,noexec,nosuid,nodev,mode=700,uid=0,gid=0,size=500m,nr_inodes=400k
    #ports:
    # DO NOT EXPOSE
    networks: # access to the docker socket is dangerous. Do not expose this container
      - socketproxynetwork #  to the outside by using an internal network here

  traefik: # use traefik as reverse proxy
    image: traefik:v3
    container_name: traefik
    # apply hardening baseline
    <<: *hardening
    depends_on:
      socketproxy:
        condition: service_started # TODO: better health check?
    user: "${TRAEFIK_UID}:${TRAEFIK_UID}"
    restart: unless-stopped
    environment:
      TZ: "${TZ}"
    ports: # publish ports on public interfaces explicitly
      - "0.0.0.0:80:80/tcp"
      - "0.0.0.0:443:443/tcp"
      - "[::]:80:80/tcp"
      - "[::]:443:443/tcp"
    command:
      - "--providers.docker=true"
      # access to docker socket via socketproxy
      - "--providers.docker.endpoint=tcp://socketproxy:2375"
      # no not create default routing rules for services
      - "--providers.docker.exposedbydefault=false"
      - "--providers.docker.useBindPortIP=false"
      - "--serversTransport.insecureSkipVerify=true"
      # apply baseline traefik hardening (see below)
      - "--providers.file.filename=/etc/traefiksecurity.yaml"
      - "--ping=false"
      # HTTP
      - "--entrypoints.web.address=:80/tcp"
      - "--entrypoints.web.http.sanitizePath=true"
      - "--entrypoints.web.forwardedHeaders.insecure=false"
      - "--entrypoints.web.http.aliasHeadersStrategy=reject"
      - "--entrypoints.web.http.maxHeaderBytes=65536"
      - "--entrypoints.web.http.encodedCharacters.allowEncodedSlash=false"
      - "--entrypoints.web.http.encodedCharacters.allowEncodedBackSlash=false"
      - "--entrypoints.web.http.encodedCharacters.allowEncodedNullCharacter=false"
      - "--entrypoints.web.http.encodedCharacters.allowEncodedSemicolon=false"
      - "--entrypoints.web.http.encodedCharacters.allowEncodedPercent=false"
      - "--entrypoints.web.http.encodedCharacters.allowEncodedQuestionMark=false"
      - "--entrypoints.web.http.encodedCharacters.allowEncodedHash=false"
      - "--entrypoints.web.http.encodedCharacters.allowEncodedSemicolon=false"
      - "--entrypoints.web.http.encodeQuerySemicolons=true"
      # HTTPS
      - "--core.strictTLSOptions=true"
      - "--entrypoints.websecure.address=:443/tcp"
      - "--entrypoints.websecure.http.sanitizePath=true"
      - "--entrypoints.websecure.http.aliasHeadersStrategy=reject"
      - "--entrypoints.websecure.forwardedHeaders.insecure=false"
      - "--entrypoints.websecure.http.maxHeaderBytes=65536"
      - "--entrypoints.web.http.redirections.entrypoint.to=websecure"
      - "--entrypoints.web.http.redirections.entrypoint.scheme=https"
      - "--entrypoints.web.http.redirections.entrypoint.permanent=true"
      - "--certificatesresolvers.le.acme.tlschallenge=true"
      - "--certificatesresolvers.le.acme.email=${ACME_EMAIL}"
      - "--certificatesresolvers.le.acme.storage=/data/acme.json"
      - "--certificatesresolvers.le.acme.keytype=EC384" # or RSA4096
      - "--entrypoints.websecure.http.encodedCharacters.allowEncodedSlash=false"
      - "--entrypoints.websecure.http.encodedCharacters.allowEncodedBackSlash=false"
      - "--entrypoints.websecure.http.encodedCharacters.allowEncodedNullCharacter=false"
      - "--entrypoints.websecure.http.encodedCharacters.allowEncodedSemicolon=false"
      - "--entrypoints.websecure.http.encodedCharacters.allowEncodedPercent=false"
      - "--entrypoints.websecure.http.encodedCharacters.allowEncodedQuestionMark=false"
      - "--entrypoints.websecure.http.encodedCharacters.allowEncodedHash=false"
      - "--entrypoints.websecure.http.encodedCharacters.allowEncodedSemicolon=false"
      - "--entrypoints.websecure.http.encodeQuerySemicolons=true"
      # disable api
      - "--api.dashboard=false"
      - "--api.insecure=false"
      # disable telemetry
      - "--global.checkNewVersion=false"
      - "--global.sendAnonymousUsage=false"
      # logging
      - "--log.level=ERROR"
      - "--log.format=common"
      - "--log.filePath=/logs/error.txt"
      - "--log.maxAge=60"
      - "--accesslog=true"
      - "--accesslog.format=common"
      - "--accesslog.filePath=/logs/access.txt"
      - "--accesslog.addInternals=false"
      # do net put sensitive information in log files
      - "--accesslog.fields.headers.defaultMode=drop"
      - "--accesslog.fields.headers.names.User-Agent=keep"
      - "--accesslog.fields.headers.names.Authorization=drop"
      - "--accesslog.fields.headers.names.Cookie=drop"
      - "--accesslog.fields.headers.names.Set-Cookie=drop"
      - "--accesslog.fields.queryParameters.defaultMode=drop"
    networks: # segregate containers from each other and the internet
      - traefik-network-with-internet
      - socketproxynetwork
      - nginx_traefik-internal-network
    volumes:
      - ./logs/traefik:/logs:rw,noexec,nosuid,nodev
      - ./traefiksecurity.yaml:/etc/traefiksecurity.yaml:ro,noexec,nosuid,nodev
      - ./certs:/data:rw,noexec,nosuid,nodev
      # DO NOT EXPOSE SOCKET!!

  nginx:
    image: nginxinc/nginx-unprivileged:alpine-slim
    container_name: nginx
    # apply hardening baseline
    <<: *hardening
    depends_on:
      php:
        condition: service_started # TODO: better health check?
    user: "${NGINX_UID}:${NGINX_UID}"
    restart: unless-stopped
    environment:
      TZ: "${TZ}"
    #ports:
    # DO NOT EXPOSE. Served behind the reverse proxy
    labels:
      - "traefik.enable=true"
      - "traefik.docker.network=nginx_traefik-internal-network" # how traefik reaches this service
      - "traefik.http.routers.site1.entrypoints=websecure" # only allow https
      # limit allowed methods
      - "traefik.http.routers.site1.rule=(Host(`${HOSTNAME}`) && (Method(`GET`) || Method(`POST`) || Method(`HEAD`)))"
      - "traefik.http.routers.site1.tls=true"
      - "traefik.http.routers.site1.tls.certresolver=le"
      - "traefik.http.routers.site1.tls.options=strict@file" # apply strict tls settings (see below)
      - "traefik.http.routers.site1.priority=10"
      # explicity request certificate once # TODO: needed? Better way to do this? seems to work...
      - "traefik.http.routers.site1.tls.domains[0].main=${HOSTNAME}"
      - "traefik.http.routers.site1.tls.domains[0].sans=www.${HOSTNAME}"
      - "traefik.http.services.site1.loadbalancer.server.port=80"
      - "traefik.http.routers.site1.middlewares=security@file"  # apply strict security headers and rate limiting (see below)
      - "traefik.http.routers.site1.priority=11"
      # redirect www to prevent problems with CORS
      - "traefik.http.routers.site1www.rule=(Host(`www.${HOSTNAME}`) && (Method(`GET`) || Method(`POST`) || Method(`HEAD`)))"
      - "traefik.http.routers.site1www.entrypoints=websecure"
      - "traefik.http.routers.site1www.tls=true"
      - "traefik.http.routers.site1www.tls.options=strict@file"
      - "traefik.http.routers.site1www.middlewares=redirect-www-1"
      - "traefik.http.routers.site1www.priority=12"
      - "traefik.http.middlewares.redirect-www-1.redirectregex.regex=^https?://www\\.${HOSTNAMEWITHOUTTLD}\\.${TLD}(.*)"
      - "traefik.http.middlewares.redirect-www-1.redirectregex.replacement=https://${HOSTNAMEWITHOUTTLD}.${TLD}$${1}"
      - "traefik.http.middlewares.redirect-www-1.redirectregex.permanent=true"
    networks:
      - php_nginx-internal-network # nginx needs to talk with php in internal network
      - nginx_traefik-internal-network # nginx needs to talk with traefik in internal network
    volumes:
      - ./html:/var/www/html:ro,noexec,nosuid,nodev
      - ./logs:/var/log/nginx:rw,noexec,nosuid,nodev
      - ./nginx.conf:/etc/nginx/nginx.conf:ro,noexec,nosuid,nodev # nginx configured to proxy to the php container
    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,mode=700,uid=${NGINX_UID},gid=${NGINX_UID},size=500m,nr_inodes=400k

  php:
    image: php:8.5-fpm-alpine
    container_name: php
    # apply hardening baseline
    <<: *hardening
    user: "${PHP_UID}:${PHP_UID}"
    restart: unless-stopped
    environment:
      TZ: "${TZ}"
    #ports:
    #  DO NOT EXPOSE
    #network: "none" would be the strictest isolation
    networks:
      - php_nginx-internal-network # php only needs to talk with nginx
    volumes: # example bind mounts
      - ./database:/var/www/database:rw,noexec,nosuid,nodev
      - ./html:/var/www/html:ro,noexec,nosuid,nodev
      - ./logs/php:/var/www/phplogs:rw,noexec,nosuid,nodev
      - ./configs/php/999_lockdown.ini:/usr/local/etc/php/conf.d/999_lockdown.ini:ro,noexec,nosuid,nodev
      - ./configs/php/zzz_lockdown.conf:/usr/local/etc/php-fpm.d/zzz_lockdown.conf:ro,noexec,nosuid,nodev
    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,mode=700,uid=${PHP_UID},gid=${PHP_UID},size=500m,nr_inodes=400k

networks:
  traefik-network-with-internet:
    name: traefik-network-with-internet
    internal: false # traefik needs access to the outside. This is the only non-internal network!
    driver: bridge
    enable_ipv6: true
    driver_opts:
      com.docker.network.bridge.host_binding_ipv4: "127.0.0.1"
      com.docker.network.bridge.enable_icc: "false" # traefik is the only container in this network!
      com.docker.network.bridge.trusted_host_interfaces: "false"
  socketproxynetwork: # socket proxy <-> traefik
    name: socketproxynetwork
    internal: true # Important: do not give access to the outside
    driver: bridge
    enable_ipv6: false
    driver_opts:
      com.docker.network.bridge.host_binding_ipv4: "127.0.0.1"
      com.docker.network.bridge.enable_icc: "true" # socket proxy <-> traefik
      com.docker.network.bridge.trusted_host_interfaces: "false"
  php_nginx-internal-network: # nginx <-> php
    name: php_nginx-internal-network
    internal: true # Important: do not give access to the outside
    driver: bridge
    enable_ipv6: false
    driver_opts:
      com.docker.network.bridge.host_binding_ipv4: "127.0.0.1"
      com.docker.network.bridge.enable_icc: "true" # nginx <-> php
      com.docker.network.bridge.trusted_host_interfaces: "false"
  nginx_traefik-internal-network: # nginx <-> traefik
    name: nginx_traefik-internal-network
    internal: true # Important: do not give access to the outside
    driver: bridge
    enable_ipv6: false
    driver_opts:
      com.docker.network.bridge.host_binding_ipv4: "127.0.0.1"
      com.docker.network.bridge.enable_icc: "true" # nginx <-> traefik
      com.docker.network.bridge.trusted_host_interfaces: "false"
```
Define the variables from `compose.yaml` in `.env`:
```
#.env
TZ=Europe/Berlin
TRAEFIK_UID=7000
NGINX_UID=5001
PHP_UID=6001
HOSTNAME=domain.com
HOSTNAMEWITHOUTTLD=domain
TLD=com
ACME_EMAIL=certs@domain.com
```
Set up strict policies for TLS and security headers in `traefiksecurity.yaml`:
```yaml
http:
  middlewares:

    # define strict security headers
    securityheaders:
      headers:
        contentTypeNosniff: true
        frameDeny: true
        customFrameOptionsValue: "DENY"

        customResponseHeaders:
          # remove headers that might leak information
          Server: ""
          X-Powered-By: ""
          X-CF-Powered-By: ""
          X-AspNet-Version: ""
          X-AspNetMvc-Version: ""
          X-Runtime: ""
          X-XSS-Protection: "1; mode=block"
          # important: block all external request attempts via the browser enforcing strict CORS
          X-Permitted-Cross-Domain-Policies: "none"
          Cross-Origin-Embedder-Policy: "require-corp"
          Cross-Origin-Resource-Policy: "same-origin"
          Cross-Origin-Opener-Policy: "same-origin"

        # important: prevent XSS
        contentSecurityPolicy: >-
          default-src 'none';
          script-src 'self';
          script-src-attr 'none';
          style-src 'self';
          img-src 'self' data:;
          font-src 'self';
          object-src 'none';
          base-uri 'none';
          frame-ancestors 'none';
          frame-src 'none';
          connect-src 'self';
          form-action 'self';
          media-src 'self';
          child-src 'self';
          worker-src 'self';
          manifest-src 'none';
          block-all-mixed-content;
          require-trusted-types-for 'script';
          trusted-types 'none';
          upgrade-insecure-requests;

        permissionsPolicy: >-
          geolocation=(),
          microphone=(),
          camera=(),
          accelerometer=(),
          autoplay=(),
          bluetooth=(),
          browsing-topics=(),
          cross-origin-isolated=(),
          display-capture=(),
          encrypted-media=(),
          fullscreen=(self),
          gamepad=(),
          gyroscope=(),
          keyboard-map=(),
          hid=(),
          idle-detection=(),
          local-fonts=(),
          magnetometer=(),
          midi=(),
          payment=(),
          picture-in-picture=(),
          publickey-credentials-get=(),
          screen-wake-lock=(),
          sync-xhr=(self),
          serial=(),
          unload=(),
          usb=(),
          web-share=(self),
          interest-cohort=(),
          xr-spatial-tracking=(),
          clipboard-read=(),
          clipboard-write=()

        referrerPolicy: no-referrer
        stsSeconds: 63072000
        stsIncludeSubdomains: true
        stsPreload: true

    # Apply ratelimiting. Could be made stricter
    # for e.g. authentication portal
    baseratelimit:
      rateLimit:
        average: 500
        period: 60s
        burst: 200
        sourceCriterion:
          ipStrategy:
            depth: 1
            ipv6Subnet: 64

    vaseinflight:
      inFlightReq:
        amount: 100

    # Uncomment if needed:
    # localonly:
    #   ipAllowList:
    #     sourceRange:
    #       - "192.168.178.0/24"
    #       - "10.0.0.0/8"

    # strict url sanitization
    baseencodedchars:
      encodedCharacters:
        allowEncodedSlash: false
        allowEncodedBackSlash: false
        allowEncodedPercent: false
        allowEncodedQuestionMark: false
        allowEncodedHash: false

    # combine the middlewares above into a security chain
    # to be used by the exposed services via traefik
    security:
      chain:
        middlewares:
          - securityheaders
          - baseratelimit
          - baseinflight
          - baseencodedchars

tls:
  options:
    strict:
      minVersion: VersionTLS13 # only allow latest TLS version
      curvePreferences: # only allow strong curves
        - X25519MLKEM768
        - SecP384r1MLKEM1024
        #- SecP256r1MLKEM768
        #- MLKEM1024
        - X25519
        - CurveP521
        #- CurveP384
        #- CurveP256
      cipherSuites: # only allow strong ciphers
        - TLS_AES_256_GCM_SHA384
        - TLS_CHACHA20_POLY1305_SHA256
        #- TLS_AES_128_GCM_SHA256
      sniStrict: true # check the host name during TLS handshake
      alpnProtocols:
        - h2
        - http/1.1
        - acme-tls/1
      disableSessionTickets: false
```

## Secrets

By default, secrets management in docker is quite limited. The following sample setup showcases the different secret mechanisms:
```yaml
# compose.yaml
services:
  myservice:
    build:
      context: .
      secrets:
        # make secret available to RUN command from file on host:
        - myBuildSecretFile
        # make secret available to RUN command from environment variable on host:
        - myBuildSecretEnv
    environment:
       # use secrets in the container by reading from provided files
       MYSQL_PASSWORD_FILE: "/run/secrets/myFile"
       ADMIN_PASSWORD_FILE: "/run/secrets/myFileFromEnv"
       # There is no way with default secrets to directly create environment variables. Either
       # run a command inside the container like 'env=$(cat file.txt)' or use .env
       NOT_TECHNICALLY_A_SECRET: "${FROM_DOT_ENV}"
    secrets:
      - source: mySecretFile
        target: /run/secrets/myFile # essentially read only bind bound into the container
      - source: mySecretEnv
        target: /run/secrets/myFileFromEnv # passing the secret as env from host to file in container
        uid: "103" # uid, gid and mode only available when passing as environment
        gid: "103" # WARNING: It looks like no matter which values are set for uid and gid,
        mode: 0o400 # they are always the same as the user running in the container. Only "mode" is honored
secrets:
  mySecretFile: # secret 1: file from the host bind-mounted into the container
    file: ./myFile
  mySecretEnv: # secret 2: environment variable from the host created as a file in the container
    environment: "MYSECRET"
  myBuildSecretFile:
    file: ./myBuildFile # secret 3: provide a file as secret during build (as file or env)
  myBuildSecretEnv:
    environment: "MYBUILDSECRET" # secret 4: provide an environment variable from the host to build (as file or env)
```

```Dockerfile
# Dockerfile
FROM alpine:latest

RUN adduser -D -u 103 app
USER 103

# pass secret as file from the host to a file for RUN
RUN --mount=type=secret,id=myBuildSecretFile,target="/somedir/myBuildSecretFile.txt",uid=103,gid=103,mode=0400 \
    cat /somedir/myBuildSecretFile.txt

# pass secret as file from the host as an environment variable to RUN
RUN --mount=type=secret,id=myBuildSecretFile,env="myBuildSecretFileAsEnv" \
    echo "$myBuildSecretFileAsEnv" && test "$myBuildSecretFileAsEnv" = "secretdef"

# pass secret from env on the host to a file for RUN
RUN --mount=type=secret,id=myBuildSecretEnv,target="/somedir/myBuildSecretEnv.txt",uid=103,gid=103,mode=0400 \
    cat /somedir/myBuildSecretEnv.txt

# pass secret from env on the host to env in RUN
RUN --mount=type=secret,id=myBuildSecretEnv,env="myBuildSecretEnvEnv" \
    echo "$myBuildSecretEnvEnv" && test "$myBuildSecretEnvEnv" = "secret456"
```

Prepare the secrets on the Host:
```bash
export MYSECRET="secret123"
export MYBUILDSECRET="secret456"
echo -n "secretabc" > myFile
echo -n "secretdef" > myBuildFile
echo -n '"FROM_DOT_ENV="not technically a secret"' > .env
```

Test:
```bash
docker compose build --progress=plain --no-cache

docker compose run --rm myservice cat /run/secrets/myFile
docker compose run --rm myservice cat /run/secrets/myFileFromEnv
docker compose run --rm myservice sh -c 'echo "$MYSQL_PASSWORD_FILE"'
docker compose run --rm myservice sh -c 'echo "$ADMIN_PASSWORD_FILE"'
docker compose run --rm myservice sh -c 'echo "$NOT_TECHNICALLY_A_SECRET"'
```

- TODO: Look at hashicorp vault
- TODO: OpenBao
- TODO: Sops
- TODO: Look at swarm-specific secrets (but swarm is not compatible with rootless docker)

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
```bash
sudo dockerd --validate --config-file /etc/docker/daemon.json
sudo systemctl restart docker
sudo docker info | grep -i userns # output should be "userns" now
```
Enable starting docker on boot:
```bash
sudo systemctl enable docker.service
sudo systemctl enable containerd.service
```
## TODO

### Unnamend and named volumes

### pids-limit / mem_limit / cgroup / ulimits (nproc, nofile soft/hard) / shm_size / cpus

- Compatibility with rootless docker

### Healthcheck

### Encrypted docker volumes

### Auth provider

- Authentik
- authelia
- pocketid+oauth2-proxy?
- keycloak

### Docker build

- locked-down user, multi-stage build, `RUN --network=none --mount=type=tmpfs --security=sandbox ...`,  `--mount=type=secret` (so that info does not end up in image)

### WAF between traefik and nginx

- [https://www.bunkerweb.io/](https://www.bunkerweb.io/)
- [modsecurity-crs-docker](https://github.com/coreruleset/modsecurity-crs-docker)
- [https://github.com/chaitin/SafeLine](https://github.com/chaitin/SafeLine)

### Encrypted volumes

- LUKS volume mounted by systemd with key in TPM

### Apparmor / seccomp

### Docker + crowsec / fail2ban

- [https://plugins.traefik.io/plugins/6335346ca4caa9ddeffda116/crowdsec-bouncer-traefik-plugin](https://plugins.traefik.io/plugins/6335346ca4caa9ddeffda116/crowdsec-bouncer-traefik-plugin)
- [https://github.com/fail2ban/fail2ban/wiki/Fail2Ban-and-Docker](https://github.com/fail2ban/fail2ban/wiki/Fail2Ban-and-Docker)
- [https://github.com/fail2ban/fail2ban/discussions/3534](https://github.com/fail2ban/fail2ban/discussions/3534)

### ssh-based socket proxy

### ipvlans / macvlans

### Docker swarm

- not available with rootless docker
- swarm-specific secrets management
- swarm-specific deploy limits (e.g. deploy: limits: pids: 1000)
- Create replace default ingress network with encrypted overlay network: `sudo docker network create -d overlay --opt encrypted --attachable network`
- Internal overlay networks
