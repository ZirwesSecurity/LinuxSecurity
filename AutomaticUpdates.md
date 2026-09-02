[Back to main document](README.md)

# Automated security updates

Keeping the system up-to-date is important to maintain security. One way is using `unattended-upgrades`.
Here, updates are configured to be check at 4am,
upgrades installed at 4:30 and reboot is performed (if necessary) at 5am. Tested with Ubuntu and Debian.
Additionally, a script to update docker contains daily is set up as well.

- [Installation and setup](#installation-and-setup)
- [Allow automated reboots (recommended)](#allow-automated-reboots-recommended)
- [Disable automated reboots (not recommended)](#disable-automated-reboots-not-recommended)
- [Setting up manual reboots (compatible with remote-reboot)](#setting-up-manual-reboots-compatible-with-remote-reboot)
- [Third-party repositories and docker](#third-party-repositories-and-docker)
- [Automatic updates for docker containers](#automatic-updates-for-docker-containers)

## Installation and setup

In general, first install all other packages required on the server before installing `unattended-upgrades` (see also [Third-party repositories and docker](#third-party-repositories-and-docker)). Then, install `unattended-upgrades`
```bash
sudo apt install unattended-upgrades update-notifier-common -y
sudo dpkg-reconfigure unattended-upgrades # choose "yes"
```
By default, security updates are checked once per day. To check if `unattended-upgrades` is running:
```bash
sudo systemctl status unattended-upgrades # should show "enabled" and "active (running)"
```
To see if activation is configured correctly, check `/etc/apt/apt.conf.d/20auto-upgrades` for the entries ("1" meaning that checks are performed every n days (once per day by default)):
```
APT::Periodic::Update-Package-Lists "1"
APT::Periodic::Unattended-Upgrade "1";
```
The types of updates are specified in `/etc/apt/apt.config.d/50unattended-upgrades`. By default, only stable security updates are enabled. To specify the time when updates are performed, run
```bash
sudo systemctl edit --full apt-daily.timer
```
and set the following two lines to run at 4am
```
OnCalendar=*-*-* 4:00
RandomizedDelaySec=5m
```
and then run
```bash
sudo systemctl edit --full apt-daily-upgrade.timer
```
and set
```
OnCalendar=*-*-* 4:30
RandomizedDelaySec=5m
```
To see the next triggered update times and check that the configuration was successful, run
```bash
systemctl status apt-daily.timer
systemctl status apt-daily-upgrade.timer
```

## Allow automated reboots (recommended)

If the machine is allowed to reboot the server if necessary after security updates, run
```bash
cat << EOF > ~/52unattended-upgrades-local
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-WithUsers "true";
Unattended-Upgrade::Remove-Unused-Dependencies "false";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot-Time "05:00";
EOF
sudo cp ~/52unattended-upgrades-local /etc/apt/apt.conf.d/52unattended-upgrades-local
sudo chmod 0644 /etc/apt/apt.conf.d/52unattended-upgrades-local
rm -f ~/52unattended-upgrades-local
```
The last line means that reboots happen at 5am (if required).

Unattended-upgrades can be invoked manually by running:
```bash
sudo unattended-upgrades # add "-v" for more infos
```
Rebooting is decided by checking the existence of the file `/var/run/reboot-required`. You can check by running
```bash
sudo touch /var/run/reboot-required
sudo unattended-upgrades -v
```
If reboots are permitted as shown above, it will print the next scheduled reboot time.

## Disable automated reboots (not recommended)

If the server should not restart automatically do the following:
```bash
cat << EOF > ~/52unattended-upgrades-local
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
Unattended-Upgrade::Remove-Unused-Dependencies "false";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
EOF
sudo cp ~/52unattended-upgrades-local /etc/apt/apt.conf.d/52unattended-upgrades-local
sudo chmod 0644 /etc/apt/apt.conf.d/52unattended-upgrades-local
rm -f ~/52unattended-upgrades-local
```

## Setting up manual reboots (compatible with remote-reboot)

If full disk encryption is used and automatic security reboots should be enabled: first, follow [Remotely working with a server with FDE](RemoteFDEserver.md). Then disable automatic reboots as in the previous section
```bash
cat << EOF > ~/52unattended-upgrades-local
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
Unattended-Upgrade::Remove-Unused-Dependencies "false";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
EOF
sudo cp ~/52unattended-upgrades-local /etc/apt/apt.conf.d/52unattended-upgrades-local
sudo chmod 0644 /etc/apt/apt.conf.d/52unattended-upgrades-local
rm -f ~/52unattended-upgrades-local
```
Create a script that checks if a reboot is required and if so, the remote-reboot is performed:
```bash
cat << EOF > ~/reboot_if_required.sh
#!/bin/bash

# could trigger unattended-upgrades manually here
#sudo unattended-upgrades
# or even run the following to do full upgrades
#apt update
#apt upgrade -y

#sleep 10m

if [[ -e /run/reboot-required || -e /var/run/reboot-required ]]; then
    sleep 5m
    /usr/local/bin/keyless-entry enable-once
    reboot
fi
EOF
sudo cp ~/reboot_if_required.sh /usr/local/bin/
sudo chown root:root /usr/local/bin/reboot_if_required.sh
sudo chmod 700 /usr/local/bin/reboot_if_required.sh
rm -f ~/reboot_if_required.sh
```
Then, setup a cronjob that will run this script every day at 5am:
```bash
sudo crontab -e
```
Add the following line to reboot at 5am
```
0 5 * * * /usr/local/bin/reboot_if_required.sh
```
To check if this was configured correctly, run
```bash
sudo crontab -l
```

## Third-party repositories and docker

When packages are installed via third-party repositories (e.g. docker), `unattended-upgrades` might not update these repositories as expected. Sometimes, installing `unattended-upgrades`
after the third-party repository will add them correctly to the list of repository update sources. Check this by looking at the repositories listed in `/etc/apt/apt.conf.d/50unattended-upgrades` under `Origins-Pattern` (Debian) or `Allowed-Origins` (ubuntu).
If the required repositories do not appear, add them manually. For example, to add docker, modify `/etc/apt/apt.conf.d/52unattended-upgrades-local` (created in the last sections) by adding the `Origins-Pattern` (Debian) or `Allowed-Origins` (ubuntu) section manually.
Start by copying the `Origins-Pattern` (Debian) or `Allowed-Origins` (ubuntu) section from `/etc/apt/apt.conf.d/50unattended-upgrades` to `/etc/apt/apt.conf.d/52unattended-upgrades-local`
The syntax depends on the OS. For Debian, `/etc/apt/apt.conf.d/52unattended-upgrades-local`, it might look like this:
```
Unattended-Upgrade::Automatic-Reboot "true";             // see the previous sections a
Unattended-Upgrade::Automatic-Reboot-WithUsers "true";   // about automatic reboots
Unattended-Upgrade::Remove-Unused-Dependencies "false";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot-Time "05:00";
Unattended-Upgrade::Origins-Pattern {
  "origin=Debian,codename=${distro_codename},label=Debian";                    // copied
  "origin=Debian,codename=${distro_codename},label=Debian-Security";           // from
  "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";  // /etc/apt/apt.conf.d/50unattended-upgrades
  "origin=Docker,site=download.docker.com";      // added so that docker can be updated as well
}
```
For Ubuntu:
```
Unattended-Upgrade::Automatic-Reboot "true";             // see the previous sections a
Unattended-Upgrade::Automatic-Reboot-WithUsers "true";   // about automatic reboots
Unattended-Upgrade::Remove-Unused-Dependencies "false";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot-Time "05:00";
Unattended-Upgrade::Allowed-Origins {
        "${distro_id}:${distro_codename}";                      // copied
        "${distro_id}:${distro_codename}-security";             // from
        "${distro_id}ESMApps:${distro_codename}-apps-security"; // original
        "${distro_id}ESM:${distro_codename}-infra-security";    // /etc/apt/apt.conf.d/50unattended-upgrades
        "Docker:${distro_codename}";      // added so that docker can be updated as well
};
```
Check that it worked:
```bash
sudo unattended-upgrade --dry-run --debug | grep -i docker
```

## Automatic updates for docker containers

Here, a rootless docker installation is assumed. Set up an update service as the user that should run the docker containers:
```bash
mkdir -p ~/.config/systemd/user # "user" is not the username. Keep it as "user"
```
Create the file `~/.config/systemd/user/docker-compose-update.service` with the following content
```
[Unit]
Description=Update Docker Compose images

[Service]
Type=oneshot
WorkingDirectory=%h/docker # path to where the compose.yaml file is located
ExecStart=/usr/bin/docker compose pull --include-deps
ExecStart=/usr/bin/docker compose up -d --remove-orphans
```
To make this more aggressive, change the last two lines to
```
ExecStart=/usr/bin/docker compose pull --include-deps --policy always
ExecStart=/usr/bin/docker compose up -d --remove-orphans --force-recreate --build
```
Then create the file `~/.config/systemd/user/docker-compose-update.timer` with the following content to update the containers daily at 5:30am:
```
[Unit]
Description=Update Docker Compose images

[Timer]
OnCalendar=*-*-* 05:30:00
Persistent=true

[Install]
WantedBy=timers.target
```
Start the service with
```bash
systemctl --user daemon-reload
systemctl --user enable --now docker-compose-update.timer
systemctl --user list-timers
```
To trigger an update manually, run
```bash
systemctl --user start docker-compose-update.service
```
To see the update log, run
```bash
journalctl --user -u docker-compose-update.service
```

TODO: unattended-upgrades can be configured to send an email if a security update fails

