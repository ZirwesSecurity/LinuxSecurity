[Back to main document](README.md)

# Securing SSH

- [Install the SSH server daemon (sshd)](#install-the-ssh-server-daemon-sshd)
- [Initial steps on the server](#initial-steps-on-the-server)
- [Generating SSH keys on the client](#generating-ssh-keys-on-the-client)
- [Harden the server configuration](#harden-the-server-configuration)
- [Additing restrictions to public keys](#additing-restrictions-to-public-keys)
- [Additional client convenience settings](#additional-client-convenience-settings)
- [2FA with TOTP](#2fa-with-totp)
  - [Option 1: google-authenticator TOTP](#option-1-google-authenticator-totp)
  - [Option 2: pam_oath TOTP](#option-2-pam_oath-totp)
  - [Generating TOTP codes](#generating-totp-codes)
  - [Enabling TOTP on the server (either pam_path or google_authenticator)](#enabling-totp-on-the-server-either-pam_path-or-google_authenticator)
- [2FA with HOTP](#2fa-with-hotp)
  - [Option 1: google-authenticator HOTP](#option-1-google-authenticator-hotp)
  - [Option 2: pam_oath HOTP](#option-2-pam_oath-hotp)
- [Protecting private keys with hardware tokens (yubikey)](#protecting-private-keys-with-hardware-tokens-yubikey)
- [Client key and host key signing](#client-key-and-host-key-signing)
  - [Client key signing](#client-key-signing)
  - [Host key signing](#host-key-signing)
- [Restricting access by time of day](#restricting-access-by-time-of-day)
- [Monitor logins](#monitor-logins)
- [Creating a locked-down user, e.g. for tunneling/SFTP](#creating-a-locked-down-user-for-eg-for-tunnelingsftp)
- [Restricting SFTP](#restricting-sftp)
- [Tunneling with SSH](#tunneling-with-ssh)

This section covers different ways of securing SSH server authentication. Everything was tested with Ubuntu 24.04 LTS and a fairly recent version of OpenSSH packaged with Ubuntu (>= 9.2).
However, most aspects discussed here are operating system agnostic. The focus lies on configuring SSH (including some additional PAM modules).
Therefore, not discussed are further protections with firewalls, fail2ban, automatic security updates, (D)DoS and IP spoofing protection...
Also, focus lies on securing authentication, not user actions on the server after authentication, e.g. by enabling SElinux, restricting local permissions, kernel hardening, forwarding or tunnelling...
This guide is work-in-progress. Do not blindly trust random security guides from the internet. If you find any mistakes or have suggestions, open an issue.
Also, basic experience with SSH is recommended before reading on.

The terms *server* and *host* are used interchangeably to refer to the machine running sshd, which may be a local home server, a VPS, ...
*Client* is used to refer to a machine connecting to the *server*. All commands are presented assuming a sudo user.

## Install the SSH server daemon (sshd)

On the **server**, check if an ssh server is already running:
```bash
systemctl status sshd
```
**Before continuing: make sure all passwords for all users (including root) on the server are very strong and unique (see [Appendix: Generating Passwords](Appendix.md#generating-passwords))**.
This alone is sufficient in most cases to secure the SSH server. Everything else in the following sections is just a bonus.

To install, type
```bash
sudo apt install openssh-server -y
# on other distros, the following might be sshd instead of ssh
sudo systemctl enable --now ssh.service 
```
Check if the daemon is running and all services are enabled:
```bash
systemctl status sshd
```
At this point, you should be able to connect to the server from the **client**:
```bash
ssh myServerUser@ip # or myServerUser@hostname
```
The server IP can be found by running
```bash
hostname -I
```
on the server.

## Initial steps on the server

On the **server**, disable weak presets:
```bash
cd $HOME
sudo awk '$5 >= 4094' /etc/ssh/moduli > moduli.safe
sudo rm -f /etc/ssh/moduli
sudo cp moduli.safe /etc/ssh/moduli
rm -f moduli.safe
```

Re-generate server (host) keys, allowing only strong key types (note that these cannot be password protected).
This should also be performed when setting up a new server to reset the defaults:
```bash
sudo rm -f /etc/ssh/ssh_host_*
sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" -C "ed25519 host key"
sudo ssh-keygen -t rsa-sha2-512 -b 4096 -f /etc/ssh/ssh_host_rsa_key -N "" -C "rsa host key"
```
Note that `-t rsa-sha2-512` in this context is equivalent to `-t rsa`. However, when signing keys, `rsa-sha2-512` must be used.
Therefore, if in doubt, always use `rsa-sha2-512` or only use `ed25519` keys. Newer versions of OpenSSH will use `ed25519` by default.
While 4096 bit RSA keys have a nominally larger security margin than `ed25519` keys, they are quite large and slowly becoming outdated and may be the first to be broken by quantum computers.
Always avoid `ecdsa` (questionable history and additional problems when used for signatures).
While using default values on newer OpenSSH versions is perfectly fine, in this guide, all options are specified explicitly for learning purposes.
```bash
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
```
Reboot the server
```bash
reboot
```
In [Harden the server configuration](#harden-the-server-configuration), password-based authentication will be switched to public key authentication. This has several advantages:
- Connection attempts without an authorized public key are immediately rejected, so bruteforce protection becomes less necessary
- Passwords can be weak, private/public keys, at least ed25519 and rsa4096, are always strong
- Passwords are sent to the server in plain text. This is only a problem if the server is compromised or a man-in-the-middle attack is performed successfully. Private keys are never sent to the server
- Private key files can be additionally protected with a password (which is a form of 2FA)
- However, registering the same public key on many different servers and public services (like github) can lead to identity leaks, so use a different private/public key pair for each server/service.

## Generating SSH keys on the client

On the **client**, generate a key pair. First use the `genpw` command to generate a new password to protect the private key (See [Appendix: Generating Passwords](Appendix.md#generating-passwords)).
```bash
mykeyname="myClientSSHKey"
ssh-keygen -a 128 -o -t ed25519 -E sha256 -Z chacha20-poly1305@openssh.com -f ~/.ssh/${mykeyname} -C "$mykeyname"
chmod 600 ~/.ssh/${mykeyname}.pub
```
- `-a`: cost factor (for bcrypt), default is 16.
- `-o`: use new openssh format with better encryption/key derivation (in newer versions of OpenSSH, this option is silently ignored).
- `-t`: key type (default in newer versions is `ed25519`). Other key types, like `rsa`, allow to specify the length of the key with `-b`. Instead of `-t ed25519` may also use `-t rsa-sha2-512 -b 4096`. Avoid other options.
- `-E`: specifies the fingerprint hash (default is sha256)
- `-Z`: encryption cipher. Instead of `-Z chacha20-poly1305@openssh.com` may also use `-Z aes256-gcm@openssh.com` or `aes256-ctr` (default: `aes256-ctr`)
- `-f`: Path to and name of the private key file. The public key has the same name with a `.pub` extension.
- `-C`: add an arbitrary comment. Note that this comment might be visible on the server when copying the public key.
On newer OpenSSH versions, the defaults are OK, so that a key could be generated simply with `ssh-keygen-f ~/.ssh/${mykeyname} -C "$mykeyname"`.
If in doubt, use the verbose syntax above.
Note that omitting `-C` includes the user name and hostname of the client in the public key by default, which will be sent to the server.
See also [Appendix: Generating keys](Appendix.md#generating-keys) for convience functions set in `.bashrc`.

Copy the public key to the server (if you want, you can first add the server's public key from `/etc/ssh/ssh_host_ed25519_key.pub` to the client's `~/.ssh/known_hosts`
or do this implicitly by accepting the fingerprint on the first connection if you trust your setup):
```bash
 # if the port was changed (see the next section),
 # then "-p xxx" must be added before myServerUser@ip
ssh-copy-id -i ~/.ssh/${mykeyname}.pub myServerUser@ip
```
This will add the public key to the server's `/home/myServerUser/.ssh/authorized_keys` (this also checks that the public key was specified.
If the private key was specified, the public key is sent instead). See also [TODO:section_atuthorized_keys]

## Harden the server configuration

Back on the **server**, consider generating a new user with a random username (see [Appendix: Generating passwords](Appendix.md#generating-passwords)) used for login if you like security by obscurity.
The user on the server will be referred to as `myServerUser`.
Authentication can be restricted to certain user groups. For example, add the server user to a new group:
```bash
sudo addgroup mysshgroup
sudo adduser $USER mysshgroup
```
Clean up the current sshd_config (it might make sense to create a backup copy of `/etc/ssh/sshd_config` now!):
```bash
sudo touch /etc/ssh/sshd_config
# remove commented lines to make the file more readable
sudo sed -i '/^#/d' /etc/ssh/sshd_config
sudo sed -i 's/^HostKey/#HostKey/g' /etc/ssh/sshd_config
```
If entries are defined more than once in `/etc/ssh/sshd_config`, the first entry is used (unless these are options that are specifically allowed to be defined multiple times).
**IMPORTANT**: Before making changes to `sshd_config`, go through the following settings and read the description (see also https://man.openbsd.org/sshd_config).
Otherwise, you might lock yourself out of the server. Also, the following will require a fairly recent version of OpenSSH (>= 9.2).
Add the following **to the beginning** of `/etc/ssh/sshd_config`:
```bash
# ============= Hardened settings ===============
HostKey /etc/ssh/ssh_host_ed25519_key # only allow ed25519 and rsa host keys
HostKey /etc/ssh/ssh_host_rsa_key

RequiredRSASize 4096 # will reject public key authentication with RSA keys < 4096 bits

# Allow login only for specified users and/or groups
AllowUsers myServerUser@192.168.*.* # IMPORTANT: this restricts login to the local network.
                                    # Could also replace with specific IP or simply write "AllowUsers myServerUser"
                                    # without specifying an IP to allow login from anywhere to that user.
                                    # This is a space-separated list, i.e. AllowUsers user1 user2@ip user3
AllowGroups mysshgroup # to login to a user, the user must be part of this group (space-separated list)
# Order of checking is DenyUsers, AllowUsers, DenyGroups, finally AllowGroups
# There is also the option 'ListenAddress' to restrict listening to specific IPs and ports.
# This makes sense if the server can be reached through multiple IPs/has multiple network devices/subnets.

# Disable all authentication methods except public key authentication. When using a "Match" block (see below),
# then "PubkeyAuthentication" could be set to "no" and "AuthenticationMethods" to "none". In this way, logging in
# is not possible at all for any cases not caught by "Match" blocks. The disadvantage is that the server then asks
# for a password for any login not covered by a "Match" block (which can never be fulfilled) instead of directly blocking
# the login attempt as in the case of only allowing public key authentication. Could also be set globally to 
# "AuthenticationMethods publickey,password" together with "PasswordAuthentication yes". In this case, first public key
# authentication is done and if successful, the password is required as well.
AuthenticationMethods publickey # syntax is: method1,method2 method3,method4; this means:
                                # (first pass method1 then method2) OR (first pass method3 and then method4) to log in
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
GSSAPIAuthentication no
ChallengeResponseAuthentication no
HostbasedAuthentication no
KerberosAuthentication no

# Optionally, add a "Match" block (should always be put at the very end of sshd_config because the indentations used below
# are ignored and simply everything after the "Match" line and before the next "Match" line is considered part of the
# Match block!). This example overwrites the settings above for any login for the specified user
# from the specified IP. Any number of "match" conditions can be put into the first line (here: user name and IP)
# Example use case: default settings above only allow public key for the user from any IP, but if the connection comes from
# the local network, also optionally allow password.
#Match User myServerUser Address 192.168.0.* # matches the specified user and any IP with 192.168.0.*
#    AuthenticationMethods publickey password # for example: this allows public key OR password authentication
                                              # when connecting from the local network 
#    PasswordAuthentication yes
#    PubkeyAuthentication yes

# Change ssh port (default: 22). This is security through obscurity and may cause problems with firewalls and SELinux
# and has to be kept in mind when configuring e.g. ufw or fail2ban
# Ports < 1024 can only be listened on by root processes, so a malicious non-root process cannot intercept packages
# Higher port numbers >> 1024, e.g. 48263, may be missed by (bad) automated scanning tools
Port 573 # If in doubt, don't set this

# Explicitly specify which algorithms are allowed. This disables weak ciphers/algorithms. Note that the actual ciphers used
# in the connection are chosen by the client (the first algorithm requested by the client that is also available on the
# server will be used). Advantage: prevents malicous downgrade attacks
# Disadvantage: if new algorithms become available, they have to be added here manually. If algorithms become deprecated,
# they have to be removed manually. Instead, could use the "-" syntax to explicitly disable unsafe algorithms and "+" to
# add algorithms to the default list. Commented out algorihtms below are not available in OpenSSH 9.2 but in later versions
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr
MACs hmac-sha2-512-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com # not supported (yet) curve25519-frodokem1344-sha512@ssh.com
HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512
FingerprintHash sha256
CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512
PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,ssh-ed25519,sk-ssh-ed25519@openssh.com
KexAlgorithms curve25519-sha256@libssh.org,curve25519-sha256,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,sntrup761x25519-sha512@openssh.com,gss-curve25519-sha256-,gss-group16-sha512- # not supported (yet) sntrup761x25519-sha512,mlkem768x25519-sha256,curve25519-frodokem1344-sha512@ssh.com

# The following should always be set
PermitEmptyPasswords no # default no
PermitRootLogin no # Never allow login as root. Could be overwritten to "yes" in a Match block
                   # e.g. when loggin in from local network
Protocol 2 # default 2
HostbasedAuthentication no # default: no
IgnoreRhosts yes # default: yes
#UsePrivilegeSeparation yes # default: yes (only available in newer versions)

# if only public key authentication is used, the following settings are not too important
LoginGraceTime 20 # time allowed for establishing a connection. default 120 s. 0 means no time limit.
                  # Might need to be adjusted depending of how involved the login requirements are
                  # (see 2FA section below for a more involved example)
MaxAuthTries 6    # default: 6. Closes connection after this many authentication attempts.
                  # Once the number of failures reaches half this value,
                  # additional failures are logged. TODO: interaction with fail2ban and PAM?
MaxSessions 10    # per user concurrently active sessions on the server, default is 10
MaxStartups 10    # There can be 10 connections which are currently between "starting the connection"
                  # and "before being authenticated". default: 10:30:100.

# Do not keep unused connections alive
ClientAliveInterval 30  # every 30s,  check if connection is still alive; default 0 (infinite).
                         # Prevents zombie connections/sessions that might be taken over at some point.
ClientAliveCountMax 300  # After 300 unanswered client alive messages, the connection is terminated (default=3)
ChannelTimeout *=60m     # after 60 minutes of inactivity on any channel, flag connection as unused (0=infinite)
UnusedConnectionTimeout 5m # once flagged as unused, terminate the session after 5 minutes
TCPKeepAlive no          # default yes

# do not allow any kind of forwarding/tunneling:
DisableForwarding yes # Disables all forwarding features.
# Optionally, disable/enable all options manually as follows:
AllowAgentForwarding no
AllowStreamLocalForwarding no
AllowTcpForwarding no
GatewayPorts no
PermitListen none
PermitOpen no
PermitTunnel no
X11Forwarding no

# Miscellaneous
PrintMotd no
Banner no
VersionAddendum none

# ============= /Hardened settings ===============
```
Replace the placeholder user name with the actual user name:
```bash
sudo sed -i "s/myServerUser/${USER}/g" /etc/ssh/sshd_config
```
```bash
sudo chmod og-rwx /etc/ssh/sshd_config
```
Test, if `sshd_config` can be parsed without errors:
```bash
sudo sshd -t
```
If a firewall like ufw is running, make sure to open the new port (if changed) and after reboot, close the old port (default 22). See [ufw](#ufw).

The delay between authentication attempts can be increased. This makes sense if you plan to allow password logins.
If only `publickey` is configured, or you plan to activatee TOTP 2FA (see sections below), skip the following line.
Otherwise In `/etc/pam.d/sshd`, add the following line to the very top of the file:
```
auth optional pam_faildelay.so delay=5000000 # 5 s. Might need to adjust LoginGraceTime (see above)
```

If no errors occurred from `sshd -t`, restart the ssh server:
```bash
sudo systemctl restart --now ssh.service # might be sshd.service on other distros
reboot # if the port was changed, reboot is required
```
The list of available algorithms supported by the current OpenSSH version can be found by running
```bash
ssh -Q cipher-auth
ssh -Q cipher
ssh -Q mac
ssh -Q kex
ssh -Q kex-gss
ssh -Q key
ssh -Q key-ca-sign
ssh -Q key-cert
ssh -Q key-plain
ssh -Q key-sig
ssh -Q protocol-version # should always be 2
```

To test if the settings were applied correctly, try to connect with a wrong cipher:
```bash
ssh -c aes256-cbc -o IdentitiesOnly=yes -i ~/.ssh/myClientSSHKey myServerUser@IP -p 573 # this should fail
```

To revoke access for a client or user, delete the respective public key from the server's `authorized_keys`, add the user to the `DenyUsers` list,
remove the user from the `mysshgroup` and/or lock the user account (see [Reset Password](#reset-passwords), TODO) if password authentication is enabled.

**NOTE**: On some distros (RHEL?), in `/etc/sysconfig/sshd` the entry `CRYPTO_POLICY=` has to be uncommented first. On Ubuntu, it works without touching this.

In newer verions of OpenSSH (>=9.8), there is built-in bruteforce protection. This works by applying penalties to specific sources.
A "source" is a single IP address (default), or a range of IP addresses grouped together. To use this, add the following entries to /etc/ssh/sshd_config
```bash
PerSourceNetBlockSize 32:128 # default 32:128. This defines what a "source" is. The first entry is for ipv4, the second
                             # for ipv6. This is the number of bits used to specify the IP ranges for that source.
                             # Since an ipv4 address is 32 bits, the default counts any IP address as its own source.
                             # Using 24:128 instead, would count any IPv4 address with the same three leading blocks
                             # together, e.g. 123.456.789.0 and 123.456.789.255 would count as the same source.
                             # With this, whole networks can be blocked. This option is available in earlier versions
                             # of OpenSSH.
PerSourceMaxStartups 3       # default: none; While MaxStartups counts all current Startups, this sets a maximum for
                             # any individual source. This option is available in earlier versions of OpenSSH.

# "Penalties" are specified for different actions. The following shows the default settings for OpenSSH >= 9.8.
# For example, an authentication failure adds a 5 second penalty for the respective source. Disconnecting without
# trying to authenticate adds a 1 second penalty, causing a crash a 90 s penalty and so. The server will remember a
# maximum of "max-sources" penalties for IPv4 and IPv6 sources. If more sources generate penalties, either additional
# connections are allowed ("permissive") or no other connections are allowed ("deny-all"). Penalties for every source
# reduce by one second every second. For example, if authentication fails, the penality is at 5 seconds. If another
# authentication is attempted after 2 seconds and fails, the penality will be at 5-2+5 = 8 seconds. Once the penalties
# have build up above the value specified by "min", the penalty is applied. So if there are three failed login attempts
# within one second, the penality reaches 15 seconds, which is the minimum for actually applying the penality, and the
# source is blocked from logging in for 15 seconds. The maximum block time is specified by "max". For more restrictive
# settings, one could set "authfail:5h min:24h max:1000h": after 5 failed login attempts within at most one hour,
# login is blocked for 24 hours.
PerSourcePenalties authfail:5 noauth:1 crash:90 grace-exceeded:20 max:600 min:15 max-sources4:65536 max-sources6:65536 refuseconnection:10 overflow:permissive overflow6:permissive

PerSourcePenaltyExemptList 192.168.0.0/16 # specify sources which are exempt from penalties,
                                          # e.g. connections from the local network

# There is also the new keyword "RefuseConnection". This can be used in a Match block as shown below. If someone
# tries to authenticate as the user "someusername", the connection is immediately refused and the penalty specified
# by "refuseconnection" is applied.
#Match User someusername
#   RefuseConnection

```

## Additing restrictions to public keys

When adding a public key to a user's `authorized_keys`, additional restrictions can be added  as a comma-separated list for use with this specific key. For example:
```
restrict,port-forwarding,permitopen="192.168.178.46:3002",from="192.168.178.26/32",command="/bin/false" ssh-ed25519 AAAA....
```
The `restrict` keyword disables many ssh features and is equivalent to specifying the following options
* `no-agend-forwarding`: do not forward ssh agents
* `no-port-forwarding`: do not allow any port forwarding
* `no-pty`: do not allow an interactive shell
* `no-X11-forwarding`: do not allow X11 forwarding
* `no-user-rc`: do not allow loading the user's `.rc` file
The `restrict` keyword can be used together with manually allowing some features, e.g.
```
restrict,port-forwarding,pty ssh-ed25519 AAAA....
```
This disables all features listed above, but allows port forwarding and interactive shells.

The `from` keyword allows use of the public key only from specified hostnames, e.g.
```
restrict,from="127.0.0.1,192.168.178.26/24,example.com" ssh-ed25519 AAAA....
```
This allows using the public key from the IP 127.0.0.1. the local subnet 192.168.178.* and the hostname example.com.

The `command` forces the execution of the specified command after authentication and disallows any other commands. See TODO:sftp and TODO:tunnel_section for more information.

Other options are:
* `environment=""`: sets environt variables for the session
* `expiry-time="timespec"`: Specifies when use of this public key expires
* `permitopen="...",permitlisten="...",tunnel="n"`: See section TODO:tunel for more information
* `verify-required`: When using a hardware key, require PIN or biometrics verification (see also section TODO:yubikey)

TODO: order of precedence with sshd_config


To revoke access of this specific key later on, simply delete the corresponding line from `/home/myServerUser/.ssh/authorized_keys` on the server and restart the ssh(d) service.
For an alternative revocation mechanism, see the last part in [Client key signing](#client-key-signing). Also, it is discoured to use the `cert-authority` flag in `authorized_keys` (see [Client key signing](#client-key-signing)).
For more information about the authorized_keys format, see https://manpages.debian.org/unstable/openssh-server/authorized_keys.5.en.html.

## Additional client convenience settings

On the **client**, add the following to `~/.ssh/config` (might not exist yet):
```bash
# General settings - check if they are already defined and overwrite if necessary
HashKnownHosts yes
Protocol 2 # default: "2,1"
UseRoaming no # deprecated
FingerprintHash sha256
ObscureKeystrokeTiming yes # default yes
IdentitiesOnly yes # only send specified public keys to the server
ForwardAgent no # do not send the ssh agent to the server. Default: no
IdentitiesOnly yes # do not offer all keys when conneting but rely on a specific one
StrictHostKeyChecking yes # do not allow connecting to an unknown server
                          # default "ask"
TCPKeepAlive no
VersionAddendum none

# specific settings for the server. Host blocks should be placed at the end of the file (similar to "Match" above)
Host myserver # set a name for the new connection. Can be any name
    Hostname 192.168.178.36 # Replace with the IP or hostname of the server
    User myServerUser # name of the user to log in to on the server
    IdentityFile ~/.ssh/myClientSSHKey # whatever the filename was during key generation
    Port 573 # same as the one specified on the server
    ForwardX11 no # default: no. Unless X connections should be used
    PreferredAuthentications publickey # match this with the server
    AddKeysToAgent yes # convenience: will remember the private key in the ssh-agent so
                       # passwords have to be typed only once per session
    CheckHostIP yes # default: yes
    # prevent downgrade attacks. Set same as settings on the server
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr
    MACs hmac-sha2-512-etm@openssh.com
    HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,rsa-sha2-512-cert-v01@openssh.com,ssh-ed25519 # not supported (yet) curve25519-frodokem1344-sha512@ssh.com
    CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512
    HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512
    KexAlgorithms curve25519-sha256@libssh.org,curve25519-sha256,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,sntrup761x25519-sha512@openssh.com,gss-curve25519-sha256-,gss-group16-sha512- # not supported (yet) sntrup761x25519-sha512,mlkem768x25519-sha256,curve25519-frodokem1344-sha512@ssh.com
    PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,ssh-ed25519,sk-ssh-ed25519@openssh.com
    FingerprintHash sha256
    RequiredRSASize 4096
```
When setting `StrictHostKeyChecking yes`, connections to unknown servers will be blocked. One way to circument this is to manually get the server's host key by running
```bash
ssh-keyscan -p 22 -O hashalg=sha256 -H -t ed25519 [IP or hostname]
```
where
  - `-p` is the port of the server (default: 22)
  - `-H` specifies that the hostname should be hashed
  - `-O hashalg` specifies the hashing algorithm
  - `-t` specifies which host key to fetch (could also be `rsa`, `ed25519-sk` ...). Can be omitted to get the default host key.
Add the host key to `~/.ssh/known_hosts` to allow connections to this server.

Now, connection is possible with, e.g.
```bash
ssh myserver
scp somefile myserver:~
ssh-copy-id -f -i ~/newKey.pub myserver # use -f if public key authentication is required and another 
                                        # key is already registered as specified by "IdentityFile" in .ssh/config
```
For convenience, if using the `AddKeysToAgent yes` option, the following line can be added to the **client**'s `~/.bashrc` to start the ssh agent on login:
```bash
eval `ssh-agent -s`
ssh-add -t 1h # store keys for one hour
```
Note that this will create a new ssh-agent process everytime you login/invoke ~/.bashrc. For a system with many (concurrent, long-lived) connections,
a different method of starting the ssh-agent might be more appropriate.

The settings in `~/.ssh/config` above could instead be set in the global `/etc/ssh/ssh_config` to apply the settings to all users on the client machine.
Note that the local config overwrites the global one.

SSH has a quirk when using multiple active public keys: by default, all identities (public keys) are sent to the server to see which one can be used for authorization.
However, by default, five failed authorization attempts lead to the connection being revoked. Also, public key files meant for another server might contain information
that should not be sent to the server in the current authentication request. Therefore, `IdentityFile` and `IdentitiesOnly yes` are set in the user's `config` file.
Instead, this can be done manually on the command line, e.g. (ignore the `-p` options if the server port was not changed)
```bash
ssh -p 573 -o IdentitiesOnly=yes -i ~/.ssh/myServerKey myserveruser@IP
scp -P 573 -o IdentitiesOnly=yes -i ~/.ssh/myServerKey file_to_be_copied myserveruser@IP:~ # note the capital P for port
ssh-copy-id -f -i ~/.ssh/newKey.pub -o IdentityFile=~/myServerKey -p 573 myserveruser@IP
```
For `ssh-copy-id`, if a new public key should be copied to the server while a previous key is already authorized and public key authentication is required,
use `-f` and both `-i` and `-o IdentityFile`.
If signed public keys are used (see [Client key signing](#client-key-signing)), also add `-o CertificateFile=myServerKey-cert.pub`.

## 2FA with TOTP

If login is restricted to `publickey` only, a second factor is technically already provided by the passphrase protecting the private key.
Nonetheless, more requirements can be added for authentication, like TOTP codes. Note that the methods described here are not limited to protecting ssh.
Any PAM login method, e.g. the graphical gdm-password login, can be extended by TOTP in the same way as described here for ssh.

**NOTE**: It can make sense to increase the `LoginGraceTime` in `/etc/ssh/sshd_config` to e.g. `120` when dealing with TOTP/multiple required login methods.

### Option 1: google-authenticator TOTP

The first option implementing TOTP 2FA is using google-authenticator. For an alternative, see [Option 2: pam_oath TOTP](#option-2-pam_oath-totp). On the **server**, run
```bash
sudo apt install libpam-google-authenticator -y
```
Generate a 512bit shared secret/seed (ideally, generate on the server or a machine other than the client so that this is truly a second factor,
and use it on a machine other than the client, e.g. client=laptop used to connect via ssh, TOTP codes generated on phone).
See the end of this section on how to get the secret more easily to a phone authenticator app using a qr code (e.g. ente auth, bitwarden TOTP, aegis, KeepassXC, ...):
```bash
# "~" refers to the home directory of the user for whom TOTP should be activated
LC_ALL=C head -c 64 /dev/urandom | base32 -w 0 | sed 's/=//g' | sed -e '$a\' > ~/.google_secret
cat << EOF >> ~/.google_secret
" RATE_LIMIT 3 30
" WINDOW_SIZE 3
" STEP_SIZE 30
" DISALLOW_REUSE
" TOTP_AUTH
EOF
chmod 0600 ~/.google_secret
```
- `RATE_LIMIT`: limit login attempts to 3 per 30 seconds
- `WINDOW_SIZE`: 3 means allow current TOTP as well as 1 TOTP code in the past and 1 in the future
- `STEP_SIZE`: generate a new TOTP code every 30 seconds
- `DISALLOW_REUSE`: allow only one login attempt per TOTP code
- `TOTP_AUTH`: TOTP mode (instead of HOTP)

To show the secret in base32 (e.g. for use in a 2FA phone app), run
```bash
head -n 1 ~/.google_secret
```

Pros of `google-authenticator`:
- window extends forward and backward, making login more resistant to time skew between client and server
- built-in rate limiting
- can block TOTP codes for one-time use
- supports 512 bits secrets (even though this has to be done manually instead of using the official tool, as described above)
- additional option for emergency codes (not used here)
Cons:
- supports only 6 TOTP digits
- uses HMAC-SHA1 (instead of HMAC-SHA256)
- made by google (but it is open-source)

Continue with section [Generating TOTP codes](#generating-totp-codes).

### Option 2: pam_oath TOTP

To use `pam_oath`, install the PAM module for enabling TOTPs (alternatively, there is `google-authenticator`, see [Option 1: google-authenticator TOTP](#option-1-google-authenticator-totp)).
On the **server**, run
```bash
sudo apt install libpam-oath -y
```
Generate a 512bit shared secret/seed (ideally, generate on the server or a machine other than the client so that this is truly a second factor,
and use it on a machine other than the client, e.g. client=laptop used to connect via ssh, TOTP codes generated on phone). See the end of this section on how to get the
secret more easily to a phone authenticator app using a qr code (e.g. ente auth, bitwarden TOTP, aegis, KeepassXC, ...):
```bash
LC_ALL=C tr -dc 'a-f0-9' </dev/urandom | head -c64 > ~/secret.txt
```
Create the file containing the TOTP info:
```bash
echo -n "HOTP/T60/8 $USER - " | cat - ~/secret.txt > ~/TOTP
```
`T60` means that a TOTP code is generated every 60 seconds (maximum 60). This makes it a bit more resistant to time skew between the client and the server,
since, in contrast to `google-authenticator`, only current and future TOTP codes can be allowed for authentication. `/8` means that the TOTP code is 8 digits long (can be 6,7,8).
The next argument is the name of the user where this TOTP setup is applied to. The `-` means that no additional PIN is required (only for use with other external authentication services).
Copy the file to the correct location:
```bash
sudo rm -f /etc/users.oath
sudo cp ~/TOTP /etc/users.oath
sudo chown root /etc/users.oath
sudo chmod 0600 /etc/users.oath
rm -f ~/TOTP
```
To show the secret in base32 (e.g. for use in a 2FA app), run
```bash
cat ~/secret.txt | xxd -r -p | base32 -w 0 | sed 's/=//g'
```

Pros of `pam_oath`:
- supports up to 8 TOTP digits
- supports 512 bits secrets
Cons:
- window extends only forward (into the future), so time skew into the past can become a problem (see below)
- no built-in rate limiting (but can of course be combined with e.g. fail2ban)
- cannot block TOTP codes for one-time use
- uses HMAC-SHA1 (instead of HMAC-SHA256)

Continue with section [Generating TOTP codes](#generating-totp-codes).

### Generating TOTP codes

First, have a reliable method of generating TOTP codes. One option is using `oathtool`:
```bash
sudo apt install oathtool -y
```
To generate a code after following the `google-authenticator` guide above:
```bash
oathtool --totp -v -s 30s -d 6 -b $( head -n 1 ~/.google_secret )
```
Or after following the pam_oath guide above:
```bash
oathtool --totp -v -s 60s -d 8 $( cat ~/secret.txt )
```
where `-d` specified the number of digits and `60s` is the TOTP time interval. The last argument is the shared secret in hex format from `secret.txt`.
`-b` allows passing the secret in base32. The `-v` option prints additional information, like the shared secret in both base32 and hex.
Optionally, adding `-w 10` prints the current TOTP code and the next 10.

An easy way of generating a QR code for scanning with a TOTP phone app is
```bash
sudo apt install qrencode -y
```
If you followed the `google-authenticator` guide, run
```bash
qrencode -t ANSIUTF8 otpauth://totp/$USER@myserver.com?secret=$( head -n 1 ~/.google_secret )\&digits=6\&issuer=myserver.com\&period=30
```
If you followed the `pam_oath` guide, run
```bash
qrencode -t ANSIUTF8 otpauth://totp/$USER@myserver.com?secret=$( cat ~/secret.txt | xxd -r -p | base32 -w 0 | sed 's/=//g' )\&digits=8\&issuer=myserver.com\&period=60
```

### Enabling TOTP on the server (either pam_path or google_authenticator)

Now that TOTP codes can be reliably generated, active them. In the following, a placeholder `TOTPENTRY` is used.
If you followed the google-authenticator guide, replace this with
```
auth requisite pam_google_authenticator.so secret=~/.google_secret grace_period=30
```
The last argument, grace_period, is optional, and specifies the amount of time in seconds between requesting a verification code and entering it.
The "~" path will be replaced with the home of the user attempted to log into. If you followed the `pam_oath` guide, replace `TOTPENTRY` with
```
auth optional pam_faildelay.so delay=10000000 # optional: limit to 1 try every 10 seconds. google-authenticator brings its own rate limiting
auth requisite pam_oath.so usersfile=/etc/users.oath window=1 digits=8 # window means how many additional TOTP codes from the future are accepted
```
In `/etc/pam.d/sshd`, decide which authentication mode to use. The first non-comment line should be:
```
@include common-auth
```
Demand either only the TOTP code, TOTP code and then password, or password and then TOTP code. These are realized with
```
# Only TOTP code
TOTPENTRY # replace this with the lines written above
#@include common-auth # comment this
```
```
# First TOTP code, then password
TOTPENTRY # replace this with the lines written above
#@include common-auth # do not comment this
```
```
# First password, then TOTP code
@include common-auth
TOTPENTRY # replace this with the lines written above. For pam_oath and if using the faildelay,
          # should move the faildelay line before @include common-auth
```
In theory, both TOTP modules can be used at the same time:
```
# First password TOTP from google-authenticator, then TOTP from pam_oath, then user account password
auth requisite pam_google_authenticator.so secret=~/.google_secret grace_period=30
auth requisite pam_oath.so usersfile=/etc/users.oath window=1 digits=8
@include common-auth
```
Instead of `requisite`, could use `required` instead. With `required`, a wrong TOTP code will cause authentication to fail, but not immediately:
If e.g. TOTP+password is configured, and the entered TOTP token is wrong, the user is still asked for the password, but even a correct password will then lead to authentication failure).
So in theory, `required` might be slightly more secure because an attacker does not know why and which authentication failed, but in practice, it can be annoying.
For `pam_oath`, `window=1` means that the current TOTP code will be accepted and the next one. `window=0` only accepts the current one and `windows=10` the current one and the next 10.
The idea is to make the login more resistant to time skew between the client and server. Unfortunately, `window` only accounts for **next** TOTP codes, not previous ones.
The `google-authenticator` module's window, `specified in ~/.google_secret`, allows to allow both future and past codes.

In `/etc/ssh/sshd_config`, make sure to set the following:
```bash
AuthenticationMethods keyboard-interactive # this will ask for the TOTP and/or password as configured above
PasswordAuthentication no # with the above configuration, this can never be used. Instead, use KbdInteractiveAuthentication
KbdInteractiveAuthentication yes # on older versions, instead set ChallengeResponseAuthentication yes
usePAM yes
```
In this way, once sshd is restarted, the user will be asked for the TOTP/password combination as configured above.
Note that `PasswordAuthentication` is now never valid and can always be set to `no`.

Instead, authentication requirements could be set to:
```bash
# this will ask for the (TOTP and/or password) as configured above OR use publickey authentication
AuthenticationMethods publickey keyboard-interactive 
PasswordAuthentication no
PubkeyAuthentication yes
KbdInteractiveAuthentication yes # on older versions, instead set ChallengeResponseAuthentication yes
usePAM yes
```
Note: there is also `keyboard-interactive:pam` instead of `keyboard-interactive`, but at least on Ubuntu, this does not seem to be necessary.

To demand public key AND TOTP (with password, if configured), set
```bash
# this will first check the public/private key and then ask for the (TOTP and/or password) as configured above
AuthenticationMethods publickey,keyboard-interactive
PasswordAuthentication no
PubkeyAuthentication yes
KbdInteractiveAuthentication yes # on older versions, instead set ChallengeResponseAuthentication yes
usePAM yes
```
It probably makes sense to require `publickey` first. In that case, any authentication attempt without the correct public/private key is immediately dropped.

On the client, in `~/.ssh/config` adjust (or remove) `PreferredAuthentications` if necessary.

Finally clean up and restart the ssh service:
```bash
rm -f ~/secret.txt
sudo systemctl restart --now ssh.service
```

## 2FA with HOTP

Instead of TOTP codes, HOTP codes could used instead. Instead of generating a time-based code, this generate code based on a counter.
Every login attempt increases the counter by one. Server and client keep track of the counter and allow for a certain amount of difference in the counter.
Again, `google-authenticator` or `pam_oath` can be used for this. The general methods follow the description of TOTPs from the previous section.
Therefore, it is recommended to go through the previous section first. In general, TOTP is easier to use due to the availability of many phone apps,
and does not have the problem of the counter getting out of sync between client and server.

### Option 1: google-authenticator HOTP

Install the google-authenticator pam module as described above. When generating the configuration file, choose the HOTP setup:
```bash
LC_ALL=C head -c 64 /dev/urandom | base32 -w 0 | sed 's/=//g' | sed -e '$a\' > ~/.google_secret
cat << EOF >> ~/.google_secret
" RATE_LIMIT 3 30
" WINDOW_SIZE 10
" HOTP_COUNTER 1
EOF
chmod 0600 ~/.google_secret
```
The entries mean:
- `RATE_LIMIT`: limit login attempts to 3 per 30 seconds
- `WINDOW_SIZE`: 10 means allow HOTP code based on the current counter and the next 10
- `HOTP_COUNTER`: the first counter value is 1
```
auth requisite pam_google_authenticator.so secret=~/.google_secret grace_period=30 no_increment_hotp
@include common-auth
```

The `no_increment_hotp` means that the counter is not increased for failed login attempts (this option is not available for the `pam_oath` module).
This can protect against locking out the user when an attacker tries to bruteforce logins.
In `/etc/ssh/sshd_config` set the entries for `keyboard-interactive`, `KbdInteractiveAuthentication yes` and `usePAM yes` as described above.
To generate a HOTP code, run
```bash
oathtool --hotp -c 1 -w 10 -d 6 -b $( head -n 1 ~/.google_secret )
```
where `-c` specified the current counter value.

### Option 2: pam_oath HOTP

Install the `pam_oath` PAM module as described above. When generating the configuration file, choose the HOTP setup:
```bash
LC_ALL=C tr -dc 'a-f0-9' </dev/urandom | head -c64 > ~/secret.txt
echo -n "HOTP $USER - " | cat - ~/secret.txt > ~/HOTP
sudo rm -f /etc/users.oath
sudo cp ~/HOTP /etc/users.oath
sudo chown root /etc/users.oath
sudo chmod 0600 /etc/users.oath
rm -f ~/HOTP
```
In `/etc/pam.d/sshd`, add
```
auth optional pam_faildelay.so delay=10000000 # optional: limit to 1 try every 10 seconds. google-authenticator brings its own rate limiting
auth requisite pam_oath.so usersfile=/etc/users.oath window=10 digits=8 # window means how many additional HOTP codes from higher counter values are accepted
@include common-auth
```
In `/etc/ssh/sshd_config` set the entries for `keyboard-interactive`, `KbdInteractiveAuthentication yes` and `usePAM yes` as described above.
To generate a HOTP code, run
```bash
oathtool --hotp -v -c 1 -w 10 -d 8 $( cat ~/secret.txt )
```
where `-c` specifies the current counter value.

## Protecting private keys with hardware tokens (yubikey)

Arguably the strongest form of 2FA is using a hardware token. They provide the only type of phishing protection since an ssh key can only be authenticated by having
physical access to the hardware token (and optionally the token's PIN/biometrics). The general idea is that the private key used for ssh authentication consists of two parts:
one part is the internal master key of the hardware token. This key is unique to the specific hardware token. It cannot be extracted from the hardware token and never
leaves the device. Instead, the hardware token itself uses the internal key to generate signatures. The second part is a key handle
(called credential ID for non-resident keys, but here *key handle* is used for both types for simplicity) which is generated and thus unique for every ssh private/public key
(e.g. for every server where a key is registered). The first part, the internal master key of the hardware device, can optionally be protected by a PIN
(or biometrics, depending on the type of the key). The second part, the key handle, can optionally be protected by an additional password
(just like any conventional ssh private key), although this only makes sense for non-resident key handles (see below).

There are two modes of these hardware token-protected FIDO keys: non-resident (non-discoverable) and resident (discoverable). In the first mode,
also known as FIDO U2F (often used without a PIN but in addition to a normal login password, i.e. as second factor), the key handle is stored on the client machine.
In the second mode, also known as FIDO2 (normally requires a PIN and thus can be used for passwordless authentication, using only the PIN and physical possession of the hardware token),
the key handle is stored on the hardware token itself.  The pros and cons are:
- Storing the key handle on the device (resident key) occupies a key slot (for example, yubikeys typically have 25 of these slots, newer keys have 100). These slots are also used when registering the key to login to websites (using FIDO2), so available space on the key is scarce.
- Storing the key handle on the device (resident key) increases the risk if the hardware token is stolen: the thief then has access to both parts (internal master key and key handle). Therefore, the hardware token should be protected, e.g. by an additional PIN or biometrics.
- Storing the key handle on the device (resident key) makes logging into an ssh server from a different client machine easier, since the key handle can be generated from the hardware token itself, without the need of copying the key handle file from the client machine where it was originally generated to the new client machine.
- Storing the key handle on the device (resident key) means that additional password protection of the key handle file does not increase security, as the key handle is available in the hardware token unencrypted (but protected by the PIN).
- If the new client machine is not trusted, using discoverable keys might make more sense, since the key handle will remain on the token and not be directly exposed to the client machine (only an intermediate key handle file). Note that for both resident and non-resident keys, the key handle itself is useless without the physical hardware token.
In general, for highest security, it is recommended to use non-discoverable keys (no key slots in the hardware token are used, key handles are not stored on the hardware token so that a thief must get physical access to the token **and** obtain the key handle file (ands its password) from the client machine), unless the machine used for login is not trusted (but then, you should probably not log into any service anyways).

Here, it is assumed that the hardware token is a yubikey. First, make sure a PIN (or biometrics, in the following, a PIN is assumed) is set for the yubikey. To set a PIN or configure the yubikey, first install the manager (this is only required on the client where the yubikey is physically connected to, not on the server where keys will later be used for authentication):
```bash
sudo snap install ykman # on Ubuntu, the apt package is an older version
```
If the yubikey is not found, try disconnecting and reconnecting it. In the following, depending on the OS/firmware/setup, it might be required to add `sudo` when interacting with the yubikey. To see a list of resident keys on the yubikey, run
```bash
ykman fido credentials list
```
To delete a slot, run 
```bash
ykman fido credentials delete xxxxxxxx
```
where `xxxxxxxx` is the credential ID of the slot shown by the `list` command. If you lost the PIN, or if you got a brand new yubikey, start by resetting the yubikey (***WARNING***: this will destroy all FIDO2 and U2F credentials by re-hashing the internal master key for FIDO use):
```bash
ykman fido reset # reset the PIN on the yubikey
```
To change (or set) the PIN, run
```bash
ykman fido access change-pin
```
Note that, in general, a PIN MUST be set and by default, the FIDO PIN is not set. Note also that the PIN is alphanumeric and can be up to 63 characters.
Minimum length is between 4 and 8 characters, depending on the yubikey model and firmware. If a PIN is entered incorrectly 3 times, the yubikey is blocked and must be physically
reconnected. After 8 incorrect PIN entries, the yubikey **must be reset** and all registered FIDO credentials become useless. This provides a strong form of bruteforce/hammer protection.
To see the remaining attempts and minimum PIN length, type `ykman fido info`. Also note that a yubikey can have three types of PINs (FIDO, PIV, gpg). Here, only the FIDO PIN is relevant.

If the yubikey also supports biometrics, a fingerprint can be added:
```bash
ykman fido fingerprints add "Left thumb"
```
Saved fingerprints are shown with `ykman fido fingerprints list` and can be deleted with `ykman fido fingerprints delete xxxx`.

Next, generate SSH keys using a hardware key. Note that ed25519 is only available on newer yubikeys. To generate a non-resident key (recommended), run (might need to add `sudo`):
```bash
ssh-keygen -a 128 -o -E sha256 -Z chacha20-poly1305@openssh.com -t ed25519-sk -O verify-required -f ~/.ssh/my-non-resident-key -C "my-non-resident-key"
```
The option `-O verify-required` is optional. If `verify-required` is used, the ssh-agent (at laest on Ubuntu) cannot be used.
This will generate two files, `my-non-resident-key` (the key handle file) and `my-non-resident-key.pub`, just as any normal private/public key pair.
If login with the key does not work, try disabling the ssh-agent (setting `IdentityAgent none` in the client's `ssh_config`) or not using the `verify-required` option.
For now, not using `verify-required` and instead protecting the key handle with a password seems to be the most practical approach.
If `sudo` was used, correct the ownership of the generated key files:
```bash
sudo chown $USER:$USER ~/.ssh/my-non-resident-key*
```
If for some reason you want to use a resident key (might need to add `sudo`), type
```bash
ssh-keygen -a 128 -o -E sha256 -Z chacha20-poly1305@openssh.com -t ed25519-sk -O resident -O application=ssh:my-resident-key -O verify-required -f ~/.ssh/my-resident-key -C "my-resident-key"
```
The arguments `-O verify-required` and `-O application=ssh:my-resident-key` are optional. The latter allows to name the key slot on the yubikey
(should be a unique name, otherwise slot is overwritten). Note that the name must begin with `ssh:`.

For both resident and non-resident keys, there is another option (`-O no-touch-required`) which should never be used due to compatibility (and security) issues.
Note that for resident keys, a password can be set when generating the key as well. However, this is not a strong security measure, since the key handle resides unencrypted on the yubikey
(see below).

As with any ssh key pair, copy the public key to the server:
```bash
# if the port was changed, then "-p xxx" must be added before myServerUser@ip
ssh-copy-id -o IdentitiesOnly=yes -i ~/.ssh/my-non-resident-key.pub myServerUser@ip
```
Then, login can be done with
```bash
ssh -o IdentitiesOnly=yes -i ~/.ssh/my-non-resident-key -p xxx myServerUser@ip
```
or in `~/.ssh/config` by configuring
```bash
Host myserver
    Hostname 192.168.123.456
    User myServerUser
    Port xxx
    IdentitiyFile ~/.ssh/my-non-resident-key.pub
    IdentitiesOnly yes
    AddKeysToAgent no # if verify-required is not used, might be changed to yes. See below for more info
    # ...
```
and running
```bash
ssh myserver
```
If `verify-required` was used for either non-resident or resident keys, I have to use `sudo ssh -i ~/.ssh/my-non-resident-key -p xxx myServerUser@IP`, otherwise the yubikey PIN is not
requested and authentication fails. Note that in this case, the settings from `/home/myServerUser/.ssh/config` are not applied and instead the one from root are used.

On the server, in `/etc/ssh/sshd_config`, further restrictions can be added:
```bash
PubkeyAuthOptions verify-required touch-required # requires both verification and touch
```
Note that this has no effect for "normal" private/public keys. This can also be applied to specific public keys by adding the option `verify-required` to `authorized_keys`
as the first entry in the line of the key that should be affected. To restrict login to solely hardware-token backed keys, change `PubkeyAcceptedAlgorithms` in `/etc/ssh/sshd_config` to
only accept `sk-`type algorithms. In this case, it is strongly recommended to register keys for more than one yubikey.

If resident keys are used, all resident public keys and key handles can be extracted from the yubikey by running
```bash
ssh-keygen -K
```
This will write all public key/key handles from all resident keys of the yubikey to the current directory. If multiple yubikeys are connected,
the one that is physically touched is chosen. In this way, carrying the yubikey to a new client machine allows for easy connection to the server by using the
extracted public key for login. Note that the key handles of resident keys are stored on the yubikey unencrypted. This means, if the resident key was originally
generated using a passphrase with `ssh-keygen`, the key handle stored on the hard disk of the client machine is encrypted with the chosen password. However, that key
handle file can then be deleted and a new one extracted with `ssh-keygen -K`, choosing a new password (or no password at all), which is then applied to all extracted
resident keys. However, to extract the resident key files, the FIDO PIN of the yubikey is required, adding a layer of protection.

In theory, it is possible to use the ssh-keyagent with yubikey-based keys. However, `verify-required` might break this. There are also reports of problems in general
when using the keyagent with hardware token keys. So if in doubt, set `AddKeysToAgent no` in `~/.ssh/config`. If you want to use the keyagent,
all **resident keys** can be added with
```bash
eval "$(ssh-agent -s)" # start the agent, omit if already running
ssh-add -K # add resident keys on the yubikey to the agend
ssh-add -l # show the keys currently in the agent
```

TODO: working with yubikeys and ssh might require adjustments for SELinux

The public keys used for the yubikey-based keys can also be signed, just as like normal public keys (see the next section).
Note that the signed public key is not stored on the yubikey. It can be additionally stored in a certificate slot of the yubikey.
However, this is not covered here and should not be necessary, especially for non-resident keys.

## Client key and host key signing

When using public key authentication, an intermediate certificate authority (CA) can be used to sign either the host (server) or client public key.
The basic idea is as follow:

**Client key signing**: Usually, a private/public key pair is generated on the client and add the client's public key to the server's `auhtorized_keys`.
When logging in, the server will check if the connecting client has access to the private key associated with any public key in `auhtorized_keys`.
When using client key signing, first a certificate authority is created (another private/public pair), ideally on a machine other than the client and server.
Then, the private key of that certificate authority is used to sign the public key of the client. The public key of the certificate authority (not that of the client!)
is copied to the server. Now, the server will authorize any connection which has a client public key signed by the certificate authority
(which can be checked with the certificate authority's public key on the server) as well as ownership of the private key associated with the signed client public key.
In this way, new client public keys do not have to be copied to the server anymore, but simply have to be signed by the certificate authority without making any changes on the server.

**Host key signing**: When a client connects to a server it has connected to before, it will check if the server's public key (or its fingerprint) is the same as
the one from the previous connection. If not, it will refuse the connection since it might be a man-in-the-middle attack (someone impersonating the real server).
The very first time a new connection to a server is made, OpenSSH will ask if the public key of the server should be trusted, and thus saved to `known_hosts`.
But how do you know if you are connecting to the correct server? Are you really checking the public key?
What if there was a server maintenance and the server's public key has changed for legitimate reasons? To solve this problem, yet another certificate authority
(a private/public key pair) on a machine other than the client and server can be created. This can be the same certificate authority as the one used above for client key signing,
or a completely new certificate authority solely used for host key signing. Instead of the client adding the server's public key to its `known_hosts`,
the client adds the public key of the certificate authority. The private key of the certificate authority is used to sign the public key of the server.
Now, when the client makes a connection to the server, the client doesn't care what the server's public key is, it only checks if the server's public was signed
by the certificate authority (and that the server has control of the associated private key), as validated with the certificate authority's public key known to the client.

In addition to the advantages mentioned above, further restrictions can be enforced when signing the keys, by baking these restrictions into the signature
(or rather the certificate). For example, we can limit the server's host key to a specific host name/ip (so the private/public key of the server cannot be copied to another server),
or the user's public key to limit logging into a specific user or set additional restrictions, e.g. force no X11 forwarding, connection from specific IPs or to specific users.
In this way, fine-grained and secure controls over the permissions of the connection can be achievied using the signed keys.
Signed keys can also be made valid for a certain time period, allowing easy key rotation (in contrast, a normal public/private key is indefinitely valid,
until the public key is manually removed, e.g. from the server's `authorized_keys`).

### Client key signing

Here, it is assumed that the client already has a private/public key pair (see [Generating SSH keys on the client](#generating-ssh-keys-on-the-client)). If the client's public key
was already added to the server's `authorized_keys`, delete the client's public key from that file (or simply create a new private/public key pair on the client).
The client's keys will be referred to as the client-publickey and client-privatekey for the remainder of this section.

Ideally on a machine other than the server and the client, here referred to as *client-certificate-authority machine*, generate a password to protect
the now to be generated client-certificate-authority's private key by using `genpw` (see [Appendix: Generate Passwords](Appendix.md#generating-passwords)), unless signing should
be part of an automated worksflow, and then proceed to generate the key pair:
```bash
sudo ssh-keygen -a 128 -o -t ed25519 -E sha256 -Z chacha20-poly1305@openssh.com -f /etc/client_ca -C "client-certificate-authority"
```
Alternatively, instead of `-t ed25519`, could also use `-t rsa-sha2-512 -b 4096`. Note that `sudo` is used to place the key to a location only root can access.
This is not mandatory, but good practice.

Copy the client-publickey from the client to the client-certificate-authority machine (note: when using scp, the port is specified with capital `-P`).
There, sign the client key with
```bash
sudo ssh-keygen -s /etc/client_ca -I "some identifier" -n myServerUser -V -1d:forever -z 1 -O no-X11-forwarding -O no-agent-forwarding -O no-port-forwarding -O source-address=192.168.0.0/16 myClientSSHKey.pub
```
The arguments are:
- `-I`: Arbitrary identifier. Must be provided and can be any string. Will be visible in the certificate for everyone.
- `-n`: A comma separated list of users that this public key will be allowed to log into. Omit to allow login as any user (optional)
- `-V`: Validity: specify the time the signed public key is valid. Here, `-1d:forever` means "from yesterday until forever". Could e.g. be `-1d:20110101`, meaning valid from one day ago to specific date. See the man page for more options.
- `-z`: A unique serial number (optional). Can be used for easy revocation later.
- `-O`: Add additional restrictions. E.g. do not allow X11 connections with this key or restrict login from a specific IP address (range) or users (optional)
The last argument is the file containing the user's public key.

This will create the signed client-publickey at the same location of the original one with name `myClientSSHKey-cert.pub` (adding the `-cert`).
Note that the `-t` option was omitted from `ssh-keygen`. Newer versions of OpenSSH will choose the strongest algorithm for signing by default.
If you want so specify this directly, add `-t ssh-ed25519` if the certificate-authority key is of type `ed25519` and add `-t rsa-sha2-512 -b 4096` if the certificate authority key
is of type `rsa`. Note that using `-t rsa-sha2-512` with `ssh-keygen` instead of `rsa` is never wrong. For generating keys, `rsa-sha2-512` will just silently fall back to `rsa`.
However, when it comes to signing, `-t rsa` must be avoided (used in older versions of ssh). Therefore, simply use `rsa-sha2-512` in any context where you need an RSA key or switch
to `ed25519`. To see the details of the signed key, run
```bash
ssh-keygen -Lf myClientSSHKey-cert.pub
```
Copy the client-certificate-authority's public key (`/etc/client_ca.pub` if the above steps were followed) from the client-certificate-authority machine
to the server (e.g. to the same location `/etc/client_ca.pub`) and set the permission
```bash
sudo chmod 600 etc/client_ca.pub
```
Add the following to the server's `/ssh/sshd_config`:
```bash
TrustedUserCAKeys /etc/client_ca.pub
```
This tells the server to trust any connections signed with any key belonging to a public key in that file. Restart the ssh server with
```bash
sudo systemctl restart --now ssh.service
```
Copy the signed client-publickey `myClientSSHKey-cert.pub` back to the client and place it in `~/.ssh/`. On the client, set the permission
```bash
chmod 600 ~/.ssh/myClientSSHKey-cert.pub
```
In the client's `~/.ssh/config`, in the section for the server (Host), set the lines
```bash
Host myserver
    # ...
    IdentityFile  ~/.ssh/myClientSSHKey
    CertificateFile ~/.ssh/myClientSSHKey-cert.pub
    # ...
```
Or specify this on the command line with `ssh -o IdentitiesOnly=yes -o CertificateFile=~/.ssh/myClientSSHKey-cert.pub -i ~/.ssh/myClientSSHKey  ...`.
The client can now authorize with its private/public keys, even though no entry in the server's `authorized_keys` for the original public key is present.

If access for all public keys signed with the client-certificate-authority should be revoked, on the server remove the entry of that certificate
authority in `/etc/client_ca.pub`. To revoke a specific signed client-publickey, first create an empty file for revoked keys (if not present already)
```bash
sudo ssh-keygen -k -f /etc/ssh/sshd_revoked_keys
```
Then, copy the user's public key (either the original one (`myClientSSHKey.pub`) or the signed certificate file (`myClientSSHKey-cert.pub`))
from the user-certificate-authority server to the server. On the server, type
```bash
ssh-keygen -k -u -f /etc/ssh/sshd_revoked_keys myClientSSHKey-cert.pub
```
The `-u` adds a key to the revoked key list.
Instead of providing the full public key, you can also provide the fingerprint or other options.
See the man page. On the server's `/etc/ssh/sshd_config`, make this file known by adding
```bash
RevokedKeys /etc/ssh/sshd_revoked_keys
```
and restart the ssh server
```bash
sudo systemctl restart --now ssh.service
```
In case you later need to remove all revoked keys (reset the revoked key list), delete the `/etc/ssh/sshd_revoked_keys` file and run `sudo ssh-keygen -k -f /etc/ssh/sshd_revoked_keys`
again to create an empty one. Note that this general revocation mechanism is not specific to signed public keys, but can be used in any context.
However, without user key signing, the specific public key can simply be deleted from `authorized_keys`.

### Host key signing

The procedure for host key signing is similar to client key signing, so it might make sense to go through that section first if you have not already.
Also note that the terms *server* and *host* are used interchangeably here.

First, on a machine separate from the client and server, here referred to as host-certificate-authority, generate a password to protect the now to be generated
host-certificate-authority private key using the `genpw` command (see [Appendix: Generating Passwords](Appendix.md#generating-passwords)) and generate the key pair with
```bash
sudo ssh-keygen -a 128 -o -t ed25519 -E sha256 -Z chacha20-poly1305@openssh.com -f /etc/host_ca -C "host-certificate-authority"
```
Alternatively, instead of `-t ed25519`, could also use `-t rsa-sha2-512 -b 4096`. Note that `sudo` is used to place the key to a location only root can access.
This is not mandatory, but good practice. Note also that in theory, the host and client certificate authority could be the same one.

Copy the public keys of the server (here assuming the main key is an ed25519 key and there is also a RSA key), located at `/etc/ssh/ssh_host_ed25519_key.pub`
and optionally `/etc/ssh/ssh_host_rsa_key.pub`, to the host-certificate-authority server. On the host-certificate-authority server, sign the server's public key(s):
```bash
sudo ssh-keygen -s /etc/host_ca -h -I "some identifier" -n 192.168.0.5 -V -1d:forever -z 1 /etc/ssh/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_rsa_key.pub
```
This will create the signed public keys (`ssh_host_ed25519_key-cert.pub` and optionally `ssh_host_rsa_key-cert.pub`) at the same location as the original server's public keys.
Note the parameter `-h` is always used for host key signing. `-n` is an optional argument and can be used to restrict validity to certain IP (ranges) or hostnames,
but is an optional argument. For a description of the other parameters, see [Client key signing](#client-key-signing) or the man page.

Copy the `*-cert.pub` files back to the server, e.g. to `/etc/ssh/` and set the permissions
```bash
sudo chmod 600 /etc/ssh/ssh_host_ed25519_key-cert.pub
sudo chmod 600 /etc/ssh/ssh_host_rsa_key-cert.pub # optionally
```
In the server's `/etc/ssh/sshd_config`, add the following lines(s):
```bash
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
HostCertificate /etc/ssh/ssh_host_rsa_key-cert.pub # if an RSA key is also available for the server
```
and restart the server
```bash
sudo systemctl restart --now ssh.service
```

On the client, if there is already a previous entry for the server in `~/.ssh/known_hosts`, remove it. Copy the host-certificate-authority's
public key `host_ca-cert.pub` to the client. There, add the following entry to the known_hosts file:
```bash
echo "@cert-authority 192.168.0.5 $(cat host_ca.pub)" >> ~/.ssh/known_hosts
```
Instead of a concrete server IP, the full qualified domain name can be used, or simply "*" to allow access to any server with a public key signed by
this certificate authority. Now, you can connect to the server without being asked if the fingerprint is valid.

If trust in the host-certificate-authority is lost, simply remove the respective entry from `~/.ssh/known_hosts` or change the `@cert-authority` at the beginning
of the line to `@revoked`. To revoke a specific host key, copy the server's public key (either the original(s) or the signed one(s)) into a file,
here called `~/.ssh/revoked_hosts` and set permissions
```bash
chmod 600 ~/.ssh/revoked_hosts
```
Then, in `~/.ssh/config` add the following line to the beginning of the file:
```bash
RevokedHostKeys ~/.ssh/revoked_hosts
```
These changes could instead be made in the global /etc/ssh/ssh_config on the client instead of the client's user's `~/.ssh/config` to revoke globally for all users
on the client machine. 

With the methods described so far, login can look like this (a yubikey ed25519 non-resident public key signed by a CA and PAM TOTP+password,
i.e. `AuthenticationMethods publickey,keyboard-interactive`)
- The user must have a public key signed by a CA on another machine trusted by the server.
- When connecting to the server, the user touches the physical yubikey.
- The user types the PIN of the yubikey and/or provides their biometrics for the yubikey.
- The user types the password used to decrypt the non-resident private key handle.
- The user types the TOTP obtained from a separate device (e.g. a phone).
- The user types the account password of the server user.

## Restricting access by time of day

Logins can be restricted by time of day. For this, open `/etc/pam.d/sshd` and before the line 
```
@include common-account
```
add the line
```
account required pam_time.so conffile=/etc/security/sshtime.conf
```
This also works if only `publickey` authentication is activated, but `usePAM` should be set to `yes` in `/etc/ssh/sshd_config`.
Create the file `/etc/security/sshtime.conf` and add the line
```
* ; * ; * ; Al1000-1800
```
This will allow login between 10am and 6pm (local server time) on all days. See `/etc/security/time.conf` for more information about these parameters.
The third parameter can be used to specify the user this applies to.

## Monitor logins

In order to get notifications on successful server logins, a simple system monitor can be employed. This has several advanatages over other approaches commonly recommended:
- Using `pam_exec`: This only works if ssh is configured to use PAM. Also, it is probably a good idea not to touch the PAM config files.
- Adding a hook to `bashrc` or `sshrc`: this could be circumvented.
- Manually monitoring a logfile: this is cumbersome to implement.
Therefore, a simple monitoring script can be used:
```python
cat <<EOF >>~/myMonitorScript.py
#!/bin/python3
from systemd import journal
import systemd
j = journal.Reader()
j.seek_tail()
j.get_previous()
while True:
    event = j.wait(-1)
    if event == systemd.journal.APPEND:
        content = ""
        for entry in j:
            idd = entry.get("SYSLOG_IDENTIFIER")
            if idd is not None and idd == "sshd":
                m = entry['MESSAGE']
                if m.startswith("Accepted"):
                    content += entry['SYSLOG_TIMESTAMP'] + m + "\n"
        if content:
            # HERE - add code to e.g. send an email notification
            print(content)
EOF
sudo cp ~/myMonitorScript.py /etc/myMonitorScript.py
sudo chown root:root /etc/myMonitorScript.py
sudo chmod 700 /etc/myMonitorScript.py
sudo rm -rf ~/myMonitorScript.py
```
This will do a configered action, e.g. send an email, whenever a successful login on the server occurs. Run this script on startup:
```bash
sudo crontab -e
```
and type
```bash
@reboot /etc/myMonitorScript.py
```
Use
```bash
sudo crontab -l
```
to see if the change was successful. Reboot the server
```bash
reboot
```

## Creating a locked-down user for, e.g. for tunneling/SFTP

## Restricting SFTP

## Tunneling with SSH

TODO

ssh -L 25:abc:25 def

Instead of ssh-agent forwarding (`ssh-agent -A`), which allows root on the jump server to use keys in the agent, use `ProxyJump`.
