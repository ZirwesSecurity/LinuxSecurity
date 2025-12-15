[Back to main document](README.md)

# Remotely working with a server with FDE

- [Method 1: Dropbear SSH in initramfs](#method-1-dropbear-ssh-in-initramfs)
- [Method 2: Temporary one-time key](#method-2-temporary-one-time-key)
- [Method 3: Using the TPM 2.0 chip to unlock the disk on boot](#method-3-using-the-tpm-20-chip-to-unlock-the-disk-on-boot)
- [TODO](#todo)

When working with a server with LUKS full disk encryption (FDE), (re)booting the server requires entering the password locally with a keyboard. To work remotely with a server like this, three approaches are presented. 
- The first uses dropbear ssh during the initramfs stage to enter the LUKS key remotely via ssh (but it can still be typed locally on a keyboard as well). The dropbear ssh server only runs during the initramfs stage, not after the boot into the actual OS.
- The second approach adds a temporary key to LUKS which is valid only for the next reboot and which is entered automatically. In this way, a reboot can be triggered without the need to enter a key. This is useful e.g. for automated security updates (unattended-upgrades). If the server is rebooted without explicitly adding the temporary key or the server is shut down (e.g. due to power failure), the key is still required.
- The third approach uses the TPM 2.0 chip to release the key automatically on boot. Should only be used together with secure boot. Of course, this means a TPM 2.0 module must be available.

All three methods do not interfere with secure boot and can be combined/used at the same time. The steps below have been tested with a fresh install of a server running Ubuntu 24.04 LTS or Debian 13, where the default install options were selected to encrypt the root:

Ubuntu 24.04 LTS server installation:
- Select "Ubuntu Server (minimized)"
- Select "Encrypt the LVM group with LUKS"

Debian 13 server
- Select "Guided - use entire disk and set up encrypted LVM" (in the non-graphical installer)

## Method 1: Dropbear SSH in initramfs

Install the light-weight dropbear ssh server for initramfs (TODO: busybox required?):
```
sudo apt install -y dropbear-initramfs busybox
```
On a different device, generate a keypair for the dropbear ssh server, e.g. an ed25519 key with OpenSSH:
```
ssh-keygen -a 128 -o -t ed25519 -E sha256 -Z chacha20-poly1305@openssh.com -f ~/.ssh/dropbear
```
Add the public key from `~/.ssh/dropbear.pub` (`AAAA...`) to
```
sudo vim /etc/dropbear/initramfs/authorized_keys
```
with the following restrictions
```
no-port-forwarding,no-agent-forwarding,no-X11-forwarding,command="cryptroot-unlock" ssh-ed25519 AAAA...
```
Adjust file permissions:
```
sudo chmod 600 /etc/dropbear/initramfs/authorized_keys
```
Configure dropbear in
```
sudo vim /etc/dropbear/initramfs/dropbear.conf
```
Modify `DROPBEAR_OPTIONS` to the following settings:
```bash
DROPBEAR_OPTIONS="-I 600 -m -j -k -p [192.168.178.15]:573 -s -T 5 -c cryptroot-unlock"
```
The IP can be omitted
```bash
DROPBEAR_OPTIONS="-I 600 -m -j -k -p 573 -s -T 5 -c cryptroot-unlock"
```
but specifying the IP (if known) makes sure the server is exposed only to a single interface (e.g. only the local network). The options are:
- `-I idle_timeout` Disconnect the session if no traffic is transmitted or received for idle_timeout seconds.
- `-m` Don't display the message of the day on login. 
- `-j` Disable local port forwarding. 
- `-k` Disable remote port forwarding. 
- `-p [address:]port` Listen on specified address and TCP port. If just a port is given, listen on all addresses (default 22 if none specified). 
- `-s` Disable password logins. 
- `-T max_authentication_attempts` Set the number of authentication attempts allowed per connection. If unspecified the default is 10.
- `-c command` Force running the specified command and nothing else after login.

Configure the network in the initramfs phase. It is recommended to specify the interface that should be used (can be found by running `ip a`):
```
sudo vim /etc/initramfs-tools/initramfs.conf
```
Comment the line
```bash
#DEVICE=
```
To configure a static IP, add the line
```bash
IP=192.168.178.16::192.168.178.1:255.255.255.0::enp0s8
#<desired ip>:<ignored>:<gateway>:<subnet>:<ignored>:<interface>
```
or to use DHCP, add
```
IP=:::::enp0s8:dhcp
```
where `enp0s8` is the desired interface in this example. Using DHCP of course does not guarantee a deterministic IP.

Optional: regenerate host keys:
```bash
sudo rm /etc/dropbear/initramfs/dropbear_*_host_key*
sudo ssh-keygen -t ed25519 -f ~/dropbear_ed25519_host_key -N ""
sudo ssh-keygen -t rsa -b 4096 -f ~/dropbear_rsa_host_key -N ""
sudo dropbearconvert openssh dropbear ~/dropbear_ed25519_host_key /etc/dropbear/initramfs/dropbear_ed25519_host_key
sudo dropbearconvert openssh dropbear ~/dropbear_rsa_host_key /etc/dropbear/initramfs/dropbear_rsa_host_key
sudo cp dropbear_rsa_host_key.pub /etc/dropbear/initramfs/
sudo cp dropbear_ed25519_host_key.pub /etc/dropbear/initramfs/
sudo rm ~/dropbear_ed25519_host_key*
sudo rm ~/dropbear_rsa_host_key*
```
Dropbear SSH uses a different private key format (hence the `dropbearconvert`) but the public key format is compatible with OpenSSH.

Build the initramfs image
```
sudo update-initramfs -u -k all
```
Reboot the server
```
sudo reboot
```
Now the key for decrypting the disk can be entered manually via local keyboard, or by connecting to the dropbear server
```bash
ssh -p 573 -o "IdentitiesOnly=yes" -i ~/.ssh/dropbear root@192.168.178.16
```
where `-p 573` is the selected port.

## Method 2: Temporary one-time key

Install the following script (might require packages `sudo apt install cryptsetup-bin cryptsetup-initramfs`, but these should already be installed). When asked, provide the password for disk decryption:
```bash
cd $HOME
wget https://raw.githubusercontent.com/jikamens/keyless-entry/refs/heads/main/keyless-entry
sudo cp keyless-entry /usr/local/bin/keyless-entry
rm -f keyless-entry
sudo chmod +x /usr/local/bin/keyless-entry
sudo /usr/local/bin/keyless-entry configure # only run once when installing
```
The idea is to add an additional key temporarily to LUKS before a reboot, and then revoke the key immediately after the reboot. To add the temporary key, run
```bash
sudo /usr/local/bin/keyless-entry enable-once # takes some time
```
To see the new temporary, key, run
```bash
sudo cryptsetup luksDump /dev/sda3 # replace sda3 with the encrypted drive on your system
```
This will show three keys: original, keyless-entry configured master key, temporary key. To see the drives, run `lsblk`.

Now, when running
```
sudo reboot
```
the server will reboot without requiring a key (this reboot will take longer than a normal reboot but will not require entering a key). After the reboot, running again
```bash
sudo cryptsetup luksDump /dev/sda3 # replace sda3 with the encrypted drive on your system
```
will now show two keys (the temporary key has been removed) and thus rebooting will require a manual password for disk decryption if `keyless-entry enable-once` is not run again.

For convenience, add the following to the server's `~/.bashrc`:
```bash
cat << EOF >> ~/.bashrc
alias remote-reboot='sudo /usr/local/bin/keyless-entry enable-once && sudo reboot'
EOF
source ~/.bashrc
```
Now, when running `remote-reboot`, the server will reboot with one-time automatic disk decryption. Can e.g. be combined with `unattended-upgrades` to trigger reboots after security updates without the need to enter a key.

## Method 3: Using the TPM 2.0 chip to unlock the disk on boot

Make sure secure boot is enabled:
```
sudo mokutil --sb-state
```
Install required tools:
```
sudo apt install clevis clevis-tpm2 clevis-luks clevis-initramfs initramfs-tools
```
Check if a TPM 2.0 module is available:
```
sudo tpm2_getcap properties-fixed
```
More information can be seen with
```
sudo tpm2_eventlog --eventlog-version=2 /sys/kernel/security/tpm0/binary_bios_measurements
```
Bind the LUKS key to the TPM chip (this will generate a new random key with the same number of bits as the master key and seal it using the TPM:
```bash
sudo clevis luks bind -d /dev/sda3 tpm2 '{"hash":"sha256","key":"ecc","pcr_bank":"sha256","pcr_ids":"1,7"}'
```
where `sda3` is the name displayed by `lsblk` as the parent of the TYPE `crypt` disk. One could add more PCR IDs to make releasing the key more restrictive (1 is for hardware change and 7 for secure boot), but it may break on updates (e.g. 0 changes on firmware update, 4 changes on boot loader update but protects against boot loader downgrade, adding 9 will protect if initramfs is rebuilt, 14 for shim). See also https://man.archlinux.org/man/systemd-cryptenroll.1#TPM2_PCRs_and_policies). (TODO: which pcr_ids to choose ideally? `"pcr_ids":"1,4,7,9,14"`?) In theory, this can be used without specifying any `pcr_ids` (e.g. without secure boot), but then, the encryption is pointless. Instead of `"key":"ecc"` could also set `"key":"rsa"`.

To check that the key was added, run
```
sudo clevis luks list -d /dev/sda3
```
Rebuild the initramfs image:
```
sudo update-initramfs -u -k all
```
Test by rebooting the server
```
sudo reboot
```
The prompt to enter the password is shown, but after a short time the boot automatically continues.

To remove the key from the TPM, run
```
sudo clevis luks unbind -d /dev/sda3 -s 2 tpm2
```
where `-s` is the slot shown by `sudo clevis luks list -d /dev/sda3` (first number). Double check with `sudo cryptsetup luksDump /dev/sda3`, which shows something like
```
Tokens:
  0: clevis
        Keyslot:    2
```

## TODO

The next Ubuntu release will switch from initramfs-tools to dracut. How does this affect the three methods?

TODO: test yubikey - # clevis luks bind -d /dev/sdX yubikey '{"slot":1}'
