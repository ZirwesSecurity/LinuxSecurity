[Back to main document](README.md)

# Appendix

  - [Generating passwords](#generating-passwords)
  - [Generating keys](#generating-keys)

## Generating passwords

Every a password needs to be set, use one of the following one-liners to generate a 256bit password:
```bash
LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c43 ; echo

LC_ALL=C len=43; s=""; while [ ${#s} -lt ${len} ]; do LC_ALL=C tmp=`gpg2 --gen-random 2 128 | tr -dc 'A-Za-z0-9'`; s=${s}${tmp}; done; LC_ALL=C echo $s | head -c${len}; s=""; tmp=""; echo

LC_ALL=C len=43; s=""; while [ ${#s} -lt ${len} ]; do LC_ALL=C tmp=`openssl rand 128 | tr -dc 'A-Za-z0-9'`; s=${s}${tmp}; done; LC_ALL=C echo $s | head -c${len}; s=""; tmp=""; echo
 ```
The latter two might marginally increase security by trying to increase the entropy in the random source, but the first one should be good enough on a modern OS and work on pretty much all systems without installing additional packages.
For convenience, add the following functions to your `~/.bashrc`:
```bash
# generate a 256 bit password
genpw () {
    LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c43 ; echo
}
# generate a short alphanumeric string, e.g. for use as username
genuser () {
    LC_ALL=C tr -dc 'a-z' </dev/urandom | head -c10 ; echo
}
```
Re-source the `.bashrc`
```bash
source ~/.bashrc
```

## Generating keys

Function to be put in `.bashrc`, allowing to generate ssh keys by typing `gensshkey myserver`
```bash
gensshkey () {
    if [[ "$#" -eq 1 ]]; then
        ssh-keygen -a 128 -o -t ed25519 -E sha256 -Z chacha20-poly1305@openssh.com -f ~/.ssh/$1 -C $1
    else
        echo "Error! Usage: gensshkey [keyname]"
    fi
    return 0
}
```
Same as above, but for RSA instead of ed25519 keys:
```bash
gensshkey_rsa () {
    if [[ "$#" -eq 1 ]]; then
        ssh-keygen -a 128 -o -t rsa-sha2-512 -b 4096 -E sha256 -Z chacha20-poly1305@openssh.com -f ~/.ssh/$1 -C $1
    else
        echo "Error! Usage: gensshkey_rsa [keyname]"
    fi
    return 0
}
```
Re-source the `.bashrc`
```bash
source ~/.bashrc
```
