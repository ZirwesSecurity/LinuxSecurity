[Back to main document](README.md)

# Uncomplicated Firewall (ufw)

- [Basic usage](#basic-usage)
- [Examples](#examples)
- [Routing](#routing)
- [Ping](#ping)

ufw is a simple tool for setting firewall rules using iptables/nftables as backend. The following steps have been tested with Ubuntu 24.04 LTS and Debian 13. Note that ufw only makes sense on simple servers where no other tools modify firewall rules (e.g. using ufw together with docker is probably not a good idea).

## Basic usage

To install ufw, run
```
sudo apt install ufw
```
After installation, the firewall is not yet active. The status can be checked with
```
sudo systemctl status ufw
```
or
```
sudo ufw status verbose
```
By default (if no other rule matches), all outgoing packets are allowed, all new incoming packets which do not match outgoing traffic are denied (i.e. silently dropped) and forwarding/routing (i.e. non-local traffic not originating from or going to the machine) is denied. In addition, there are a handful of additional rules by default:
- Drop packets with RH0 headers and invalid packets
- Accept certain ICMP (for ping), DHCP (for IP address negotiation), mDNS (multicast DNS) and UPnP (service discovery) traffic (see the ufw documentation for more information)
- Traffic through the loopback device is always allowed
By default, the logging level is set to 'low' (see below).

To change the default behavior for tcp and udp traffic, run
```
sudo ufw (--dry-run) default (allow|deny|reject) (incoming|outgoing|routed)
```
For creating rules for incoming and outgoing traffic, there is a short-hand and long-form notation. The short-hand syntax does not allow specifying IP addresses and interfaces. Almost all arguments are optional, at least `from` or `to` must be specified for the long-form notation. Rules are created by default for both ipv4 and ipv6 if possible (e.g. if no ipv4 or ipv6 are explicitly mentioned in the rule). The order of rules matters: rules are applied top to bottom (starting with rule number 1). The first match wins (so specific rules should go first, general rules last). To block all ipv6 (except on loopback device), set `IPV6=no` in `/etc/default/ufw`. Short-hand:
```
sudo ufw (--dry-run) (prepend|delete|insert [NUM]) (allow|deny|reject|limit) (in|out) (log|log-all) (([PORT](/[PROTOCOL]))|[APPNAME]) (comment [COMMENT])
```
Long-form:
```
sudo ufw (--dry-run) (prepend|delete|insert [NUM]) (allow|deny|reject|limit) (in|out) (on [INTERFACE]) (log|log-all) (proto [PROTOCOL]) (from ([ADDRESS]|[RANGE]|any) (port [PORT]|app [APPNAME])) (to ([ADDRESS]|[RANGE]|any) (port [PORT]|app [APPNAME])) (comment [COMMENT])
```
- `(--dry-run)` Optional: Do not apply the rule, only check if it would be valid and show the changes that would be made
- `(prepend|delete|insert [NUM])` Optional: By default, the rule is appended to the list of rules.
  - Instead, the rule can be `prepend`ed (same as `insert 1`).
  - The rule can also be added at a specific position with `insert [NUM]` (no rules are overwritten, simply the new rule is added), where [NUM] is the rule number (ufw will store ipv6 rules after the ipv4 rules, trying to maintain the same relative order). If the same rule already exists, it must first be deleted.
  - `delete` deletes the rule (use the same arguments as used when the rule was added, comments are ignored).
- `(allow|deny|reject|limit)`:
  - `allow`: allow traffic matching the rule
  - `deny`: silently drop traffic
  - `reject`: drop traffic but respond with a rejection message
  - `limit`: allow traffic, but limit connection attempts to 6/min. If exceeded, silently drop.
- `(in|out)` Optional: specifies if the rule is applied to incoming or outgoing traffic. If not specified, defaults to `in`.
- `(on [INTERFACE])` Optional: specifies the interface the rule applies to, e.g. `eth0`. By default, rules apply to all interfaces. Can only be used together with `(in|out)`.
- `(log|log-all)` Optional: by default, no rule-specific logging is applied (see below for global logging options). Specifying `log` will log all new connections matching the rule, and `log-all` will log all packets matching the rule.
- `[PROTOCOL]` Optional: Specify the protocol this rule applies to. If omitted, the rule applies to tcp and udp. Protocols other than tcp and udp require long-form notation and do not accept a port. Available protocols are:
  - tcp
  - udp
  - ipv6 (tunneled ipv6)
  - esp and ah (IPSec)
  - vrrp (keepalive)
  - igmp (Internet Group Management Protocol)
  - gre (Generic Routing Encapsulation, VPN)
- `([ADDRESS]|[RANGE]|any)` Specifies the target or destination IP. Hostnames are not supported.
  - `ADDRESS`: ipv4 or ipv6 address, e.g. 1.2.3.4. If IP is specified, the rule is added only for ipv4 or ipv6, respectively
  - `RANGE`: Specify an IP range, e.g. 1.2.3.0/24. To allow all ipv4, use 0.0.0.0/0. To allow all ipv6, use ::/0.
  - `any`: Matches all IPs and therefore means both `0.0.0.0/0` AND `::/0`.
- `[PORT]` Optional: For long-form notation, must be used together with `([ADDRESS]|[RANGE]|any)`. List of ports, e.g. `22` or `22,80,443` or `22,80:128,443`, where `a:b` is the range of ports from `a` to `b`. At most 15 ports can be specified, where the `a:b` port pair counts as two ports.
- `[APPNAME]` Optional: Instead of protocol and port, an app name can be specified. To see available apps, run `sudo ufw app list`. The ports and protocols included by the app alias can be seen with `sudo ufw app info [APPNAME]`. If a `from` port is specified, it is overwritten by the specification of the app. Cannot be specified together with a protocol. 
- `[COMMENT]` Optional: add a comment for the rule, e.g. `comment "my new rule"`

To see the rules while ufw is inactive, use
```
sudo ufw show added
```

To active the rules, run (NOTE: if you are connected via ssh, make sure the ssh connection is allowed first, e.g. with `sudo ufw limit 22/tcp`!)
```
sudo ufw enable
```
Check the status with `sudo systemctl status ufw` and `sudo ufw status verbose`.
To restart ufw (after changing settings), run
```
sudo ufw reload
```
or
```
sudo ufw disable && sudo ufw enable
```
To see more details about the rules, run
```
sudo ufw status verbose
sudo ufw status numbered
sudo ufw show added
sudo ufw show raw
sudo iptables -S
sudo ip6tables -S
sudo nft list rules
```
Default rules can be seen in
```
/etc/ufw/before.rules
/etc/ufw/before6.rules
/etc/ufw/after.rules
/etc/ufw/after6.rules
/etc/ufw/sysctl.conf
```
To delete a rule, run either
```
sudo ufw delete [rule]
```
or
```
sudo ufw delete [NUM]
```
where [rule] is the same rule as specified when it was added (ignoring the comment) and [NUM] is the rule's number as given by `sudo ufw status numbered`. Note that the rule numbers may change after deletion, so be careful with consecutive `ufw delete [NUM]`. Also, `ufw delete [rule]` will affect both ipv4 and ipv6 rules (if applicable) while `ufw delete [NUM]` only deletes the chosen number.

To reset ufw (i.e. restore defaults and remove all rules), run
```
ufw reset # this also disables ufw
```

Logging can be specified with
```
sudo ufw logging (on|off|low|medium|high|full)
```
By default, logging is set to `low` (higher values can lead to excessively large log files). To see the logs, run
```
sudo journalctl -g "UFW"
```
or check `/var/log/ufw.log` (depending on the system).


## Examples

Allow incoming http and https:
```
sudo ufw allow 80,443/tcp
sudo ufw allow 443/udp comment "For QUIC"
```
Allow (and rate limit) incoming ssh with standard port 22 (the port on this machine) from any network:
```
sudo ufw limit 22/tcp
```
Allow (and rate limit) ssh with standard port 22 only from the internal network 192.168.178.* to any (interface) IP of this machine (note: is does not really make sense to specify a "from" port because it is a randomized high port number for each connection):
```
sudo ufw limit from 192.168.178.0/24 to any port 22 proto tcp
```
Allow (and rate limit) ssh with standard port 22 only from the internal network 192.168.178.* with destination in the internal network (e.g. the machine itself. Instead of using the IP range in the `to` address, could use the IP of the server if it as a static IP):
```
sudo ufw limit from 192.168.178.0/24 to 192.168.178.0/24 port 22 proto tcp
```
Allow (and limit) ssh with standard port 22 only via the specific the interface enp0s8, e.g. the one for the internal network (note that interface names might change over time, so in this case, prefer the previous rule):
```
sudo ufw limit in on enp0s8 from any to any port 22 proto tcp
```
This can be made even more restrictive (not allowing receiving/forwarding/tunneling packets from other interfaces/networks) by using (here, 1.1.1.1 is the client's address, 1.1.1.2 is the server's address on the specified interface, address ranges as in the previous example, e.g. if the server and/or client do not have a static ip, are possible as well):
```
sudo ufw limit in on enp0s8 from 1.1.1.1 to 1.1.1.2 port 22 proto tcp
```
To allow outgoing traffic, e.g. if the default outgoing policy is `deny`, use the following command (where 1.1.1.2 is the IP of the server where the command is run on (if it has a static ip, otherwise use a range) and enp0s8 its interface name affected by this rule, and 1.1.1.3 is the destination server whose IP can be a range as well) [note that again it does not make sense to specify a "from" port, because the outgoing connections will originate from a random high port]:
```
sudo ufw allow out on enp0s8 from 1.1.1.2 to 1.1.1.3 port 22 proto tcp
```
Or allow outgoing traffic only into the internal net to the default ssh port:
```
sudo ufw allow out to 192.168.178.0/24 port 22 proto tcp # implies "from any"
```
Or allow outgoing traffic if it goes to port 22 on the destination machine:
```
sudo ufw allow out to any port 22 proto tcp # same as "ufw allow out 22/tcp" short-hand notation
```

## Routing

ufw can also be used to add routing rules. Adding rules has a slightly different syntax:
```
ufw route (--dry-run) (log|log-all) (delete|insert [NUM]|prepend) (allow|deny|reject|limit) (in (on [INTERFACE])) (from [ADDRESS] (port [PORT] | app [APPNAME])) (out (on [INTERFACE])) (to [ADDRESS] (port [PORT] | app [APPNAME])) (proto [PROTOCOL]) (comment COMMENT)
 ```
For routing rules, both `in` and `out` parameters can be specified.


Consider the case of a destination server (9.9.9.9) hosting a website. This server can only be reached via a proxy server (IPs 9.9.9.5 (enp0s9) and 1.1.1.5 (enp0s8)). A client (1.1.1.1) wants to access the website via the proxy server:
Client   -> proxy    -> internal routing -> proxy    -> destination server
            1.1.1.5                         9.9.9.5     9.9.9.9
1.1.1.1     (enp0s8)                        (enp0s9)

To achieve routing packets from the client arriving at the proxy server's enp0s8 interface to the other proxy server's interface enp0s9 and from there to the destination server, make the following changes on the proxy server. In
```
/etc/sysctl.conf
```
allow forwarding by setting
```
net.ipv4.ip_forward=1
```
For ipv6, see `net/ipv6/conf/default/forwarding=1`. Then, add the routing rules (in general, it is not a good idea to manually set iptables rules since they are managed by ufw. This is only an example case):
```
sudo iptables -t nat -A PREROUTING -i enp0s8 -p tcp --dport 80 -j DNAT --to-destination 9.9.9.9:80
```
Destination NAT (DNAT) redirects incoming connections to the proxy's enp0s8 on port 80 to the destination server
- `-t nat``: change source or destination address
- `-A PREROUTING`: append to prerouting table
- match packets coming in (`-i`) on interface `enp0s8` of protocol (`-p`) tcp with destination port (`--dport`) 80
- `-j DNAT`: rewrite the destinate address and port of the packet

And for the reverse route:
```
sudo iptables -t nat -A POSTROUTING -o enp0s9 -j MASQUERADE
```
Source NAT (SNAT / MASQUERADE) so the destination server sends replies back to the proxy, not directly to the client.
- -t nat: change source or destination address
- -A POSTROUTING: append to prerouting table
- -j MASQUERADE: rewrite the source IP of the packet to the current IP of enp0s9
This is equivalent to `sudo iptables -t nat -A POSTROUTING -o enp0s9 -j SNAT --to-source 1.1.1.1`.

Apply changes and disable ufw
```
sudo sysctl -p
sudo ufw reload
sudo ufw disable
```
Now, when running `curl 1.1.1.5` on the client, the website from `9.9.9.9` is displayed.
After enabling ufw
```
sudo ufw enable
```
this does not work anymore, because ufw's default routing policy is `deny`.
To allow the routing, add the following rules on the proxy:
```
ufw route allow in on enp0s8 out on enp0s9
ufw route allow in on enp0s9 out on enp0s8
```
Alternatively, instead of specifying interfaces, the IPs (or IP ranges) of the interfaces can be specified:
```
ufw route allow from 1.1.1.0/24 to 9.9.9.0/24
ufw route allow from 9.9.9.0/24 to 1.1.1.0/24
```
Note that no additional incoming or outgoing ufw rules are required, even if the default incoming and outgoing policies are set to `deny`.

To me most restrictive, set the following rules. Allow routing through the proxy from the client to the destination server:
```
sudo ufw route allow in on enp0s8 from 1.1.1.1 out on enp0s9 to 9.9.9.9 port 80 proto tcp
```
Allow routing through the proxy from the destination server back to the client:
```
sudo ufw route allow in on enp0s9 from 9.9.9.9 port 80 out on enp0s8 to 1.1.1.1 port 80 proto tcp
```
Note that the IPs are those from machines the client and destination, but interface names are those of the proxy! Also note that specifying port 80 as the destination port in the last rule only works due to the way ufw keeps track of connections. In general, only the source port should be specified (TODO: correct?)

## PING

To block ping responses, run
```
sudo sed -i '/icmp/s/ACCEPT/DROP/' /etc/ufw/before.rules
sudo ufw reload
```
TODO: how to do this for ipv6 without causing conflict with other parts of the ipv6 protocol?
