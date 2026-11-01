# ShadowSentry S3: router tripwires for RouterOS 7.24 (tested against the
# 7.24 CLI reference only, never run on a router by the author).
#
# What it does: the router sends a few log topics to the sentry over UDP
# syslog, and a mangle chain logs and lists (address-list shadowsentry-trip)
# three kinds of offender: a port scan the router sees (psd), a non-admin host
# on the router's management ports, and DNS to anything but the Pi-hole.
# Nothing here drops, rejects or rate-limits a packet, and nothing touches
# your admin access: the rules use the jump, return, add-src-to-address-list
# and log=yes actions only, and your admin addresses skip the chain entirely.
#
# Paste it in a terminal (or /import it) after editing the lines marked EDIT.
# Remove it again with:
#   /ip firewall mangle remove [find where comment~"^shadowsentry"]
#   /ip firewall address-list remove [find where list=shadowsentry-trip]
#   /system logging remove [find where action=shadowsentry]
#   /system logging action remove [find where name=shadowsentry]
# (keep the shadowsentry-admin and shadowsentry-dns lists if blocklist.rsc
# uses them).
#
# References (RouterOS 7.24 manual, checked 2026-11-01):
#   http://manual.mikrotik.com/docs/7.24/cli-reference/system/logging/
#   http://manual.mikrotik.com/docs/7.24/cli-reference/system/logging/action/
#   http://manual.mikrotik.com/docs/7.24/diagnostics-monitoring-and-troubleshooting/log/
#   http://manual.mikrotik.com/docs/7.24/cli-reference/ip/firewall/mangle/
#   http://manual.mikrotik.com/docs/7.24/cli-reference/ip/firewall/filter/
#   http://manual.mikrotik.com/docs/7.24/cli-reference/ip/firewall/address-list/
#   http://manual.mikrotik.com/docs/7.24/management-tools/console/  (place-before, find where)
#   https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/log/  (7.26 page: the
#     syslog wire format, add-topics-string, the "login failure" line)
# Not in the manual, taken from forum samples: the psd values 21,3s,3,1 (the
# manual gives the order weight-threshold, delay-threshold, low-port-weight,
# high-port-weight but no defaults) and the firewall log line layout with a
# prefix ("<prefix> <chain>: in:.. out:.., connection-state:new src-mac ..,
# proto TCP (SYN), a:p->b:q, len N"), which the sentry parses.

# ── 1. Addresses ──────────────────────────────────────────────────────────────
# shadowsentry-admin: never tripped (and never blocked by blocklist.rsc).
# Put every PC you manage the router from here, and the sentry itself (its
# read-only REST login reads the router every few seconds).
/ip firewall address-list
add list=shadowsentry-admin address=192.168.0.10 comment="shadowsentry: EDIT your admin PC"
add list=shadowsentry-admin address=192.168.0.118 comment="shadowsentry: EDIT the sentry (ShadowSentry S3)"
# shadowsentry-dns: the resolvers clients may use. DNS to anything else trips.
add list=shadowsentry-dns address=192.168.0.2 comment="shadowsentry: EDIT the Pi-hole"

# ── 2. Syslog to the sentry ───────────────────────────────────────────────────
# remote: the sentry. src-address: the router's address on the sentry's LAN
# (the sentry accepts syslog only from that address, with the gateway's MAC).
# syslog format with the topics added, so the sentry can tell a DHCP host
# name from a login line.
/system logging action
add name=shadowsentry target=remote remote=192.168.0.118 remote-port=514 src-address=192.168.0.1 remote-log-format=syslog syslog-facility=local5 syslog-severity=auto add-topics-string=yes
# EDIT above: remote= the sentry, src-address= the router's LAN address
# (the same address as MIKROTIK_URL or ROUTER_SYSLOG_SRC on the sentry).

/system logging
# Logins and logouts (system,info,account).
add topics=account action=shadowsentry
# Failed logins (system,error,critical).
add topics=critical action=shadowsentry
# Configuration changes ("... changed by ...", system,info), logins excluded.
add topics=system,info,!account action=shadowsentry
# DHCP leases ("<server> assigned <ip> for <MAC> <host>").
add topics=dhcp,info action=shadowsentry
# Only this file's firewall lines, not every log=yes rule you have.
add topics=firewall action=shadowsentry regex="^SS-TRIP-"

# ── 3. Tripwires (mangle: log and list, never drop) ───────────────────────────
# New connections from the LAN, except the admin list, go through the
# shadowsentry-trip chain. A source already on the list skips the rules for
# an hour, so a scan logs once, not once a packet.
/ip firewall mangle
add chain=prerouting action=jump jump-target=shadowsentry-trip connection-state=new in-interface-list=LAN src-address-list=!shadowsentry-admin comment="shadowsentry: tripwires, log and address-list only, never drops"
# EDIT above: in-interface-list=LAN is defconf's list of LAN ports; use yours.

# A port scan the router sees (from the LAN, to the router or routed through it).
add chain=shadowsentry-trip action=add-src-to-address-list address-list=shadowsentry-trip address-list-timeout=1h src-address-list=!shadowsentry-trip protocol=tcp psd=21,3s,3,1 log=yes log-prefix="SS-TRIP-PSD" comment="shadowsentry: port scan seen by the router"

# A non-admin host on the router's own management ports (FTP, SSH, Telnet,
# web, bandwidth test, the www port 8080, Winbox, API, API-SSL).
add chain=shadowsentry-trip action=add-src-to-address-list address-list=shadowsentry-trip address-list-timeout=1h src-address-list=!shadowsentry-trip dst-address-type=local protocol=tcp dst-port=21,22,23,80,443,2000,8080,8291,8728,8729 log=yes log-prefix="SS-TRIP-MGMT" comment="shadowsentry: management port from a non-admin host"
# EDIT above: dst-port= the ports your /ip service list uses, if you moved any.

# The Pi-hole itself may ask anyone (Unbound talks to the root servers).
add chain=shadowsentry-trip action=return src-address-list=shadowsentry-dns comment="shadowsentry: the resolvers skip the DNS tripwire"

# DNS or DNS over TLS to anything but the Pi-hole or the router.
add chain=shadowsentry-trip action=add-src-to-address-list address-list=shadowsentry-trip address-list-timeout=1h src-address-list=!shadowsentry-trip dst-address-list=!shadowsentry-dns dst-address-type=!local protocol=udp dst-port=53 log=yes log-prefix="SS-TRIP-DNS" comment="shadowsentry: DNS bypass (UDP)"
add chain=shadowsentry-trip action=add-src-to-address-list address-list=shadowsentry-trip address-list-timeout=1h src-address-list=!shadowsentry-trip dst-address-list=!shadowsentry-dns dst-address-type=!local protocol=tcp dst-port=53,853 log=yes log-prefix="SS-TRIP-DNS" comment="shadowsentry: DNS bypass (TCP, DoT)"

# If an earlier prerouting rule of yours ends in action=accept, it hides the
# jump: remove the jump and add it again in front of that rule with
#   place-before=[find where comment="<that rule's comment>"]
# (place-before as in the 7.24 Console page's examples).
