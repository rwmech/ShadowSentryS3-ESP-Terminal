# ShadowSentry S3: IPFIX from the router's WAN port for RouterOS 7.24
# (written against the 7.24 CLI reference only, never run on a router by the
# author).
#
# What it does: RouterOS traffic-flow records every flow crossing the WAN
# port and sends it to the sentry as IPFIX on UDP 4739. The sentry keeps, per
# LAN device, each outside address and port it talked to, with bytes and
# packets each way, so short connections that come and go between two reads
# of the connection table still show on the device page. Read only: nothing
# is filtered or changed.
#
# Edit the lines marked EDIT, then paste. Remove it again with:
#   /ip traffic-flow target remove [find where dst-address=192.168.0.118]
#   /ip traffic-flow set enabled=no
# (the second line only if nothing else of yours uses traffic-flow).
#
# References (RouterOS 7.24 manual, checked 2026-11-01):
#   http://manual.mikrotik.com/docs/7.24/cli-reference/ip/traffic-flow/
#   http://manual.mikrotik.com/docs/7.24/cli-reference/ip/traffic-flow/target/
#   http://manual.mikrotik.com/docs/7.24/cli-reference/ip/traffic-flow/ipfix/
#   http://manual.mikrotik.com/docs/7.24/diagnostics-monitoring-and-troubleshooting/traffic-flow/
#     (defaults: interfaces all, cache-entries 4k, active-flow-timeout 30m,
#     inactive-flow-timeout 15s; "Traffic Flow can process only that traffic
#     which is processed by the router CPU", "HW offloaded traffic will not be
#     seen". The page does not say whether FastTracked connections are seen.)
#
# Notes:
# - interfaces= your WAN port only, so LAN to LAN traffic is not exported.
# - active-flow-timeout=1m: a long download is reported every minute instead
#   of every 30 minutes (the default), so the device page stays current.
# - The sentry accepts IPFIX only from the router's address with the
#   gateway's MAC; src-address= makes the router send from its LAN address.
# - It parses the templates the router sends (NetFlow v9 works too, with
#   version=9), so the field set below may change. It uses bytes, packets,
#   protocol, ports, src and dst address and the NAT addresses (those name
#   the LAN device on a reply that comes back to the WAN address).
# - The sentry takes at most 200 flow records a second (ROUTER_IPFIX_RATE);
#   more are counted as dropped in GET /api/router/status.

/ip traffic-flow
set enabled=yes interfaces=ether1 cache-entries=4k active-flow-timeout=1m inactive-flow-timeout=15s
# EDIT above: interfaces= your WAN interface (ether1 is defconf's).

/ip traffic-flow target
add dst-address=192.168.0.118 port=4739 src-address=192.168.0.1 version=ipfix
# EDIT above: dst-address= the sentry, src-address= the router's LAN address
# (the same address the sentry knows the router by: MIKROTIK_URL or
# ROUTER_SYSLOG_SRC).

/ip traffic-flow ipfix
set bytes=yes packets=yes protocol=yes src-address=yes dst-address=yes src-port=yes dst-port=yes nat-src-address=yes nat-dst-address=yes
