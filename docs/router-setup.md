# MikroTik router setup for ShadowSentry S3

What was configured on the router (MechRouter, CCR1036-8G-2S+, RouterOS 7.25) on 2026-11-03, why, and how to check it. The rollback for every part is in `docs\router-rollback.md`.

The sentry is 192.168.0.118 (admin port 9999). The router is 192.168.0.1 on bridge1. The Pi-hole is 192.168.0.103. The admin PCs are 192.168.0.75 and 192.168.0.156.

Everything the sentry does to the router is read-only, through the REST user `shadowsentry` on http://192.168.0.1:8080. The router never runs anything the sentry sends.

## Before any change

- A config export was taken: `/export file=pre-shadowsentry` (on the router's file list as `pre-shadowsentry.rsc`). It holds the values the changes below replaced, including the earlier `/ip dns` servers.
- Each change was made inside a Safe Mode session (Ctrl+X), checked, then released.

## Network layout found

- bridge1: 192.168.0.0/24 (gateway 192.168.0.1)
- vlan2: 192.168.2.0/24 (gateway 192.168.2.1)
- vlan3: 192.168.3.0/24 (gateway 192.168.3.1)
- WAN: the interface named `WAN`
- The forward chain has no isolation between bridge1 and the VLANs.
- Existing rules kept as they were:
  - Google DoH, DoT and DoQ blocks for 192.168.0.0/24
  - the Pi-hole's own DoT to Quad9
  - the port 53 redirect to the Pi-hole for 192.168.0.0/24 (NAT rules 0 to 3)
- Services: www 8080 and reverse-proxy 443 are enabled, Winbox 8291 is limited to 192.168.0.0/24, and FTP, SSH, Telnet, API and API-SSL are disabled.

## 1. DNS: every client uses the Pi-hole directly

So that the Pi-hole sees each device by its own address, which the device page needs.

```
/ip dhcp-server network set [find address=192.168.0.0/24] dns-server=192.168.0.103
/ip dhcp-server network set [find address=192.168.2.0/24] dns-server=192.168.0.103
/ip dhcp-server network set [find address=192.168.3.0/24] dns-server=192.168.0.103
/ip dns set servers=192.168.0.103
```

- Before: the DHCP networks had no dns-server set. The previous `/ip dns` servers are in `pre-shadowsentry.rsc`.
- No loop: the Pi-hole's upstream is Quad9 over DoT (forward rule 7), not the router.
- Pi-hole side: Settings, DNS, Interface settings, "Permit all origins" is set, so it answers vlan2 and vlan3.
- Check: `/ip dns print` and `/ip dhcp-server network print detail`. Clients pick up the new DNS at their next lease renewal.

## 2. Port 53 redirect extended to the VLANs, with hairpin

Devices that hard-code a public DNS server (Google and Android devices, the NVIDIA Shield) are answered by the Pi-hole anyway.

```
/ip firewall nat add chain=dstnat action=dst-nat to-addresses=192.168.0.103 protocol=udp dst-port=53 in-interface-list=shadowsentry-lan src-address=!192.168.0.103 dst-address=!192.168.0.103 comment="DNS to Pi-hole"
/ip firewall nat add chain=srcnat action=masquerade protocol=udp src-address=192.168.0.0/24 dst-address=192.168.0.103 dst-port=53 comment="DNS to Pi-hole hairpin"
/ip firewall nat add chain=dstnat action=dst-nat to-addresses=192.168.0.103 protocol=tcp dst-port=53 in-interface-list=shadowsentry-lan src-address=!192.168.0.103 dst-address=!192.168.0.103 comment="DNS to Pi-hole (TCP)"
/ip firewall nat add chain=srcnat action=masquerade protocol=tcp src-address=192.168.0.0/24 dst-address=192.168.0.103 dst-port=53 comment="DNS to Pi-hole hairpin (TCP)"
```

- For bridge1, the existing rules 2 and 3 match first. The new dst-nat rules add vlan2 and vlan3.
- Hairpin: a bridge1 device that asks 8.8.8.8 is answered through the router, so the reply appears to come from 8.8.8.8, as the device expects. Without it the Pi-hole would reply directly and the device would drop the answer.
- Side effect: the Pi-hole sees redirected lookups (only those) as coming from the router. Devices that use the Pi-hole directly keep their own address.
- Check: `/ip firewall nat print where comment~"Pi-hole"` (8 rules: the 4 existing and the 4 new). From a bridge1 PC, a query sent to 8.8.8.8 is answered.

## 3. Tripwires (log and address-list only, never drop)

The router reports to the sentry over syslog. Mangle rules log and list offenders. Nothing here drops, rejects or rate-limits traffic. The admin PCs and the sentry never trip.

```
/interface list add name=shadowsentry-lan comment="shadowsentry"
/interface list member add list=shadowsentry-lan interface=bridge1
/interface list member add list=shadowsentry-lan interface=vlan2
/interface list member add list=shadowsentry-lan interface=vlan3
/ip firewall address-list add list=shadowsentry-admin address=192.168.0.75 comment="shadowsentry: admin PC"
/ip firewall address-list add list=shadowsentry-admin address=192.168.0.156 comment="shadowsentry: admin PC 2"
/ip firewall address-list add list=shadowsentry-admin address=192.168.0.118 comment="shadowsentry: the sentry"
/ip firewall address-list add list=shadowsentry-dns address=192.168.0.103 comment="shadowsentry: the Pi-hole"
/system logging action add name=shadowsentry target=remote remote=192.168.0.118 remote-port=514 src-address=192.168.0.1 remote-log-format=syslog syslog-facility=local5 syslog-severity=auto add-topics-string=yes
/system logging add topics=account action=shadowsentry
/system logging add topics=critical action=shadowsentry
/system logging add topics=system,info,!account action=shadowsentry
/system logging add topics=dhcp,info action=shadowsentry
/system logging add topics=firewall action=shadowsentry regex="^SS-TRIP-"
/ip firewall mangle add chain=prerouting action=jump jump-target=shadowsentry-trip connection-state=new in-interface-list=shadowsentry-lan src-address-list=!shadowsentry-admin comment="shadowsentry: tripwires, log and address-list only, never drops"
/ip firewall mangle add chain=shadowsentry-trip action=add-src-to-address-list address-list=shadowsentry-trip address-list-timeout=1h src-address-list=!shadowsentry-trip protocol=tcp psd=21,3s,3,1 log=yes log-prefix="SS-TRIP-PSD" comment="shadowsentry: port scan seen by the router"
/ip firewall mangle add chain=shadowsentry-trip action=add-src-to-address-list address-list=shadowsentry-trip address-list-timeout=1h src-address-list=!shadowsentry-trip dst-address-type=local protocol=tcp dst-port=21,22,23,80,443,2000,8080,8291,8728,8729 log=yes log-prefix="SS-TRIP-MGMT" comment="shadowsentry: management port from a non-admin host"
/ip firewall mangle add chain=shadowsentry-trip action=return src-address-list=shadowsentry-dns comment="shadowsentry: the resolvers skip the DNS tripwire"
/ip firewall mangle add chain=shadowsentry-trip action=add-src-to-address-list address-list=shadowsentry-trip address-list-timeout=1h src-address-list=!shadowsentry-trip dst-address-list=!shadowsentry-dns dst-address-type=!local protocol=udp dst-port=53 log=yes log-prefix="SS-TRIP-DNS" comment="shadowsentry: DNS bypass (UDP)"
/ip firewall mangle add chain=shadowsentry-trip action=add-src-to-address-list address-list=shadowsentry-trip address-list-timeout=1h src-address-list=!shadowsentry-trip dst-address-list=!shadowsentry-dns dst-address-type=!local protocol=tcp dst-port=53,853 log=yes log-prefix="SS-TRIP-DNS" comment="shadowsentry: DNS bypass (TCP, DoT)"
```

- What trips:
  - a port scan seen by the router (55-24)
  - a non-admin host on the router's management ports, including disabled services (55-23)
  - DNS to anything but the Pi-hole or the router (55-26)
  - logins and failed logins (55-21, 55-10)
  - configuration changes (55-22)
  - new DHCP leases (60-02)
- The mangle rules run before NAT. So a device that asks 8.8.8.8 trips 55-26 even though the redirect in section 2 hands the lookup to the Pi-hole: the alert means the device tried, not that it got through. Google and Android devices do this routinely.
- Check:
  - on the router: `/ip firewall mangle print where comment~"shadowsentry"` (6 rules) and `/system logging print` (5 rules with action shadowsentry)
  - on the sentry: `GET /api/router/status`, where syslog shows `live` true and `received` climbing

## 4. IPFIX flow export (read-only)

Every flow crossing the WAN port goes to the sentry, so a device's short connections show on its device page.

```
/ip traffic-flow set enabled=yes interfaces=WAN cache-entries=4k active-flow-timeout=1m inactive-flow-timeout=15s
/ip traffic-flow target add dst-address=192.168.0.118 port=4739 src-address=192.168.0.1 version=ipfix
/ip traffic-flow ipfix set bytes=yes packets=yes protocol=yes src-address=yes dst-address=yes src-port=yes dst-port=yes nat-src-address=yes nat-dst-address=yes
```

- Traffic-flow was not in use before.
- About 20 flow records a second at the first check. The sentry accepts up to 200 a second and counts the rest as dropped.
- Check: `GET /api/router/status`, where ipfix shows `state` "ok" with `records` climbing and `bad` 0.

## 5. Block list (the device page's Block buttons)

The sentry keeps the list (64 entries at most). The router fetches it every minute and keeps two address lists that two drop rules use.
- dst entries drop traffic from the LAN to that address. The admin PCs are exempt.
- src entries drop a device's routed traffic: the internet and the other subnets. It can still reach its own segment.

The router reads plain lines and checks each one; it never runs anything from the sentry.

```
/ip firewall address-list add list=shadowsentry-never address=192.168.0.1 comment="shadowsentry: the router"
/ip firewall address-list add list=shadowsentry-never address=192.168.0.118 comment="shadowsentry: the sentry"
/ip firewall address-list add list=shadowsentry-never address=192.168.0.103 comment="shadowsentry: the Pi-hole"
/ip firewall address-list add list=shadowsentry-never address=192.168.0.75 comment="shadowsentry: admin PC"
/ip firewall address-list add list=shadowsentry-never address=192.168.0.156 comment="shadowsentry: admin PC 2"
```
- The script `shadowsentry-block` is pasted from `tools\routeros\blocklist.rsc`, with the URL http://192.168.0.118:9999/routeros/block.txt.
- The scheduler `shadowsentry-block`, every 1 min, was added with `disabled=yes`.
- The two drop rules go before the "Block Google DoH" rule, so they sit above FastTrack:
```
/ip firewall filter add chain=forward action=drop dst-address-list=shadowsentry-block-dst src-address-list=!shadowsentry-admin place-before=[find comment="Block Google DoH"] comment="shadowsentry: block dst (sentry list)"
/ip firewall filter add chain=forward action=drop src-address-list=shadowsentry-block-src place-before=[find comment="Block Google DoH"] comment="shadowsentry: block src (sentry list)"
```

- First run by hand, `/system script run shadowsentry-block`: no error, and the sentry counted 1 fetch, 0 refused.
- To finish:
  1. Block a test address (for example 1.1.1.1) on the device page.
  2. Run the script again; `/ip firewall address-list print where list=shadowsentry-block-dst` shows it.
  3. Unblock it and run the script again; the entry goes.
  4. `/system scheduler enable shadowsentry-block`.
- Use: block a direct-IP destination from the device page, and unblock it from the same page. Blocks by name belong in the Pi-hole: many services share cloud addresses.

## Still to do

- Finish the block-list test and enable the scheduler (section 5).
- Optional: point the DoH, DoT and DoQ block rules at all three subnets, so vlan2 and vlan3 can't bypass the Pi-hole with encrypted DNS. Use an address list `lan-subnets` with the three networks, then `set` each rule's `src-address-list=lan-subnets`.
- Create a named full user, check you can log in with it, then disable `admin`.
- Then press "Arm router baseline" on the sentry's Settings page. Do this last, so none of today's changes count as integrity alerts.
- Optional: `reverse-proxy` listens on 443 with no available-from limit. Check that the input chain blocks it from the WAN.

## Sentry side

- `main\config.h` (git-ignored): `ROUTER_ADMIN_IPS` and `ROUTER_NEVER_BLOCK` are "192.168.0.75,192.168.0.156", from the next build.
- Pi-hole: query logging must be on (Settings, DNS, Log DNS queries) for the device page's DNS lookup matching. `ip-api.com` must be allowed for the Owner column.
