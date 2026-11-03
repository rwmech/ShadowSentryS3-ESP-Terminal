# MikroTik router rollback for ShadowSentry S3

How to undo each part of `docs\router-setup.md`, newest first. Every part comes out on its own and leaves the rest working.

Do each removal in a Safe Mode session (Ctrl+X), check, then release. Everything the setup added carries "shadowsentry" (or "DNS to Pi-hole") in its name, list or comment, so the commands match on those and touch nothing else.

## Fast stop: lift every block now

If a block cuts off something it shouldn't:

```
/system scheduler disable shadowsentry-block
/ip firewall address-list remove [find where comment="shadowsentry-block"]
```

Traffic flows again at once. The sentry's list is untouched; unblock there too, or the next sync puts the entries back once the scheduler is re-enabled.

## 5. Block list

```
/system scheduler remove [find where name=shadowsentry-block]
/system script remove [find where name=shadowsentry-block]
/ip firewall filter remove [find where comment~"^shadowsentry: block"]
/ip firewall address-list remove [find where comment="shadowsentry-block"]
/ip firewall address-list remove [find where list=shadowsentry-never]
```

Check: `/ip firewall filter print where comment~"shadowsentry"` shows nothing.

## 4. IPFIX flow export

```
/ip traffic-flow target remove [find where dst-address=192.168.0.118]
/ip traffic-flow set enabled=no
```

Traffic-flow was not in use before, so turning it off restores the earlier state. The sentry's ipfix status returns to "waiting"; the device pages keep the connection-table rows.

## 3. Tripwires

```
/ip firewall mangle remove [find where comment~"^shadowsentry"]
/ip firewall address-list remove [find where list=shadowsentry-trip]
/system logging remove [find where action=shadowsentry]
/system logging action remove [find where name=shadowsentry]
/ip firewall address-list remove [find where list=shadowsentry-admin]
/ip firewall address-list remove [find where list=shadowsentry-dns]
```

- Do the last two only after section 5 is gone, because the block script uses those lists.
- The interface list `shadowsentry-lan` is also used by the NAT rules in section 2. Remove it only after them:
  ```
  /interface list member remove [find where list=shadowsentry-lan]
  /interface list remove [find where name=shadowsentry-lan]
  ```
- The sentry's syslog status stops at its last count, and the router tripwire cells on the panel show OFF.

## 2. Port 53 redirect for the VLANs, and the hairpin

```
/ip firewall nat remove [find where comment="DNS to Pi-hole"]
/ip firewall nat remove [find where comment="DNS to Pi-hole (TCP)"]
/ip firewall nat remove [find where comment="DNS to Pi-hole hairpin"]
/ip firewall nat remove [find where comment="DNS to Pi-hole hairpin (TCP)"]
```

- This leaves the pre-existing rules ("Pi-hole exempt from DNS redirect", "Force all UDP/TCP DNS to Pi-hole") as they were, so bridge1 keeps its redirect.
- If bridge1 devices that hard-code a public DNS server stop resolving after this, the hairpin was needed. Put the two hairpin rules back.

## 1. DNS settings

```
/ip dhcp-server network set [find address=192.168.0.0/24] dns-server=""
/ip dhcp-server network set [find address=192.168.2.0/24] dns-server=""
/ip dhcp-server network set [find address=192.168.3.0/24] dns-server=""
/ip dns set servers=<the value from pre-shadowsentry.rsc>
```

- Find the old `/ip dns` value in the export, under `/ip dns set ... servers=...`: `/file print`, then open `pre-shadowsentry.rsc` (Files in Winbox, or download it).
- Clients go back to the old DNS at their next lease renewal.

## Everything at once

Run the sections in order: 5, 4, 3 (with the interface list at the end), 2, 1.

Don't `/import pre-shadowsentry.rsc` onto the running router. An export is a script of add and set commands; on a router that already has those items it creates duplicates and errors part way. Use it only as a reference for old values, or on a router reset to defaults.

## Sentry side

- To stop the sentry polling the router, turn the MikroTik integration off in Settings, or clear `MIKROTIK_URL` in `main\config.h`.
- Block-list entries live on the sentry: clear them on the device pages or with `POST /api/block/remove`.
- Nothing on the sentry has to change for a router rollback. The router feeds just stop, and the panel shows those cells as OFF.
