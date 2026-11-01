# ShadowSentry S3: the router pulls the sentry's block list, RouterOS 7.24
# (written against the 7.24 CLI reference and scripting manual only, never
# run on a router by the author).
#
# What it does: every minute a scheduler runs the script shadowsentry-block,
# which fetches http://<sentry>:9999/routeros/block.txt (plain text, lines
# "dst a.b.c.d" or "src a.b.c.d") into a variable, checks every line itself,
# and syncs two address lists. Two forward-chain rules drop:
#   dst  traffic from your LAN to a blocked address
#   src  a blocked device's traffic through the router (the internet and
#        your other subnets); it can still reach devices on its own LAN
#        segment, because bridged traffic does not pass the IP firewall
#
# Why it is safe if the sentry were taken over:
# - The router fetches data, never a script: the text goes into a variable
#   and is parsed here; nothing from the sentry is ever run (/import, :parse
#   and :execute are not used). The sentry's own router login stays read-only.
# - Each line must be "dst" or "src", one space, an address :toip accepts.
#   Anything else is skipped.
# - At most 64 addresses are taken, the rest ignored.
# - Never blocked, checked here on the router: the shadowsentry-never list
#   (EDIT below), the shadowsentry-admin and shadowsentry-dns lists (from
#   tripwires.rsc), and every address of the router itself.
# - Only entries this script made (comment "shadowsentry-block") are ever
#   removed; the two lists are only used by the two drop rules below.
# - The drop rules are in the forward chain: the router's own management
#   (input chain) is untouched, and the dst rule never applies to the
#   shadowsentry-admin PCs.
# - If the fetch fails (sentry down, 404, 500) nothing changes: the last
#   good list stays. To lift every block: disable the scheduler, then
#   /ip firewall address-list remove [find where comment="shadowsentry-block"]
#
# Edit the lines marked EDIT, then paste. Remove it with:
#   /system scheduler remove [find where name=shadowsentry-block]
#   /system script remove [find where name=shadowsentry-block]
#   /ip firewall filter remove [find where comment~"^shadowsentry: block"]
#   /ip firewall address-list remove [find where comment="shadowsentry-block"]
#
# References (RouterOS 7.24 manual, checked 2026-11-01):
#   http://manual.mikrotik.com/docs/7.24/cli-reference/tool/fetch/
#   http://manual.mikrotik.com/docs/7.24/developer-guides/scripting/
#   http://manual.mikrotik.com/docs/7.24/developer-guides/scripting/scripting-tips-and-tricks/
#   http://manual.mikrotik.com/docs/7.24/cli-reference/system/scheduler/
#   http://manual.mikrotik.com/docs/7.24/cli-reference/system/script/
#   http://manual.mikrotik.com/docs/7.24/cli-reference/ip/firewall/filter/
#   http://manual.mikrotik.com/docs/7.24/cli-reference/ip/firewall/address-list/
#   http://manual.mikrotik.com/docs/7.24/management-tools/console/  (place-before, find where)
#   https://help.mikrotik.com/docs/spaces/ROS/pages/8978514/Fetch  (as-value with output=user,
#     the "status" and "data" keys, the 64 KB limit of output=user)
# Not stated in the manual, from MikroTik's forum: that :find gives nil when
# the text is not found and that a failed :toip gives a nil value (the script
# tests both with :typeof, so either way a bad line is skipped), and the
# array append idiom ":set a ($a, $v)".

# ── 1. Never block (checked on the router) ────────────────────────────────────
/ip firewall address-list
add list=shadowsentry-never address=192.168.0.1 comment="shadowsentry: EDIT the router's LAN address"
add list=shadowsentry-never address=192.168.0.118 comment="shadowsentry: EDIT the sentry"
add list=shadowsentry-never address=192.168.0.2 comment="shadowsentry: EDIT the Pi-hole"
add list=shadowsentry-never address=192.168.0.10 comment="shadowsentry: EDIT your admin PC"

# ── 2. The script ─────────────────────────────────────────────────────────────
/system script
add name=shadowsentry-block policy=read,write,test dont-require-permissions=no source={
# EDIT: the sentry's address and admin port.
:local url "http://192.168.0.118:9999/routeros/block.txt"
:local tag "shadowsentry-block"
:local max 64
:local r
:do {
  :set r [/tool fetch url=$url output=user as-value]
} on-error={
  :log warning "shadowsentry-block: fetch failed, block list unchanged"
  :error "fetch failed"
}
:if (($r->"status") != "finished") do={
  :log warning "shadowsentry-block: fetch did not finish, block list unchanged"
  :error "fetch not finished"
}
:local data ($r->"data")
:local wantDst [:toarray ""]
:local wantSrc [:toarray ""]
:local taken 0
:local skipped 0
:while (([:len $data] > 0) && ($taken < $max)) do={
  :local e [:find $data "\n"]
  :local line
  :if ([:typeof $e] = "num") do={
    :set line [:pick $data 0 $e]
    :set data [:pick $data ($e + 1) [:len $data]]
  } else={
    :set line $data
    :set data ""
  }
  :local sp [:find $line " "]
  :local ok false
  :if ([:typeof $sp] = "num") do={
    :local kind [:pick $line 0 $sp]
    :local a [:toip [:pick $line ($sp + 1) [:len $line]]]
    :if ((($kind = "dst") || ($kind = "src")) && ([:typeof $a] = "ip")) do={
      :local s [:tostr $a]
      :local never false
      :if ([:len [/ip firewall address-list find where (list="shadowsentry-never" || list="shadowsentry-admin" || list="shadowsentry-dns") && address=$s]] > 0) do={ :set never true }
      :if ([:len [/ip address find where address~("^" . $s . "/")]] > 0) do={ :set never true }
      :if (!$never) do={
        :set ok true
        :set taken ($taken + 1)
        :if ($kind = "dst") do={ :set wantDst ($wantDst, $s) } else={ :set wantSrc ($wantSrc, $s) }
      } else={
        :log warning ("shadowsentry-block: " . $s . " is on a never-block list, skipped")
      }
    }
  }
  :if ((!$ok) && ([:len $line] > 0)) do={ :set skipped ($skipped + 1) }
}
:if ($skipped > 0) do={ :log warning ("shadowsentry-block: " . $skipped . " lines skipped") }
# Sync each list: drop our entries that left, add the new ones.
:foreach id in=[/ip firewall address-list find where list="shadowsentry-block-dst" && comment=$tag] do={
  :local a [:tostr [/ip firewall address-list get $id address]]
  :if ([:typeof [:find $wantDst $a]] != "num") do={
    /ip firewall address-list remove $id
    :log info ("shadowsentry-block: unblocked dst " . $a)
  }
}
:foreach a in=$wantDst do={
  :if ([:len [/ip firewall address-list find where list="shadowsentry-block-dst" && address=$a]] = 0) do={
    /ip firewall address-list add list=shadowsentry-block-dst address=$a comment=$tag
    :log info ("shadowsentry-block: blocked dst " . $a)
  }
}
:foreach id in=[/ip firewall address-list find where list="shadowsentry-block-src" && comment=$tag] do={
  :local a [:tostr [/ip firewall address-list get $id address]]
  :if ([:typeof [:find $wantSrc $a]] != "num") do={
    /ip firewall address-list remove $id
    :log info ("shadowsentry-block: unblocked src " . $a)
  }
}
:foreach a in=$wantSrc do={
  :if ([:len [/ip firewall address-list find where list="shadowsentry-block-src" && address=$a]] = 0) do={
    /ip firewall address-list add list=shadowsentry-block-src address=$a comment=$tag
    :log info ("shadowsentry-block: blocked src " . $a)
  }
}
}

# ── 3. Every minute ───────────────────────────────────────────────────────────
/system scheduler
add name=shadowsentry-block interval=1m on-event="/system script run shadowsentry-block" policy=read,write,test

# ── 4. The drop rules (forward chain only) ────────────────────────────────────
# Put them first in the forward chain, so they also stop connections that
# were already established (FastTrack lets those skip later rules). Rules
# already established and FastTracked before the block may run on until
# they close. place-before takes the first forward rule, if there is one.
# Absolute paths, so it pastes from any menu.
:if ([:len [/ip firewall filter find where chain=forward]] > 0) do={
  /ip firewall filter add chain=forward action=drop dst-address-list=shadowsentry-block-dst src-address-list=!shadowsentry-admin place-before=[:pick [/ip firewall filter find where chain=forward] 0] comment="shadowsentry: block dst (sentry list)"
  /ip firewall filter add chain=forward action=drop src-address-list=shadowsentry-block-src place-before=[:pick [/ip firewall filter find where chain=forward] 1] comment="shadowsentry: block src (sentry list)"
} else={
  /ip firewall filter add chain=forward action=drop dst-address-list=shadowsentry-block-dst src-address-list=!shadowsentry-admin comment="shadowsentry: block dst (sentry list)"
  /ip firewall filter add chain=forward action=drop src-address-list=shadowsentry-block-src comment="shadowsentry: block src (sentry list)"
}
