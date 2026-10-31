#pragma once
/*
 * Extra lwIP hooks for ShadowSentry, compiled into the lwip component.
 *
 * ESP-IDF 5.4 has no Kconfig option for the IPv4 input hook (only
 * LWIP_HOOK_IP6_INPUT has one). lwipopts.h sets LWIP_HOOK_FILENAME to
 * "lwip_default_hooks.h", which includes ESP_IDF_LWIP_HOOK_FILENAME when it is
 * defined. The project CMakeLists.txt defines it for the lwip target only, with
 * this directory on that target's include path, the way IDF's
 * examples/network/vlan_support injects its hooks.
 *
 * lwIP calls the hook from ip4_input() on the tcpip task, after the version
 * check and before its own header checks: return 0 to pass the packet on, or
 * free it and return non-zero to eat it.
 */

struct pbuf;
struct netif;

int ss_ip4_input_hook(struct pbuf *p, struct netif *inp);   // main/detect/detect.c

#define LWIP_HOOK_IP4_INPUT(p, inp)  ss_ip4_input_hook((p), (inp))
