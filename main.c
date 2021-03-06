#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <sys/epoll.h>
#include <net/if.h> 
#include <sys/socket.h>
#include <arpa/inet.h>

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/snmp.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_arp.h>
#include <linux/rtnetlink.h>
#include <linux/genetlink.h>
#include <linux/if_packet.h>
#include <linux/fib_rules.h>
#include <linux/net_namespace.h>
#include <linux/netconf.h>

#include <libmnl/libmnl.h>

#include "nltrace.h"


#define NLOG(fmt, ...) printf(fmt, ##__VA_ARGS__)

#define LINE_LEN 128

static void
hexdump(const void *buf, unsigned int len)
{
	unsigned int i, out, ofs;
	const unsigned char *data = buf;
	char line[LINE_LEN];	/* space needed 8+16*3+3+16 == 75 */

	NLOG("  Dump data at [%p], len=%u\n", data, len);
	ofs = 0;
	while (ofs < len) {
		/* format the line in the buffer */
		out = snprintf(line, LINE_LEN, "%08X:", ofs);
		for (i = 0; i < 16; i++) {
			if (ofs + i < len)
				snprintf(line + out, LINE_LEN - out,
					 " %02X", (data[ofs + i] & 0xff));
			else
				strcpy(line + out, "   ");
			out += 3;
		}


		for (; i <= 16; i++)
			out += snprintf(line + out, LINE_LEN - out, " | ");

		for (i = 0; ofs < len && i < 16; i++, ofs++) {
			unsigned char c = data[ofs];

			if (c < ' ' || c > '~')
				c = '.';
			out += snprintf(line + out, LINE_LEN - out, "%c", c);
		}
		NLOG("%s\n", line);
	}
}


static int
print_info_slave_data_attr(const struct nlattr *a, void *data)
{
	if (mnl_attr_type_valid(a, IFLA_BOND_SLAVE_MAX) < 0) {
		NLOG("mnl_attr_type_valid");
		return MNL_CB_OK;
	}
	static char * ifla[] = {
		"IFLA_BOND_SLAVE_UNSPEC",
		"IFLA_BOND_SLAVE_STATE",
		"IFLA_BOND_SLAVE_MII_STATUS",
		"IFLA_BOND_SLAVE_LINK_FAILURE_COUNT",
		"IFLA_BOND_SLAVE_PERM_HWADDR",
		"IFLA_BOND_SLAVE_QUEUE_ID",
		"IFLA_BOND_SLAVE_AD_AGGREGATOR_ID",
		"IFLA_BOND_SLAVE_AD_ACTOR_OPER_PORT_STATE",
		"IFLA_BOND_SLAVE_AD_PARTNER_OPER_PORT_STATE",
	};
	uint8_t *permhw;
	int type = mnl_attr_get_type(a);

	NLOG("{nla_len=%d, nla_type=%s, ", mnl_attr_get_len(a), ifla[type]);
	switch(type){
	case IFLA_BOND_SLAVE_STATE:
	case IFLA_BOND_SLAVE_MII_STATUS:
	case IFLA_BOND_SLAVE_AD_ACTOR_OPER_PORT_STATE:
		NLOG("%u}", mnl_attr_get_u8(a));
		break;
	case IFLA_BOND_SLAVE_LINK_FAILURE_COUNT:
		NLOG("%u}", mnl_attr_get_u32(a));
		break;
	case IFLA_BOND_SLAVE_PERM_HWADDR:
		permhw = (uint8_t* )mnl_attr_get_payload(a);
		for (int i = 0; i < mnl_attr_get_payload_len(a); i++) {
			NLOG("%02x", permhw[i]);
		}
		NLOG("}");
		break;
	case IFLA_BOND_SLAVE_QUEUE_ID:
	case IFLA_BOND_SLAVE_AD_AGGREGATOR_ID:
	case IFLA_BOND_SLAVE_AD_PARTNER_OPER_PORT_STATE:
		NLOG("%u}", mnl_attr_get_u16(a));
		break;
	}
	return 0;
}

static int 
driver_kind(const char *type)
{
	const char *kinds[] = {
		"bridge",
		"tun",
		"bond",
		"vlan",
	};
	for (size_t i = 0; i < MNL_ARRAY_SIZE(kinds); i ++) {
		if (!strcmp(kinds[i], type)) {
			return i;
		}
	}
	return -1;
}

static int
print_info_data_attr(const struct nlattr *a, int driver_type, void *data)
{
	if (driver_type == -1) {
		NLOG("invalid driver kind type");
	}
	int type = mnl_attr_get_type(a);
	if (driver_type == 0) {
		static char *brinfo[] = {
#define _(a) #a
			BRIDGE_INFO_ENUM
#undef _
		};
		struct ifla_bridge_id *id;
		// struct br_boolopt_multi *multi;
		uint8_t *addr;
		NLOG("{nla_len=%d, nla_type=%s, ", mnl_attr_get_len(a), brinfo[type]);
		switch(type) {
			case IFLA_BR_HELLO_TIMER:
			case IFLA_BR_TCN_TIMER:
			case IFLA_BR_TOPOLOGY_CHANGE_TIMER:
			case IFLA_BR_GC_TIMER:
			case IFLA_BR_MCAST_LAST_MEMBER_INTVL:
			case IFLA_BR_MCAST_MEMBERSHIP_INTVL:
			case IFLA_BR_MCAST_QUERIER_INTVL:
			case IFLA_BR_MCAST_QUERY_INTVL:
			case IFLA_BR_MCAST_QUERY_RESPONSE_INTVL:
			case IFLA_BR_MCAST_STARTUP_QUERY_INTVL:
				NLOG("%lu}", mnl_attr_get_u64(a));
				break;
			case IFLA_BR_FORWARD_DELAY:
			case IFLA_BR_HELLO_TIME:
			case IFLA_BR_MAX_AGE:
			case IFLA_BR_AGEING_TIME:
			case IFLA_BR_STP_STATE:
			case IFLA_BR_ROOT_PATH_COST:
			case IFLA_BR_MCAST_HASH_ELASTICITY:
			case IFLA_BR_MCAST_HASH_MAX:
			case IFLA_BR_MCAST_LAST_MEMBER_CNT:
			case IFLA_BR_MCAST_STARTUP_QUERY_CNT:
				NLOG("%u}", mnl_attr_get_u32(a));
				break;
			case IFLA_BR_PRIORITY:
			case IFLA_BR_VLAN_PROTOCOL:
			case IFLA_BR_VLAN_DEFAULT_PVID:
			case IFLA_BR_GROUP_FWD_MASK:
			case IFLA_BR_ROOT_PORT:
				NLOG("%u}", mnl_attr_get_u16(a));
				break;
			case IFLA_BR_VLAN_FILTERING:
			case IFLA_BR_VLAN_STATS_ENABLED:
			case IFLA_BR_VLAN_STATS_PER_PORT:
			case IFLA_BR_MCAST_STATS_ENABLED:
			case IFLA_BR_TOPOLOGY_CHANGE:
			case IFLA_BR_TOPOLOGY_CHANGE_DETECTED:
			case IFLA_BR_MCAST_ROUTER:
			case IFLA_BR_MCAST_SNOOPING:
			case IFLA_BR_MCAST_QUERY_USE_IFADDR:
			case IFLA_BR_MCAST_QUERIER:
			case IFLA_BR_MCAST_IGMP_VERSION:
			case IFLA_BR_MCAST_MLD_VERSION:
			case IFLA_BR_NF_CALL_IPTABLES:
			case IFLA_BR_NF_CALL_IP6TABLES:
			case IFLA_BR_NF_CALL_ARPTABLES:
				NLOG("%u}", mnl_attr_get_u8(a));
				break;
			case IFLA_BR_ROOT_ID:
			case IFLA_BR_BRIDGE_ID:
				id = (struct ifla_bridge_id*)mnl_attr_get_payload(a);
				NLOG("(prio %02x%02x, addr %02x:%02x:%02x:%02x:%02x:%02x)}", id->prio[0], id->prio[1],
					id->addr[0], id->addr[1], id->addr[2], id->addr[3], id->addr[4], id->addr[5]);
				break;
			case IFLA_BR_GROUP_ADDR:
				addr = (uint8_t*)mnl_attr_get_payload(a);
				NLOG("%02x:%02x:%02x:%02x:%02x:%02x}", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
				break;
			case IFLA_BR_FDB_FLUSH:
				break;
			case IFLA_BR_MULTI_BOOLOPT:
				// multi = (struct br_boolopt_multi *)mnl_attr_get_payload(a);
				// NLOG("(optval %u, optmask %u)}",multi->optval, multi->optmask);
				break;
		}
	}else if (driver_type == 0) {
		static char *ifla[] = {
			"IFLA_VLAN_UNSPEC",
			"IFLA_VLAN_ID",
			"IFLA_VLAN_FLAGS",
			"IFLA_VLAN_EGRESS_QOS",
			"IFLA_VLAN_INGRESS_QOS",
			"IFLA_VLAN_PROTOCOL",
		};
		struct ifla_vlan_flags *flags;
		NLOG("{nla_len=%d, nla_type=%s, ", mnl_attr_get_len(a), ifla[type]);
		switch(type) {
			case IFLA_VLAN_ID:
			case IFLA_VLAN_PROTOCOL:
				NLOG("%u}", mnl_attr_get_u16(a));
				break;
			case IFLA_VLAN_FLAGS:
				flags = (struct ifla_vlan_flags *)mnl_attr_get_payload(a);
				NLOG("(flags %u, mask %u)}", flags->flags, flags->mask);
				break;
			case IFLA_VLAN_EGRESS_QOS:
			case IFLA_VLAN_INGRESS_QOS:
				break;
		}
	}

	return 0;
}

static int
print_info_attr(const struct nlattr *a, void *data)
{
	struct nlattr *attr;
	static char *ifla[]= {
		"IFLA_INFO_UNSPEC",
		"IFLA_INFO_KIND",
		"IFLA_INFO_DATA",
		"IFLA_INFO_XSTATS",
		"IFLA_INFO_SLAVE_KIND",
		"IFLA_INFO_SLAVE_DATA",
	};
	int type = mnl_attr_get_type(a);
	if (mnl_attr_type_valid(a, IFLA_INFO_MAX) < 0) {
		NLOG("mnl_attr_type_valid");
		return MNL_CB_OK;
	}
	static int driver;

	NLOG("{nla_len=%d, nla_type=%s, ", mnl_attr_get_len(a), ifla[type]);
	switch (type) {
	case IFLA_INFO_KIND:
		driver = driver_kind(mnl_attr_get_str(a));
		/* FALLTHROUGH */
	case IFLA_INFO_SLAVE_KIND:
		NLOG("%s}", mnl_attr_get_str(a));
		break;
	case IFLA_INFO_DATA:
		/* it depends on the driver */
		mnl_attr_for_each_payload(mnl_attr_get_payload(a), mnl_attr_get_payload_len(a)) {
			print_info_data_attr(attr, driver, NULL);
		}
		NLOG("}");
		break;
	case IFLA_INFO_SLAVE_DATA:
		mnl_attr_for_each_payload(mnl_attr_get_payload(a), mnl_attr_get_payload_len(a)) {
			print_info_slave_data_attr(attr, NULL);
		}
		NLOG("}");
		break;
	}
	return 0;
}

static int
print_vf_attr(const struct nlattr *a, void *data)
{
	struct ifla_vf_mac *mac;
	struct ifla_vf_vlan *vlan;
	struct ifla_vf_tx_rate *tx_rate;
	struct ifla_vf_spoofchk *spf;
	struct ifla_vf_rate *rate;
	struct ifla_vf_link_state *state;
	// struct ifla_vf_rss_query_en *query;
	struct ifla_vf_trust *vf_trust;
	struct ifla_vf_guid *vf_guid;

	int type = mnl_attr_get_type(a);
	static char *ifla[]= {
#define _(a) #a
		VF_ENUM
#undef _
	};

	if (mnl_attr_type_valid(a, IFLA_VF_MAX) < 0) {
		NLOG("mnl_attr_type_valid");
		return MNL_CB_OK;
	}
	NLOG(" {nla_len=%d, nla_type=%s, ", mnl_attr_get_len(a), ifla[type]);
	switch(type) {
	case IFLA_VF_MAC:
		mac = (struct ifla_vf_mac* )mnl_attr_get_payload(a);
		NLOG("(vf %d, mac", mac->vf);
		for (int i = 0; i < 32; i++) {
			NLOG(" 0x%02x", mac->mac[i]);
		}
		NLOG(")}");
		break;
	case IFLA_VF_VLAN:
		vlan = (struct ifla_vf_vlan *)mnl_attr_get_payload(a);
		NLOG("(vf %u, vlan %u, qos %u)}", vlan->vf, vlan->vlan, vlan->qos);
		break;
	case IFLA_VF_TX_RATE:
		tx_rate = (struct ifla_vf_tx_rate *)mnl_attr_get_payload(a);
		NLOG("(vf %u, rate %u)}", tx_rate->vf, tx_rate->rate);
		break;
	case IFLA_VF_SPOOFCHK:
		spf = (struct ifla_vf_spoofchk *)mnl_attr_get_payload(a);
		NLOG("(vf %u, setting %u)}", spf->vf, spf->setting);
		break;
	case IFLA_VF_LINK_STATE:
		state = (struct ifla_vf_link_state *)mnl_attr_get_payload(a);
		NLOG("(vf %u, link_state %u)", state->vf, state->link_state);
		break;
	case IFLA_VF_RATE:
		rate = (struct ifla_vf_rate *)mnl_attr_get_payload(a);
		NLOG("(vf %u, min_tx_rate %u, max_tx_rate %u)}", rate->vf, rate->min_tx_rate, rate->max_tx_rate);
		break;
	case IFLA_VF_TRUST:
		vf_trust = (struct ifla_vf_trust *)mnl_attr_get_payload(a);
		NLOG("(vf %u, setting %u)", vf_trust->vf, vf_trust->setting);
		break;
	case IFLA_VF_IB_NODE_GUID:
	case IFLA_VF_IB_PORT_GUID:
		vf_guid = (struct ifla_vf_guid *)mnl_attr_get_payload(a);
		NLOG("(vf %u, guid %llu)", vf_guid->vf, vf_guid->guid);
		break;
	}

	return 0;
}

static int
print_xdp_attr(const struct nlattr *a, void *data)
{
	int type = mnl_attr_get_type(a);
	static char *ifla[]= {
		"IFLA_XDP_UNSPEC",
		"IFLA_XDP_FD",
		"IFLA_XDP_ATTACHED",
		"IFLA_XDP_FLAGS",
		"IFLA_XDP_PROG_ID",
		"IFLA_XDP_DRV_PROG_ID",
		"IFLA_XDP_SKB_PROG_ID",
		"IFLA_XDP_HW_PROG_ID",
	};
	static char *attach[] = {
		"XDP_ATTACHED_NONE",
		"XDP_ATTACHED_DRV",
		"XDP_ATTACHED_SKB",
		"XDP_ATTACHED_HW",
		"XDP_ATTACHED_MULTI",
	};

	if (mnl_attr_type_valid(a, IFLA_XDP_MAX) < 0) {
		NLOG("mnl_attr_type_valid");
		return MNL_CB_OK;
	}
	NLOG(" {nla_len=%d, nla_type=%s, ", mnl_attr_get_len(a), ifla[type]);
	switch(type) {
	case IFLA_XDP_FD:
	case IFLA_XDP_PROG_ID:
	case IFLA_XDP_FLAGS:
	case IFLA_XDP_DRV_PROG_ID:
	case IFLA_XDP_SKB_PROG_ID:
	case IFLA_XDP_HW_PROG_ID:
		NLOG("%d}", mnl_attr_get_u32(a));
		break;
	case IFLA_XDP_ATTACHED:
		NLOG("%s}", attach[mnl_attr_get_u8(a)]);
		break;
	}
	return 0;
}

static int
print_af_attr(const struct nlattr *a, void *data)
{
	uint8_t *d;
	int type = mnl_attr_get_type(a);
	static char *ifla[] = {
		"IFLA_INET_UNSPEC",
		"IFLA_INET_CONF",
	};
	static char *ip4_devconf[] = {
		"IPV4_UNSPEC",
#define _(a) #a
		IPV4_DEVCONF_ENUM
#undef _
	};

	if (mnl_attr_type_valid(a, IFLA_INET_MAX) < 0) {
		NLOG("mnl_attr_type_valid");
		return MNL_CB_OK;
	}
	NLOG(" {nla_len=%d, nla_type=%s, ", mnl_attr_get_len(a), ifla[type]);
	switch(type) {
	case IFLA_INET_CONF:
		/* The format of IFLA_INET_CONF differs depending on the direction
		the attribute is sent. The attribute sent by the kernel consists
		of a u32 array, basically a 1:1 copy of in_device->cnf.data[].
		The attribute expected by the kernel must consist of a sequence
		of nested u32 attributes, each representing a change request,*/
		d = (uint8_t *)mnl_attr_get_payload(a);
		for(size_t i = 0; i < mnl_attr_get_payload_len(a); i+=4) {
			NLOG("%s[%s] = %u", (i==0)?" ":", ", ip4_devconf[i/4+1], *(uint32_t *)(d + i));
		}
		NLOG("}");
		break;
	}
	return 0;
}

static int
print_af6_attr(const struct nlattr *a, void *data)
{
	uint8_t *d;
	char ip6[64];
	struct ifla_cacheinfo *cache;
	struct in6_addr *token;
	int type = mnl_attr_get_type(a);
	static char *ifla[] = {
		"IFLA_INET6_UNSPEC",
		"IFLA_INET6_FLAGS",
		"IFLA_INET6_CONF",
		"IFLA_INET6_STATS",
		"IFLA_INET6_MCAST",
		"IFLA_INET6_CACHEINFO",
		"IFLA_INET6_ICMP6STATS",
		"IFLA_INET6_TOKEN",
		"IFLA_INET6_ADDR_GEN_MODE",
	};
	static char *ipv6_devconf[] = {
#define _(a) #a
		IPV6_DEVCONF_ENUM
#undef _
	};
	static char *ip6_stats[] = {
#define _(a) #a
		IPSTATS_ENUM
#undef _
	};
	static char *icmp6_stats[] = {
		"ICMP6_MIB_NUM",
		"ICMP6_MIB_INMSGS",
		"ICMP6_MIB_INERRORS",
		"ICMP6_MIB_OUTMSGS",
		"ICMP6_MIB_OUTERRORS",
		"ICMP6_MIB_CSUMERRORS",
	};

	if (mnl_attr_type_valid(a, IFLA_INET6_MAX) < 0) {
		NLOG("mnl_attr_type_valid");
		return MNL_CB_OK;
	}
	NLOG(" {nla_len=%d, nla_type=%s, ", mnl_attr_get_len(a), ifla[type]);
	switch(type) {
	case IFLA_INET6_FLAGS:
		NLOG("0x%x}", mnl_attr_get_u32(a));
		break;
	case IFLA_INET6_CONF:
		d = (uint8_t *)mnl_attr_get_payload(a);
		for(size_t i = 0; i < mnl_attr_get_payload_len(a); i += 4) {
			NLOG("%s[%s] = %u", (i == 0) ? " " : ", ", ipv6_devconf[i/4], *(uint32_t *)(d + i));
		}
		NLOG("}");
		break;
	case IFLA_INET6_CACHEINFO:
		cache = (struct ifla_cacheinfo *)mnl_attr_get_payload(a);
		NLOG("(max_reasm_len %u, tstamp %u, reachable_time %u, retrans_time %u)",
			cache->max_reasm_len, cache->tstamp, cache->reachable_time, cache->retrans_time);
		NLOG("}");
		break;
	case IFLA_INET6_STATS:
		d = (uint8_t *)mnl_attr_get_payload(a);
		for (size_t i = 0; i < mnl_attr_get_payload_len(a); i += 8) {
			NLOG("%s[%s] = %lu", (i == 0) ? " " : ", ", ip6_stats[i/8], *(uint64_t *)(d + i));
		}
		NLOG("}");
		break;
	case IFLA_INET6_ICMP6STATS:
		d = (uint8_t *)mnl_attr_get_payload(a);
		for (size_t i = 0; i < mnl_attr_get_payload_len(a); i += 8) {
			NLOG("%s[%s] = %lu", (i == 0) ? " ": ", ", icmp6_stats[i/8], *(uint64_t *)(d + i));
		}
		NLOG("}");
		break;
	case IFLA_INET6_TOKEN:
		token = (struct in6_addr *)mnl_attr_get_payload(a);
		inet_ntop(AF_INET6, token, ip6, 64);
		NLOG("%s}", ip6);
		break;
	case IFLA_INET6_ADDR_GEN_MODE:
		NLOG("%u}", mnl_attr_get_u8(a));
		break;
	}
	return 0;
}

/* for type and length see https://elixir.bootlin.com/linux/v5.14-rc6/source/net/core/rtnetlink.c#L1844*/
static int
print_link_attr(const struct nlattr *a, void *data)
{
	struct nlattr *pos, *attr;
	struct rtnl_link_ifmap *map;
	struct rtnl_link_stats *stats;
	struct rtnl_link_stats64 *stats64;
	uint8_t * mac;

	int type = mnl_attr_get_type(a);
	static char *ifla[] = {
#define _(a) #a
		IFLA_ENUM
#undef _
	};

	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(a, IFLA_MAX) < 0) {
		NLOG("mnl_attr_type_valid");
		return MNL_CB_OK;
	}
	NLOG(" {nla_len=%d, nla_type=%s, ", mnl_attr_get_len(a), ifla[type]);
	switch (type) {
	case IFLA_LINKMODE:
	case IFLA_PROTO_DOWN:
	case IFLA_OPERSTATE:
		NLOG("%d}", mnl_attr_get_u8(a));
		break;
	case IFLA_MTU:
	case IFLA_LINK:
	case IFLA_MASTER:
	case IFLA_TXQLEN:
	case IFLA_WEIGHT:
	case IFLA_NET_NS_PID:
	case IFLA_NUM_VF:
	case IFLA_EXT_MASK:
	case IFLA_EVENT:
	case IFLA_GROUP:
	case IFLA_NET_NS_FD:
	case IFLA_PROMISCUITY:
	case IFLA_NUM_TX_QUEUES:
	case IFLA_NUM_RX_QUEUES:
	case IFLA_CARRIER_CHANGES:
	case IFLA_LINK_NETNSID:
	case IFLA_GSO_MAX_SEGS:
	case IFLA_GSO_MAX_SIZE:
	case IFLA_CARRIER_DOWN_COUNT:
	case IFLA_CARRIER_UP_COUNT:
	case IFLA_MIN_MTU:
	case IFLA_MAX_MTU:
		NLOG("%d}", mnl_attr_get_u32(a));
		break;
	case IFLA_IFNAME:
	case IFLA_IFALIAS:
	case IFLA_QDISC:
	case IFLA_PHYS_PORT_NAME:
		NLOG("%s}", mnl_attr_get_str(a));
		break;
	case IFLA_PHYS_PORT_ID:
	case IFLA_PHYS_SWITCH_ID:
		mac = (uint8_t* )mnl_attr_get_payload(a);
		for (int i = 0; i < mnl_attr_get_payload_len(a); i++) {
			NLOG("%02x", mac[i]);
		}
		NLOG("}");
		break;
	case IFLA_ADDRESS:
	case IFLA_BROADCAST:
		mac = (uint8_t* )mnl_attr_get_payload(a);
		for(int i = 0; i < mnl_attr_get_payload_len(a); i++) {
            NLOG("%02x%s", mac[i], i < 5 ? ":":"");
		}
		NLOG("}");
		break;
	case IFLA_MAP:
		map = (struct rtnl_link_ifmap *)mnl_attr_get_payload(a);
		NLOG("(mem_start 0x%llx, mem_end 0x%llx, base_addr 0x%llx, irq %u, dma %u, port %u)}",
			map->mem_start, map->mem_end, map->base_addr, map->irq, map->dma, map->port);
		break;
	case IFLA_STATS:
		stats = (struct rtnl_link_stats *)mnl_attr_get_payload(a);
		NLOG("(rx_packets %u, tx_packets %u, rx_bytes %u, tx_bytes %u, rx_errors %u,"
				" tx_errors %u, rx_dropped %u, tx_dropped %u, multicast %u, collisions %u,"
				" rx_length_errors %u, rx_over_errors %u, rx_crc_errors %u, rx_frame_errors %u,"
				" rx_fifo_errors %u, rx_missed_errors %u, tx_aborted_errors %u, tx_carrier_errors %u,"
				" tx_fifo_errors %u, tx_heartbeat_errors %u, tx_window_errors %u, rx_compressed %u,"
				" tx_compressed %u, rx_nohandler %u)",
				stats->rx_packets, stats->tx_packets, stats->rx_bytes, stats->tx_bytes,
				stats->rx_errors, stats->tx_errors, stats->rx_dropped, stats->tx_dropped,
				stats->multicast, stats->collisions, stats->rx_length_errors, stats->rx_over_errors,
				stats->rx_crc_errors, stats->rx_frame_errors, stats->rx_fifo_errors, stats->rx_missed_errors,
				stats->tx_aborted_errors, stats->tx_carrier_errors, stats->tx_fifo_errors, 
				stats->tx_heartbeat_errors, stats->tx_window_errors,
				stats->rx_compressed, stats->tx_compressed, stats->rx_nohandler);
		NLOG("}");
		break;
	case IFLA_STATS64:
		stats64 = (struct rtnl_link_stats64 *)mnl_attr_get_payload(a);
		NLOG("(rx_packets %llu, tx_packets %llu, rx_bytes %llu, tx_bytes %llu, rx_errors %llu,"
				" tx_errors %llu, rx_dropped %llu, tx_dropped %llu, multicast %llu, collisions %llu,"
				" rx_length_errors %llu, rx_over_errors %llu, rx_crc_errors %llu, rx_frame_errors %llu,"
				" rx_fifo_errors %llu, rx_missed_errors %llu, tx_aborted_errors %llu, tx_carrier_errors %llu,"
				" tx_fifo_errors %llu, tx_heartbeat_errors %llu, tx_window_errors %llu, rx_compressed %llu,"
				" tx_compressed %llu, rx_nohandler %llu)",
				stats64->rx_packets, stats64->tx_packets, stats64->rx_bytes, stats64->tx_bytes,
				stats64->rx_errors, stats64->tx_errors, stats64->rx_dropped, stats64->tx_dropped,
				stats64->multicast, stats64->collisions, stats64->rx_length_errors, stats64->rx_over_errors,
				stats64->rx_crc_errors, stats64->rx_frame_errors, stats64->rx_fifo_errors, stats64->rx_missed_errors,
				stats64->tx_aborted_errors, stats64->tx_carrier_errors, stats64->tx_fifo_errors, 
				stats64->tx_heartbeat_errors, stats64->tx_window_errors,
				stats64->rx_compressed, stats64->tx_compressed, stats64->rx_nohandler);
		NLOG("}");
		break;
	case IFLA_LINKINFO:
		mnl_attr_for_each_payload(mnl_attr_get_payload(a), mnl_attr_get_payload_len(a)) {
			print_info_attr(attr, NULL);
		}
		NLOG("}");
		break;
	case IFLA_VFINFO_LIST:
		mnl_attr_parse_nested(a, print_vf_attr, NULL);
		
		// mnl_attr_parse_payload(mnl_attr_get_payload(a), mnl_attr_get_payload_len(a), , data);
		NLOG("}");
		break;
	case IFLA_VF_PORTS:
	case IFLA_AF_SPEC:
		/*   [IFLA_AF_SPEC] = {
		*       [AF_INET] = {
		*           [IFLA_INET_CONF] = ...,
		*       },
		*       [AF_INET6] = {
		*           [IFLA_INET6_FLAGS] = ...,
		*           [IFLA_INET6_CONF] = ...,
		*       }
		*   }
		*/
		mnl_attr_for_each_nested(pos, a) {
			NLOG("{nla_len=%d", mnl_attr_get_len(pos));
			if (AF_INET == mnl_attr_get_type(pos)) {
				NLOG(" nla_type=AF_INET,");
				mnl_attr_parse_payload(mnl_attr_get_payload(pos), mnl_attr_get_payload_len(pos), print_af_attr, NULL);
				NLOG("} ");
			} else if(AF_INET6 == mnl_attr_get_type(pos)) {
				NLOG(" nla_type=AF_INET6,");
				mnl_attr_for_each_payload(mnl_attr_get_payload(pos), mnl_attr_get_payload_len(pos)) {
					print_af6_attr(attr, NULL);
				}
				NLOG("}");
			}
		}
		break;
	case IFLA_PORT_SELF:
	case IFLA_XDP:
		mnl_attr_parse_nested(a, print_xdp_attr, data);
		NLOG("}");
		break;
	default:
		NLOG("type=%s: %d",ifla[type], mnl_attr_get_len(a) - 4);
		break;
	}
	return MNL_CB_OK;
}

static int
print_ns_attr(const struct nlattr *a, void *data)
{
	int type = mnl_attr_get_type(a);
	static char *nsa[] = {
		"NETNSA_NONE",
		"NETNSA_NSID",
		"NETNSA_PID",
		"NETNSA_FD",
		"NETNSA_TARGET_NSID",
		"NETNSA_CURRENT_NSID",
	};

	if (mnl_attr_type_valid(a, NETNSA_MAX) < 0) {
		NLOG("mnl_attr_type_valid");
		return MNL_CB_OK;
	}
	NLOG(" {nla_len=%d, nla_type=%s, ", mnl_attr_get_len(a), nsa[type]);
	switch(type) {
		case NETNSA_NSID:
		case NETNSA_PID:
		case NETNSA_FD:
		case NETNSA_TARGET_NSID:
		case NETNSA_CURRENT_NSID:
			NLOG("%u}", mnl_attr_get_u32(a));
			break;
	}

	return MNL_CB_OK;
}

static int print_ndta_para_attr(const struct nlattr *a, void *data)
{
	int type = mnl_attr_get_type(a);
	static char *ndta[] = {
		"NDTPA_IFINDEX",			/* u32, unchangeable */
		"NDTPA_REFCNT",			/* u32, read-only */
		"NDTPA_REACHABLE_TIME",		/* u64, read-only, msecs */
		"NDTPA_BASE_REACHABLE_TIME",	/* u64, msecs */
		"NDTPA_RETRANS_TIME",		/* u64, msecs */
		"NDTPA_GC_STALETIME",		/* u64, msecs */
		"NDTPA_DELAY_PROBE_TIME",		/* u64, msecs */
		"NDTPA_QUEUE_LEN",		/* u32 */
		"NDTPA_APP_PROBES",		/* u32 */
		"NDTPA_UCAST_PROBES",		/* u32 */
		"NDTPA_MCAST_PROBES",		/* u32 */
		"NDTPA_ANYCAST_DELAY",		/* u64, msecs */
		"NDTPA_PROXY_DELAY",		/* u64, msecs */
		"NDTPA_PROXY_QLEN",		/* u32 */
		"NDTPA_LOCKTIME",			/* u64, msecs */
		"NDTPA_QUEUE_LENBYTES",		/* u32 */
		"NDTPA_MCAST_REPROBES",		/* u32 */
		"NDTPA_PAD",
	};

	NLOG(" {nla_len=%d, nla_type=%s, ", mnl_attr_get_len(a), ndta[type]);
	if (mnl_attr_type_valid(a, NDTPA_MAX) < 0)
		return MNL_CB_OK;
	
	switch(type) {
		case NDTPA_IFINDEX:
		case NDTPA_QUEUE_LEN:
		case NDTPA_PROXY_QLEN:
		case NDTPA_APP_PROBES:
		case NDTPA_UCAST_PROBES:
		case NDTPA_MCAST_PROBES:
		case NDTPA_MCAST_REPROBES:
			NLOG("%u}", mnl_attr_get_u32(a));
			break;
		case NDTPA_BASE_REACHABLE_TIME:
		case NDTPA_GC_STALETIME:
		case NDTPA_DELAY_PROBE_TIME:
		case NDTPA_RETRANS_TIME:
		case NDTPA_ANYCAST_DELAY:
		case NDTPA_PROXY_DELAY:
		case NDTPA_LOCKTIME:
			NLOG("%lu}", mnl_attr_get_u64(a));
			break;
	}
	return MNL_CB_OK;
}
static int
print_netconf_attr(const struct nlattr *a, void *data)
{
	int type = mnl_attr_get_type(a);
	static char *nta[] = {
		"NETCONFA_UNSPEC",
		"NETCONFA_IFINDEX",
		"NETCONFA_FORWARDING",
		"NETCONFA_RP_FILTER",
		"NETCONFA_MC_FORWARDING",
		"NETCONFA_PROXY_NEIGH",
		"NETCONFA_IGNORE_ROUTES_WITH_LINKDOWN",
		"NETCONFA_INPUT",
		"NETCONFA_BC_FORWARDING",
	};
	if (mnl_attr_type_valid(a, NETCONFA_MAX) < 0)
		return MNL_CB_OK;
	
	NLOG(" {nla_len=%d, nla_type=%s, ", mnl_attr_get_len(a), nta[type]);
	switch(type) {
		case NETCONFA_IFINDEX:
		case NETCONFA_FORWARDING:
		case NETCONFA_RP_FILTER:
		case NETCONFA_MC_FORWARDING:
		case NETCONFA_PROXY_NEIGH:
		case NETCONFA_IGNORE_ROUTES_WITH_LINKDOWN:
		case NETCONFA_INPUT:
		case NETCONFA_BC_FORWARDING:
			NLOG("%u}", mnl_attr_get_u32(a));
			break;

	}

	return MNL_CB_OK;
}
static int
print_ndtm_attr(const struct nlattr *a, void *data)
{
	int type = mnl_attr_get_type(a);
	static char *ndta[] = {
		"NDTA_UNSPEC",
		"NDTA_NAME",			/* char *, unchangeable */
		"NDTA_THRESH1",			/* u32 */
		"NDTA_THRESH2",			/* u32 */
		"NDTA_THRESH3",			/* u32 */
		"NDTA_CONFIG",			/* struct ndt_config, read-only */
		"NDTA_PARMS",			/* nested TLV NDTPA_* */
		"NDTA_STATS",			/* struct ndt_stats, read-only */
		"NDTA_GC_INTERVAL",		/* u64, msecs */
		"NDTA_PAD",
	};

	if (mnl_attr_type_valid(a, NDTA_MAX) < 0)
		return MNL_CB_OK;
	
	NLOG(" {nla_len=%d, nla_type=%s, ", mnl_attr_get_len(a), ndta[type]);
	switch(type) {
		case NDTA_NAME:
			NLOG("%s}", mnl_attr_get_str(a));
			break;
		case NDTA_THRESH1:
		case NDTA_THRESH2:
		case NDTA_THRESH3:
			NLOG("%u}", mnl_attr_get_u32(a));
			break;
		case NDTA_GC_INTERVAL:
			NLOG("%lu}", mnl_attr_get_u64(a));
			break;
		case NDTA_PARMS:
			mnl_attr_parse_nested(a, print_ndta_para_attr, data);
			NLOG("}");
			break;
	}
	return MNL_CB_OK;
}

static int
print_route_attr(const struct nlattr *a, void *data)
{
	int type = mnl_attr_get_type(a);
	static char *rta[] = {
#define _(a) #a
		RTA_ENUM
#undef _		
	};
	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(a, RTA_MAX) < 0)
		return MNL_CB_OK;
	
	NLOG(" {nla_len=%d, nla_type=%s, ", mnl_attr_get_len(a), rta[type]);
	switch(type) {
		case RTA_TABLE:
		case RTA_DST:
		case RTA_SRC:
		case RTA_OIF:
		case RTA_FLOW:
		case RTA_PREFSRC:
		case RTA_GATEWAY:
			if (mnl_attr_validate(a, MNL_TYPE_U32) < 0) {
				perror("mnl_attr_validate");
				return MNL_CB_ERROR;
			}
			NLOG("%u}", mnl_attr_get_u32(a));
			break;
		case RTA_METRICS:
			if (mnl_attr_validate(a, MNL_TYPE_NESTED) < 0) {
				perror("mnl_attr_validate");
				return MNL_CB_ERROR;
			}
			NLOG("}");
			break;
	}
	return MNL_CB_OK;
}

static int
print_addr_attr(const struct nlattr *a, void *data)
{
	struct ifa_cacheinfo *cache;
	int type = mnl_attr_get_type(a);
	static char * ifa[] = {
		"IFA_UNSPEC",
		"IFA_ADDRESS",
		"IFA_LOCAL",
		"IFA_LABEL",
		"IFA_BROADCAST",
		"IFA_ANYCAST",
		"IFA_CACHEINFO",
		"IFA_MULTICAST",
		"IFA_FLAGS",
		"IFA_RT_PRIORITY",
		"IFA_TARGET_NETNSID"
	};
	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(a, IFA_MAX) < 0)
		return MNL_CB_OK;

	NLOG(" {nla_len=%d, nla_type=%s, ", mnl_attr_get_len(a), ifa[type]);
	switch(type) {
	case IFA_ADDRESS:
	case IFA_LOCAL:
		NLOG("%u}", *(uint32_t*)mnl_attr_get_payload(a));
		break;
	case IFA_LABEL:
		NLOG("%s}", mnl_attr_get_str(a));
		/* FALLTHROUGH */
	case IFA_CACHEINFO:
		cache = (struct ifa_cacheinfo *)mnl_attr_get_payload(a);
		NLOG("(ifa_prefered %u, ifa_valid %u, cstamp %u, tstamp %u)", cache->ifa_prefered,
			cache->ifa_valid, cache->cstamp, cache->tstamp);
		break;
	case IFA_BROADCAST:
	case IFA_FLAGS:
	case IFA_TARGET_NETNSID:
	case IFA_RT_PRIORITY:
		NLOG("%u}", mnl_attr_get_u32(a));
		break;
	}
	return 0;
}

static int
print_nd_attr(const struct nlattr *a, void *data)
{
	uint8_t *addr;
	char buff[32];
	struct nda_cacheinfo *cache;
	int type = mnl_attr_get_type(a);
	static char *nda[] = {
		"NDA_UNSPEC",
		"NDA_DST",
		"NDA_LLADDR",
		"NDA_CACHEINFO",
		"NDA_PROBES",
		"NDA_VLAN",
		"NDA_PORT",
		"NDA_VNI",
		"NDA_IFINDEX",
		"NDA_MASTER",
		"NDA_LINK_NETNSID",
		"NDA_SRC_VNI",
		"NDA_PROTOCOL",
	};

	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(a, IFA_MAX) < 0)
		return MNL_CB_OK;

	NLOG(" {nla_len=%d, nla_type=%s, ", mnl_attr_get_len(a), nda[type]);
	switch(type) {
		case NDA_DST:
		case NDA_LLADDR:
			addr = (uint8_t *)mnl_attr_get_payload(a);
			if (mnl_attr_get_payload_len(a) == 4) {
				inet_ntop(AF_INET, addr, buff, 32);
				NLOG(" %s", buff);
			} else {
				inet_ntop(AF_INET6, addr, buff, 32);
				NLOG(" %s", buff);
			}
			NLOG("}");
			break;
		case NDA_CACHEINFO:
			cache = (struct nda_cacheinfo *)mnl_attr_get_payload(a);
			NLOG("(ndm_confirmed %u, ndm_used %u, ndm_updated %u, ndm_refcnt %u)}",
			cache->ndm_confirmed, cache->ndm_used, cache->ndm_updated, cache->ndm_refcnt);
			break;
		case NDA_PROBES:
		case NDA_VNI:
		case NDA_SRC_VNI:
		case NDA_IFINDEX:
		case NDA_MASTER:
		case NDA_LINK_NETNSID:
			NLOG("%u}", mnl_attr_get_u32(a));
			break;
		case NDA_VLAN:
		case NDA_PORT:
			NLOG("%u}", mnl_attr_get_u16(a));
			break;
		case NDA_PROTOCOL:
			NLOG("%u}", mnl_attr_get_u8(a));
			break;
	}

	return 0;
}

static int
print_fib_rule_attr(const struct nlattr *a, void *data)
{
	uint8_t *addr;
	char buff[32];
	struct fib_rule_port_range *range;
	static char* fra[] = {
#define _(a) #a
		FRA_ENUM
#undef _
	};
	int type = mnl_attr_get_type(a);
	NLOG(" {nla_len=%d, nla_type=%s, ", mnl_attr_get_len(a), fra[type]);
	switch(type) {
		case FRA_DST:
		case FRA_SRC:
			addr = (uint8_t *)mnl_attr_get_payload(a);
			inet_ntop(AF_INET, addr, buff, 32);
			NLOG("%s}", buff);
			break;
		case FRA_TABLE:
		case FRA_SUPPRESS_PREFIXLEN:
		case FRA_SUPPRESS_IFGROUP:
		case FRA_FWMARK:
		case FRA_FWMASK:
			NLOG("%u}", mnl_attr_get_u32(a));
			break;
		case FRA_PROTOCOL:
		case FRA_IP_PROTO:
			NLOG("%u}", mnl_attr_get_u8(a));
			break;
		case FRA_SPORT_RANGE:
		case FRA_DPORT_RANGE:
			range = (struct fib_rule_port_range *)mnl_attr_get_payload(a);
			NLOG("(start %u, end %u)}", range->start, range->end);
			break;
		case FRA_IIFNAME:
		case FRA_OIFNAME:
			NLOG("%s}", mnl_attr_get_str(a));
			break;
	}
	
	return 0;
}

static int
print_rtmsg(void *msg)
{
	struct rtmsg * rt = (struct rtmsg *)msg;
	static char *afname[] = {
#define _(a) #a
		ADDR_FAMILY_ENUM
#undef _
	};
	static char *tables[] = {
		[0] = "RT_TABLE_UNSPEC",
		[252] = "RT_TABLE_COMPAT",
		[253] = "RT_TABLE_DEFAULT",
		[254] = "RT_TABLE_MAIN",
		[255] = "RT_TABLE_LOCAL",
	};
	static char *types[] = {
		"RTN_UNSPEC",
		"RTN_UNICAST",
		"RTN_LOCAL",
		"RTN_BROADCAST",
		"RTN_ANYCAST",
		"RTN_MULTICAST",
		"RTN_BLACKHOLE",
		"RTN_UNREACHABLE",
		"RTN_PROHIBIT"
		"RTN_THROW",
		"RTN_NAT",
		"RTN_XRESOLVE"
	};
	static char *scope[] = {
		[0] = "RT_SCOPE_UNIVERSE",
		[200] = "RT_SCOPE_SITE",
		[253] = "RT_SCOPE_LINK",
		[254] = "RT_SCOPE_HOST",
		[255] = "RT_SCOPE_NOWHERE",
	};
	static char *proto[] = {
		[0] = "RTPROT_UNSPEC",
		[1] = "RTPROT_REDIRECT",
		[2] = "RTPROT_KERNEL",
		[3] = "RTPROT_BOOT",
		[4] = "RTPROT_STATIC",
		/* Values of protocol >= RTPROT_STATIC are not interpreted by kernel*/
	};
	NLOG("{rtm_family=%s, rtm_dst_len=%u, rtm_src_len=%u, rtm_tos=%u, rtm_table=%s,"
		" rtm_protocol=%s, rtm_scope=%s, rtm_type=%s, rtm_flags=0x%x}",
		afname[rt->rtm_family], rt->rtm_dst_len, rt->rtm_src_len, rt->rtm_tos,
		tables[rt->rtm_table], proto[rt->rtm_protocol], scope[rt->rtm_scope], types[rt->rtm_type], rt->rtm_flags);
	return 0;
}

static int 
print_ifinfomsg(void *msg)
{
	struct ifinfomsg *ifm = (struct ifinfomsg *)msg;
	char if_name[IFNAMSIZ] = {'\0'};
	struct iff_flag {
		unsigned int flag;
		const char *name;
	};
	static const struct iff_flag flags[] = {
		{ IFF_UP, "UP", },
		{ IFF_BROADCAST, "BROADCAST", },
		{ IFF_DEBUG, "DEBUG", },
		{ IFF_LOOPBACK, "LOOPBACK", },
		{ IFF_POINTOPOINT, "POINTOPOINT", },
		{ IFF_NOTRAILERS, "NOTRAILERS", },
		{ IFF_RUNNING, "RUNNING", },
		{ IFF_NOARP, "NOARP", },
		{ IFF_PROMISC, "PROMISC", },
		{ IFF_ALLMULTI, "ALLMULTI", },
		{ IFF_MASTER, "MASTER", },
		{ IFF_SLAVE, "SLAVE", },
		{ IFF_MULTICAST, "MULTICAST", },
		{ IFF_PORTSEL, "PORTSEL", },
		{ IFF_AUTOMEDIA, "AUTOMEDIA", },
		{ IFF_DYNAMIC, "DYNAMIC", },
	};
	static char *afname[] = {
#define _(a) #a
		ADDR_FAMILY_ENUM
#undef _
	};
	if (ifm->ifi_index != 0)
		if_indextoname(ifm->ifi_index, if_name);
	NLOG("{ifi_family=%s, ifi_type=%u, ifi_index=%d(if_nametoindex(\"%s\")), ifi_flags=0x%x(",
		afname[ifm->ifi_family], ifm->ifi_type, ifm->ifi_index, if_name, ifm->ifi_flags);
	for (size_t i = 0; i < MNL_ARRAY_SIZE(flags); i++) {
		if (ifm->ifi_flags & flags[i].flag) {
			NLOG(" %s", flags[i].name);
		}
	}
	NLOG("), ifi_change=%u}", ifm->ifi_change);

	return 0;
}

static int
print_ifaddrmsg(void *msg)
{
	static char *afname[] = {
#define _(a) #a
		ADDR_FAMILY_ENUM
#undef _
	};
	static char *scope[] = {
		[0] = "RT_SCOPE_UNIVERSE",
		[200] = "RT_SCOPE_SITE",
		[253] = "RT_SCOPE_LINK",
		[254] = "RT_SCOPE_HOST",
		[255] = "RT_SCOPE_NOWHERE",
	};
	struct ifaddrmsg* ifa = (struct ifaddrmsg *) msg;

	NLOG("{ifa_family=%s, ifa_prefixlen=%u, ifa_flags=%u, ifa_scope=%s, ifa_index=%u}",
		afname[ifa->ifa_family], ifa->ifa_prefixlen, ifa->ifa_flags, scope[ifa->ifa_scope], ifa->ifa_index);
	
	return 0;
}

static int
print_ndmsg(void *msg)
{
	static char *afname[] = {
#define _(a) #a
		ADDR_FAMILY_ENUM
#undef _
	};
	static char *states[] = {
		[0] = "NUD_NONE",
		[1] = "NUD_INCOMPLETE",
		[2] = "NUD_REACHABLE",
		[4] = "NUD_STALE",
		[8] = "NUD_DELAY",
 		[16] = "NUD_PROBE",
 		[0x20] = "NUD_FAILED",
 		[0x40] = "NUD_NOARP",
		[0x80] = "NUD_PERMANENT",
	};
	static char *rte_type[] = {
		"RTN_UNSPEC",
		"RTN_UNICAST",
		"RTN_LOCAL",
		"RTN_BROADCAST",
		"RTN_ANYCAST",
		"RTN_MULTICAST",
		"RTN_BLACKHOLE",
		"RTN_UNREACHABLE",
		"RTN_PROHIBIT",
		"RTN_THROW",
		"RTN_NAT",
		"RTN_XRESOLVE",
	};
	char if_name[IF_NAMESIZE] = {'\0'};
	struct ndmsg *nd = (struct ndmsg *)msg;
	if (nd->ndm_ifindex!=0)
		if_indextoname(nd->ndm_ifindex, if_name);
	NLOG("{ndm_family=%s, ndm_ifindex=%u(if_nametoindex(\"%s\")), ndm_state=%s, ndm_flags=%u, ndm_type=%s}", 
		afname[nd->ndm_family], nd->ndm_ifindex, if_name, states[nd->ndm_state], nd->ndm_flags, rte_type[nd->ndm_type]);

	return 0;
}

static int
print_rulemsg(void *msg)
{
	static char *afname[] = {
#define _(a) #a
		ADDR_FAMILY_ENUM
#undef _
	};
	static char *actions[] = {
		"FR_ACT_UNSPEC",
		"FR_ACT_TO_TBL",
		"FR_ACT_GOTO",
		"FR_ACT_NOP",
		"FR_ACT_RES3",
		"FR_ACT_RES4",
		"FR_ACT_BLACKHOLE",
		"FR_ACT_UNREACHABLE",
		"FR_ACT_PROHIBIT",
	};
	struct fib_rule_hdr *frh = (struct fib_rule_hdr *)msg;
	NLOG("{family=%s, dst_len=%u, src_len=%u, tos=%u, table=%u, action=%s, flags=%u}",
		afname[frh->family], frh->dst_len, frh->src_len, frh->tos, frh->table,
		actions[frh->action], frh->flags);
	return 0;
}

static int
print_nlmsghdr(const struct nlmsghdr *nlh)
{
	static char * msgtype[] = {
		[1] = "NLMSG_NOOP",
		[2] = "NLMSG_ERROR",
		[3] = "NLMSG_DONE",
		[4] = "NLMSG_OVERRUN",
#define _(a, v)  [v] = #a
		RTM_TYPE_ENUM
#undef _
	};
	static char * flags[] = {
		[0] = "NLM_F_REQUEST",
		[1] = "NLM_F_MULTI",
		[2] = "NLM_F_ACK",
		[3] = "NLM_F_ECHO",
		[4] = "NLM_F_DUMP_INTR",
		[5] = "NLM_F_DUMP_FILTERED",
		[6] = "NLM_F_ROOT",
		[7] = "NLM_F_MATCH",
		[8] = "NLM_F_ATOMIC",
		[10] = "NLM_F_REPLACE",
		[11] = "NLM_F_EXCL",
		[12] = "NLM_F_CREATE",
		[13] = "NLM_F_APPEND",
	};
	NLOG("{len=%d, type=%d(%s), flags=%d(",nlh->nlmsg_len, nlh->nlmsg_type,
		msgtype[nlh->nlmsg_type], nlh->nlmsg_flags);
	for(size_t i = 0; i < MNL_ARRAY_SIZE(flags); i ++) {
		if (nlh->nlmsg_flags & (1 << i)) {
			NLOG("%s ", flags[i]);
		}
	}
	NLOG("), seq=%u, pid=%u}, ",  nlh->nlmsg_seq, nlh->nlmsg_pid);
	return nlh->nlmsg_type;
}

static int
netlink_cb(const struct nlmsghdr *nlh, void *data)
{
	struct rtgenmsg *rnmsg;
	struct ndtmsg *ndtmsg;
	struct netconfmsg *ncm;
	void *msg = mnl_nlmsg_get_payload(nlh);
	
	int type = print_nlmsghdr(nlh);
	if (type <= NLMSG_MIN_TYPE) {
		hexdump(msg, mnl_nlmsg_get_payload_len(nlh));
	}
	switch (type) {
		case RTM_NEWLINK:
		case RTM_DELLINK:
		case RTM_GETLINK:
		case RTM_SETLINK:
			print_ifinfomsg(msg);
			NLOG("{");
			mnl_attr_parse(nlh, sizeof(struct ifinfomsg), print_link_attr, NULL);
			NLOG("}");
			break;
		case RTM_NEWADDR:
		case RTM_DELADDR:
		case RTM_GETADDR:
			print_ifaddrmsg(msg);
			NLOG("{");
			mnl_attr_parse(nlh, sizeof(struct ifaddrmsg), print_addr_attr, NULL);
			NLOG("}");
			break;
		case RTM_NEWROUTE:
		case RTM_DELROUTE:
		case RTM_GETROUTE:
			print_rtmsg(msg);
			NLOG("{");
			mnl_attr_parse(nlh, sizeof(struct rtmsg), print_route_attr, NULL);
			NLOG("}");
			break;
		case RTM_NEWNEIGH:
		case RTM_DELNEIGH:
		case RTM_GETNEIGH:
			print_ndmsg(msg);
			NLOG("{");
			mnl_attr_parse(nlh, sizeof(struct ndmsg), print_nd_attr, NULL);
			NLOG("}");
			break;
		case RTM_NEWRULE:
		case RTM_DELRULE:
		case RTM_GETRULE:
			print_rulemsg(msg);
			NLOG("{");
			mnl_attr_parse(nlh, sizeof(struct fib_rule_hdr), print_fib_rule_attr, NULL);
			NLOG("}");
			break;
		case RTM_NEWNSID:
		case RTM_DELNSID:
		case RTM_GETNSID:
			rnmsg = (struct rtgenmsg *)msg;
			NLOG("{rtgen_family=%d}", rnmsg->rtgen_family);
			NLOG("{");
			mnl_attr_parse(nlh, sizeof(struct rtgenmsg), print_ns_attr, NULL);
			NLOG("}");
			break;
		case RTM_NEWNEIGHTBL:
		case RTM_GETNEIGHTBL:
		case RTM_SETNEIGHTBL:
			ndtmsg = (struct ndtmsg *)msg;
			NLOG("{ndtm_family=%u}", ndtmsg->ndtm_family);
			NLOG("{");
			mnl_attr_parse(nlh, sizeof(struct ndtmsg), print_ndtm_attr, NULL);
			NLOG("}");
			break;
		case RTM_NEWNETCONF:
		case RTM_DELNETCONF:
		case RTM_GETNETCONF:
			ncm = (struct netconfmsg *)msg;
			NLOG("{ncm_family=%u}", ncm->ncm_family);
			NLOG("{");
			mnl_attr_parse(nlh, sizeof(struct netconfmsg), print_netconf_attr, NULL);
			NLOG("}");
			break;
	}
	NLOG("\n");
	
	return MNL_CB_OK;
}

static int
ppp_cb(const struct nlmsghdr *nlh, void *data)
{
	struct genlmsghdr *ghr;
	void *msg = mnl_nlmsg_get_payload(nlh);
	print_nlmsghdr(nlh);
	ghr = (struct genlmsghdr *) msg;
	printf("{cmd=%u, version=%u}", ghr->cmd, ghr->version);
	hexdump(msg, mnl_nlmsg_get_payload_len(nlh));
	NLOG("\n");
	return MNL_CB_OK;
}

static const int fatal_signals[] = { SIGINT, SIGTERM, SIGHUP, SIGALRM,
									SIGSEGV, SIGABRT};
static bool running = true;

void
fatal_signal_handler(int sig_nr)
{
	running = false;
}

/* ip l add nlmon0 type nlmon */
void
create_nlmon(void)
{
	int ret;
	int one = 1;
	uint8_t buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq = time(NULL);
	struct ifinfomsg *ifm = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifm));
	ifm->ifi_family = AF_UNSPEC;
	ifm->ifi_change = IFF_UP;
	ifm->ifi_flags = IFF_UP;

	struct mnl_socket *nl;
	nl = mnl_socket_open(NETLINK_ROUTE);
	if (nl == NULL) {
		perror("mnl_socket_open");
		exit(EXIT_FAILURE);
	}

	ret = mnl_socket_setsockopt(nl, NETLINK_CAP_ACK, &one, sizeof(one));
	if (ret) {
		perror("mnl_socket_setsockopt");
		exit(EXIT_FAILURE);
	}
	ret = mnl_socket_setsockopt(nl, NETLINK_EXT_ACK, &one, sizeof(one));
	if (ret) {
		perror("mnl_socket_setsockopt");
		exit(EXIT_FAILURE);
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		exit(EXIT_FAILURE);
	}

	mnl_attr_put_str(nlh, IFLA_IFNAME, "nlmon0");
	struct nlattr * linkinfo = mnl_attr_nest_start(nlh, IFLA_LINKINFO);
	mnl_attr_put_str(nlh, IFLA_INFO_KIND, "nlmon");
	mnl_attr_nest_end(nlh, linkinfo);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_sendto");
		exit(EXIT_FAILURE);
	}

	mnl_socket_close(nl);
}

/* ip l del nlmon0 */
void
destroy_nlmon(void)
{
	int ret;
	int one = 1;
	uint8_t buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= RTM_DELLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = time(NULL);
	struct ifinfomsg *ifm = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifm));
	ifm->ifi_family = AF_UNSPEC;
	ifm->ifi_index = if_nametoindex("nlmon0");

	struct mnl_socket *nl;
	nl = mnl_socket_open(NETLINK_ROUTE);
	if (nl == NULL) {
		perror("mnl_socket_open");
		exit(EXIT_FAILURE);
	}

	ret = mnl_socket_setsockopt(nl, NETLINK_CAP_ACK, &one, sizeof(one));
	if (ret) {
		perror("mnl_socket_setsockopt");
		exit(EXIT_FAILURE);
	}
	ret = mnl_socket_setsockopt(nl, NETLINK_EXT_ACK, &one, sizeof(one));
	if (ret) {
		perror("mnl_socket_setsockopt");
		exit(EXIT_FAILURE);
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		exit(EXIT_FAILURE);
	}

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_sendto");
		exit(EXIT_FAILURE);
	}

	mnl_socket_close(nl);
}

int
capture_nlmon()
{
	int one = 1;
	int so = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
	if (so < 0) {
		NLOG("sock create fail!\n");
		return -1;
	}
	struct sockaddr_nl snl;
	memset( &snl, 0, sizeof(snl));
	snl.nl_family = AF_NETLINK;

	struct sockaddr_ll sll;
	memset( &sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = if_nametoindex("nlmon0");
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_hatype = ARPHRD_NETLINK;

	ssize_t recvlen;
	char control[CMSG_SPACE(sizeof(struct timeval))];
	char buffer[65536];
	struct iovec iov[1];
	iov[0].iov_base = buffer;
	iov[0].iov_len = sizeof(buffer);

	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct timeval *ts = 0;

	msg.msg_name = &sll;
	msg.msg_namelen = sizeof(sll);
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	if (bind(so, (struct sockaddr *) &sll, sizeof(sll)) == -1) {
		perror("bind error:");
		exit(-1);
	}

	/* enable promisc on nlmon0 */
	struct packet_mreq mreq = {0};
	mreq.mr_ifindex = if_nametoindex("nlmon0");
	mreq.mr_type = PACKET_MR_PROMISC;
	if (setsockopt(so, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == -1) {
		perror("setsockopt");
		exit(1);
	}

	if (setsockopt(so, SOL_SOCKET, SO_TIMESTAMP, &one, sizeof(one)) == -1) {
		perror("setsockopt");
		exit(1);
	}

	recvlen = recvmsg(so, &msg, 0);
	while (recvlen >= 0 && running) {

		struct sockaddr_ll *ll = (struct sockaddr_ll *)msg.msg_name;
		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg ; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if (cmsg->cmsg_level == PF_LOCAL && cmsg->cmsg_type == SO_TIMESTAMP) {
				ts = (struct timeval*)CMSG_DATA(cmsg);
				NLOG("[%ld.%06ld]:", ts->tv_sec, ts->tv_usec);
				break;
			}
		}
		if (msg.msg_flags & MSG_TRUNC) {
			NLOG("frame too large for buffer: trucated");
		} else if (ll->sll_protocol == 0) {
			recvlen = mnl_cb_run(buffer, recvlen, 0, 0, netlink_cb, NULL);
		} else if (ll->sll_protocol == htons(ETH_P_PPPTALK)) {
			recvlen = mnl_cb_run(buffer, recvlen, 0, 0, ppp_cb, NULL);
		} else {
			NLOG("protocol %u\n", htons(ll->sll_protocol));
		}
		if (recvlen < 0)
				break;
		recvlen = recvmsg(so, &msg, 0);
	}
	if (recvlen < 0) {
		NLOG("msg len %d, msg_flags %d\n", msg.msg_namelen, msg.msg_flags);
		NLOG("error: %d recv length %ld\n", errno, recvlen);
		perror("error");
		return -1;
	}
	return 0;
}


int main(void)
{

	for (size_t i = 0; i < MNL_ARRAY_SIZE(fatal_signals); i++) {
		int sig_nr = fatal_signals[i];
#ifdef _POSIX_C_SOURCE
		struct sigaction old_sa;
		sigaction(sig_nr, NULL, &old_sa);
		if (old_sa.sa_handler == SIG_DFL && signal(sig_nr, fatal_signal_handler) == SIG_ERR) {
			perror("signal handler error");
			exit(EXIT_FAILURE);
		}
#endif
	}

	setuid(0);

	create_nlmon();

	/* skip recv msg error*/
	// while (running) {
		capture_nlmon();
	// }

	destroy_nlmon();

	return 0;
}
