/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 * Author: Kai Xiong <xiongkai.123@bytedance.com>
 */
#include <sys/socket.h>
#include <netinet/icmp6.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include <net/if.h>

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>

#include "tpa.h"
#include "lib/utils.h"
#include "log.h"
#include "dev.h"
#include "shell.h"
#include "packet.h"
#include "neigh.h"

static void get_mulitcast_ip(uint8_t *dst, uint8_t *target)
{
	uint8_t ip[16] = {
		0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01, 0xff, 0x00, 0x00, 0x00,
	};

	ip[13] = target[13];
	ip[14] = target[14];
	ip[15] = target[15];

	memcpy(dst, ip, sizeof(ip));
}

static inline void get_multicast_mac(struct rte_ether_addr *addr, uint8_t *ip)
{
	uint16_t *ip16 = (uint16_t *)ip;
	uint16_t *addr16 = (uint16_t *)addr->addr_bytes;

	addr16[0] = 0x3333;
	addr16[1] = ip16[6];
	addr16[2] = ip16[7];
}

struct ndp_solicit_hdr {
	struct rte_ether_hdr eth;
	struct rte_ipv6_hdr ip6;
	struct nd_neighbor_solicit ns;
	struct nd_opt_hdr opt;
	struct rte_ether_addr mac;
} __attribute__((packed));

static void ndp_init_hdr(struct ndp_solicit_hdr *hdr, struct tpa_ip *ip)
{
	struct rte_ipv6_hdr *ip_hdr;
	struct nd_neighbor_solicit *ns;
	uint8_t multicast_ip[16];

	get_mulitcast_ip(multicast_ip, ip->u8);

	rte_ether_addr_copy(&dev.mac, ETH_SRC_ADDR(&hdr->eth));
	get_multicast_mac(ETH_DST_ADDR(&hdr->eth), multicast_ip);
	hdr->eth.ether_type = htons(RTE_ETHER_TYPE_IPV6);

	ip_hdr = &hdr->ip6;
	memcpy(ip_hdr->dst_addr, multicast_ip, 16);
	memcpy(ip_hdr->src_addr, &dev.ip6.ip, 16);
	ip_hdr->vtc_flow = htonl(6 << 28);
	ip_hdr->payload_len = htons(sizeof(*hdr) - sizeof(hdr->eth) - sizeof(hdr->ip6));
	ip_hdr->hop_limits = 255;
	ip_hdr->proto = IPPROTO_ICMPV6;

	ns = &hdr->ns;
	ns->nd_ns_hdr.icmp6_type = ND_NEIGHBOR_SOLICIT;
	ns->nd_ns_hdr.icmp6_code = 0;
	memcpy(&ns->nd_ns_target, ip, 16);

	hdr->opt.nd_opt_type = ND_OPT_SOURCE_LINKADDR;
	hdr->opt.nd_opt_len = 1;
	rte_ether_addr_copy(&dev.mac, &hdr->mac);

	ns->nd_ns_hdr.icmp6_cksum = 0;
	ns->nd_ns_hdr.icmp6_cksum = rte_ipv6_udptcp_cksum(ip_hdr, ns);
}

static int ndp_solicit(struct tpa_ip *ip, struct tpa_worker *worker)
{
	struct ndp_solicit_hdr *hdr;
	struct packet *pkt;
	int ret;

	pkt = packet_alloc(generic_pkt_pool);
	if (pkt == NULL)
		return -ERR_PKT_ALLOC_FAIL;

	hdr = (struct ndp_solicit_hdr *)rte_pktmbuf_append(&pkt->mbuf, sizeof(*hdr));
	if (!hdr)
		return -ERR_PKT_PREPEND_HDR;

	ndp_init_hdr(hdr, ip);

	ret = dev_port_txq_enqueue(0, worker->queue, pkt);
	if (unlikely(ret < 0))
		packet_free(pkt);

	return ret;
}

static int ndp_solicit_by_socket(int fd, struct tpa_ip *ip)
{
	struct ndp_solicit_hdr hdr;
	struct sockaddr_in6 addr;
	size_t size;

	ndp_init_hdr(&hdr, ip);
	size = sizeof(hdr) - sizeof(hdr.eth) - sizeof(hdr.ip6);

	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_scope_id = if_nametoindex(dev.name);
	memcpy(addr.sin6_addr.s6_addr, hdr.ip6.dst_addr, sizeof(addr.sin6_addr.s6_addr));

	if (sendto(fd, &hdr.ns, size, 0, (struct sockaddr *)&addr, sizeof(addr)) != size) {
		LOG_WARN("failed to send ndp neigh solicit packet: %s", strerror(errno));
		return -1;
	}

	return 0;
}

int ndp_handle_reply(uint8_t *packet, size_t len)
{
	struct nd_neighbor_advert *na  = (struct nd_neighbor_advert *)packet;
	struct nd_opt_hdr *opt;
	struct tpa_ip ip;

	if (len < sizeof(*na) + sizeof(struct nd_opt_hdr) + RTE_ETHER_ADDR_LEN)
		return 0;

	if (na->nd_na_hdr.icmp6_type == ND_NEIGHBOR_ADVERT &&
	    na->nd_na_hdr.icmp6_code == 0) {
		opt = (struct nd_opt_hdr *)(na + 1);

		if (opt->nd_opt_type == ND_OPT_TARGET_LINKADDR && opt->nd_opt_len == 1) {
			tpa_ip_set_ipv6(&ip, (uint8_t *)(&na->nd_na_target));
			neigh_handle_reply(&ip, (uint8_t *)(opt + 1));
		}
	}

	return 0;
}

static void ndp_cache_init(void)
{
	char ip6[INET6_ADDRSTRLEN];
	struct tpa_ip ip;
	char buf[1024];
	char eth[128];
	uint8_t mac[6];
	FILE *f;

	if (getenv("TPA_NDP_SKIP_CACHE_INIT"))
		return;

	f = popen("ip -6 neigh", "r");
	if (!f) {
		LOG_ERR("failed to get initial ip6 neighbos");
		return;
	}

	while (fgets(buf, sizeof(buf), f)) {
		if (sscanf(buf, "%s dev %s lladdr %hhx:%hhx:%hhx:%hhx:%hhx:%hhx", ip6, eth,
			   &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 8) {
			continue;
		}

		if (strlen(dev.name) && strcmp(eth, dev.name))
			continue;

		neigh_update(tpa_ip_from_str(&ip, ip6), mac);
	}

	/* for supporting loopback mode */
	neigh_update(&dev.ip6.ip, dev.mac.addr_bytes);

	pclose(f);
}

static int ndp_init(void)
{
	struct icmp6_filter filter;
	int fd;

	ndp_cache_init();

	fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (fd < 0)
		return -1;

	ICMP6_FILTER_SETBLOCKALL(&filter);
	ICMP6_FILTER_SETPASS(ND_NEIGHBOR_ADVERT, &filter);
	if (setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter)) <  0)
		LOG_WARN("failed to set filter: ND_NEIGHBOR_ADVERT pkts only");

	setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &(int){ 255 }, sizeof(int));
	setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &(int){ 255 }, sizeof(int));

	return fd;
}

const struct neigh_ops ndp_ops = {
	.nd_init = ndp_init,
	.nd_solicit = ndp_solicit,
	.nd_solicit_by_socket = ndp_solicit_by_socket,
	.nd_handle_reply = ndp_handle_reply,
};
