/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 * Author: Kai Xiong <xiongkai.123@bytedance.com>
 */
#include <stdio.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include <net/if.h>

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_ip.h>

#include "tpa.h"
#include "lib/utils.h"
#include "log.h"
#include "dev.h"
#include "shell.h"
#include "packet.h"
#include "neigh.h"

struct arp_solicit_hdr {
	struct rte_ether_hdr eth;
	struct rte_arp_hdr arp;
	char pad[22];
} __attribute__((packed));

static struct rte_ether_addr broadcast_mac = {
	.addr_bytes = "\xff\xff\xff\xff\xff\xff",
};

static void arp_init_hdr(struct arp_solicit_hdr *hdr, struct tpa_ip *ip)
{
	struct rte_ether_hdr *eth;
	struct rte_arp_hdr *arp;

	eth = &hdr->eth;
	rte_ether_addr_copy(&dev.mac, ETH_SRC_ADDR(eth));
	rte_ether_addr_copy(&broadcast_mac, ETH_DST_ADDR(eth));
	eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

	arp = &hdr->arp;
	arp->arp_hardware = htons(RTE_ARP_HRD_ETHER);
	arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
	arp->arp_hlen = sizeof(struct rte_ether_addr);
	arp->arp_plen = sizeof(struct in_addr);
	arp->arp_opcode = htons(RTE_ARP_OP_REQUEST);

	rte_ether_addr_copy(&dev.mac, &arp->arp_data.arp_sha);
	rte_ether_addr_copy(&broadcast_mac, &arp->arp_data.arp_tha);
	arp->arp_data.arp_sip = dev.ip4;
	arp->arp_data.arp_tip = tpa_ip_get_ipv4(ip);
}

/*
 * injecting ARP request by DPDK and recv it by the AF_PACKET socket.
 */
static int arp_solicit(struct tpa_ip *ip, struct tpa_worker *worker)
{
	struct arp_solicit_hdr *hdr;
	struct packet *pkt;
	int ret;

	pkt = packet_alloc(generic_pkt_pool);
	if (pkt == NULL)
		return -ERR_PKT_ALLOC_FAIL;

	hdr = (struct arp_solicit_hdr *)rte_pktmbuf_append(&pkt->mbuf, sizeof(*hdr));
	if (!hdr) {
		packet_free(pkt);
		return -ERR_PKT_PREPEND_HDR;
	}

	arp_init_hdr(hdr, ip);

	ret = dev_port_txq_enqueue(0, worker->queue, pkt);
	if (unlikely(ret < 0))
		packet_free(pkt);

	return ret;
}

static int arp_solicit_by_socket(int fd, struct tpa_ip *ip)
{
	struct arp_solicit_hdr hdr;
	struct sockaddr_ll addr;

	arp_init_hdr(&hdr, ip);

	memset(&addr, 0, sizeof(addr));
	addr.sll_ifindex = if_nametoindex(dev.name);

	if (sendto(fd, &hdr, sizeof(hdr), 0, (struct sockaddr *)&addr, sizeof(addr)) < sizeof(hdr)) {
		LOG_WARN("failed to send arp request: %s", strerror(errno));
		return -1;
	}

	return 0;
}

int arp_input(uint8_t *pkt, size_t len)
{
	struct rte_arp_hdr *arp;
	struct tpa_ip ip;

	arp = (struct rte_arp_hdr *)(pkt + sizeof(struct rte_ether_hdr));

	tpa_ip_set_ipv4(&ip, arp->arp_data.arp_sip);
	neigh_input(&ip, arp->arp_data.arp_sha.addr_bytes);

	return 0;
}

static char *skip_word(char *p)
{
	while (*p && *p == ' ')
		p++;

	while (*p && *p != ' ')
		p++;

	while (*p && *p == ' ')
		p++;

	return p;
}

static char *skip_words(char *p, int count)
{
	while (count--)
		p = skip_word(p);

	return p;
}

static void arp_cache_init(void)
{
	FILE *f;
	union {
		uint32_t raw;
		uint8_t  bytes[4];
	} ip4;
	struct tpa_ip ip;
	uint8_t mac[6];
	char buf[1024];
	char *eth;
	char *p;

	if (getenv("TPA_ARP_SKIP_CACHE_INIT"))
		return;

	f = fopen("/proc/net/arp", "r");
	if (!f) {
		LOG_ERR("failed to open neigh proc file");
		return;
	}

	while (fgets(buf, sizeof(buf), f)) {
		if (sscanf(buf, "%hhu.%hhu.%hhu.%hhu", &ip4.bytes[0],
				&ip4.bytes[1], &ip4.bytes[2], &ip4.bytes[3]) != 4)
			continue;

		p = skip_words(buf, 3);
		if (sscanf(p, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
				&mac[0], &mac[1], &mac[2],
				&mac[3], &mac[4], &mac[5]) != 6)
			continue;

		if (strlen(dev.name)) {
			eth = skip_words(p, 2);
			p = strchr(eth, '\n');
			if (p)
				*p = '\0';
			if (strcmp(eth, dev.name))
				continue;
		}

		neigh_update(tpa_ip_set_ipv4(&ip, ip4.raw), mac);
	}

	/* for supporting loopback mode */
	neigh_update(tpa_ip_set_ipv4(&ip, dev.ip4), dev.mac.addr_bytes);

	fclose(f);
}

static int cmd_arp(struct shell_cmd_info *cmd)
{
	neigh_dump(cmd->reply);

	return 0;
}

static const struct shell_cmd arp = {
	.name    = "arp",
	.handler = cmd_arp,
};

static int arp_init(void)
{
	if (dev.ip4 == 0)
		return ND_SKIP;

	arp_cache_init();
	shell_register_cmd(&arp);

	return socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
}

const struct neigh_ops arp_ops = {
	.nd_init = arp_init,
	.nd_solicit = arp_solicit,
	.nd_solicit_by_socket = arp_solicit_by_socket,
	.nd_input = arp_input,
};
