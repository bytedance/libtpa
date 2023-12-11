/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Kai Xiong <xiongkai.123@bytedance.com>
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <unistd.h>

#include "test_utils.h"
#include "neigh.h"

static void test_ndp_missing_basic(void)
{
	struct tcp_sock *tsock = NULL;
	struct packet *pkt;
	struct tcp_opts opts;
	struct neigh_entry *entry;
	struct tpa_ip server_ip;
	int sid;

	printf("testing %s\n", __func__);

	tpa_ip_set_ipv6(&server_ip, (uint8_t *)SERVER_IP6);
	assert(neigh_find(&server_ip) == NULL);

	/*
	 * 1. tx arp request, queue syn pkt
	 */
	sid = ut_connect_to(SERVER_IP6_STR, SERVER_PORT, NULL);
	assert(sid >= 0);

	/* make sure NDP request is sent instead of the syn pkt */
	assert(ut_tcp_output(&pkt, 1) == 1); {
		struct ndp_solicit_hdr *hdr;

		hdr = rte_pktmbuf_mtod(&pkt->mbuf, struct ndp_solicit_hdr *);

		assert(hdr->eth.ether_type == htons(RTE_ETHER_TYPE_IPV6));

		assert(hdr->ip6.proto == IPPROTO_ICMPV6);
		assert(hdr->ip6.vtc_flow == htonl(6 << 28));
		assert(ntohs(hdr->ip6.payload_len) == sizeof(*hdr) - 54);

		assert(hdr->ns.nd_ns_hdr.icmp6_type == ND_NEIGHBOR_SOLICIT);
		assert(memcmp(&hdr->ns.nd_ns_target, SERVER_IP6, 16) == 0);

		assert(memcmp(&hdr->mac, dev.mac.addr_bytes, RTE_ETHER_ADDR_LEN) == 0);

		entry = neigh_find(&server_ip);
		assert(entry != NULL);
		assert(rte_is_zero_ether_addr(&entry->mac));

		packet_free(pkt);
	}

	/*
	 * 2. recv NDP response from kernel, update NDP cache
	 */
	pkt = make_ndp_rsp_pkt(&server_ip, (uint8_t []){2, 0, 0, 1, 0, 0});
	ut_ndp_input(pkt); {
		assert(neigh_find(&server_ip) != NULL);
		assert(!rte_is_zero_ether_addr(&entry->mac));
	}

	/*
	 * 3. send the queueing syn pkt
	 */
	assert(ut_tcp_output(&pkt, 1) == 1); {
		tsock = tsock_get_by_sid(sid);
		assert(parse_tcp_opts(&opts, pkt) == 0);
		assert(opts.has_ts == tsock->ts_enabled);
		assert(opts.has_wscale == tsock->ws_enabled);
		packet_free(pkt);
	}

	ut_close(tsock, CLOSE_TYPE_CLOSE_DIRECTLY);
}

static void test_ndp_not_in_same_subnet(void)
{
	struct neigh_entry *entry;
	struct tpa_ip server_ip;
	struct tpa_ip gw6;
	uint8_t mac[6] = {0x2, 1, 1, 1, 1, 1};

	printf("testing %s\n", __func__);

	/* set gw mac manually as it's been skipped due to "skip_arp" is set */
	neigh_update(tpa_ip_set_ipv6(&gw6, (uint8_t *)GW_IP6), mac);

	/* no subnet neighbors */
	dev.ip6.prefixlen = 128;

	tpa_ip_set_ipv6(&server_ip, (uint8_t *)SERVER_IP6);
	entry = neigh_lookup(worker, &server_ip); {
		assert(entry != NULL);
		assert(tpa_ip_equal(&entry->ip, &dev.gw6.ip));
	}
}

int main(int argc, char *argv[])
{
	skip_arp = 1;
	ut_init(argc, argv);

	test_ndp_missing_basic();
	test_ndp_not_in_same_subnet();

	return 0;
}
