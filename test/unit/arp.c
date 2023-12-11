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

static void test_arp_missing_basic(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	struct tcp_opts opts;
	int sid;

	printf("testing %s\n", __func__);

	/*
	 * 1. tx arp request, queue syn pkt
	 */
	sid = ut_connect_to(SERVER_IP_STR, SERVER_PORT, NULL);
	assert(sid >= 0);

	/* make sure ARP request is sent instead of the syn pkt */
	assert(ut_tcp_output(&pkt, 1) == 1); {
		struct rte_ether_hdr *eth;
		struct rte_arp_hdr *arp;

		eth = rte_pktmbuf_mtod(&pkt->mbuf, struct rte_ether_hdr *);
		assert(eth->ether_type == htons(RTE_ETHER_TYPE_ARP));

		arp = rte_pktmbuf_mtod_offset(&pkt->mbuf, struct rte_arp_hdr *, sizeof(*eth));
		assert(arp->arp_opcode == htons(RTE_ARP_OP_REQUEST));
		assert(arp->arp_data.arp_sip == dev.ip4);
		assert(arp->arp_data.arp_tip == SERVER_IP);

		packet_free(pkt);
	}

	/*
	 * 2. recv arp response from kernel, update arp cache
	 */
	uint8_t mac[6] = {2, 1, 1, 1, 1, 1};
	pkt = make_arp_rsp_pkt(SERVER_IP, mac);
	ut_arp_input(pkt); {
		assert(neigh_find_ip4(SERVER_IP) != NULL);
	}

	/*
	 * 3. send the queueing syn pkt
	 */
	assert(ut_tcp_output(&pkt, 1) == 1); {
		/* verify the syn pkt being sent out is okay */
		tsock = tsock_get_by_sid(sid);
		assert(parse_tcp_opts(&opts, pkt) == 0);
		assert(opts.has_ts == tsock->ts_enabled);
		assert(opts.has_wscale == tsock->ws_enabled);
		packet_free(pkt);
	}

	/*
	 * 4. rcv RST
	 */
	pkt = ut_inject_rst_packet(tsock);
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->err == ECONNREFUSED);
	}

	ut_close(tsock, CLOSE_TYPE_CLOSE_DIRECTLY);
}

static void test_arp_evict_basic(void)
{
	struct neigh_entry *entry;
	struct packet *pkt;
	uint8_t mac[6] = { 0, };

	printf("testing %s\n", __func__);

	mac[0] = 0x2;
	pkt = make_arp_rsp_pkt(SERVER_IP, mac);
	ut_arp_input(pkt); {
		entry = neigh_find_ip4(SERVER_IP);
		assert(neigh_find_ip4(SERVER_IP) != NULL);
		assert(memcmp(mac, entry->mac.addr_bytes, sizeof(mac)) == 0);
	}

	/*
	 * assume recv arp response again from SERVER_IP but different MAC
	 * check whether MAC addr updates
	 */
	mac[0] = 0x4;
	pkt = make_arp_rsp_pkt(SERVER_IP, mac);
	ut_arp_input(pkt); {
		entry = neigh_find_ip4(SERVER_IP);
		assert(neigh_find_ip4(SERVER_IP) != NULL);
		assert(memcmp(mac, entry->mac.addr_bytes, sizeof(mac)) == 0);
	}
}

static void test_arp_evict_full(void)
{
	struct packet *pkt;
	struct neigh_entry *entry;
	uint8_t mac[6] = { 0, };
	uint32_t ip;

	printf("testing %s\n", __func__);

	mac[0] = 0x2;
	while (get_neigh_cache_len() != MAX_NEIGH_ENTRY) {
		ip = rand();
		pkt = make_arp_rsp_pkt(ip, mac);
		ut_arp_input(pkt); {
			entry = neigh_find_ip4(ip);
			assert(entry != NULL);
			assert(memcmp(mac, entry->mac.addr_bytes, sizeof(mac)) == 0);
		}
	}
	assert(get_neigh_cache_len() == MAX_NEIGH_ENTRY);

	mac[0] = 0x4;
	do {
		ip = rand();
	} while (neigh_find_ip4(ip));
	pkt = make_arp_rsp_pkt(ip, mac);
	ut_arp_input(pkt); {
		entry = neigh_find_ip4(ip);
		assert(entry != NULL);
		assert(memcmp(mac, entry->mac.addr_bytes, sizeof(mac)) == 0);
		/* evict an old one, keep the maximum size */
		assert(get_neigh_cache_len() == MAX_NEIGH_ENTRY);
	}
}

static void test_gw_arp_missing(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	struct rte_arp_hdr *arp;
	uint8_t mac[6] = { 0x4, };
	int sid;

	printf("testing arp [gw arp missing]\n");

	ut_test_opts.remote_ip = 0xc0a81e01;

	sid = ut_connect_to("192.168.30.1", SERVER_PORT, NULL); {
		assert(sid >= 0);
		tsock = tsock_get_by_sid(sid);
	}

	assert(ut_tcp_output(&pkt, 1) == 1); {
		arp = rte_pktmbuf_mtod_offset(&pkt->mbuf, struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));
		/* check gw ip */
		assert(arp->arp_data.arp_tip == GW_IP);
		packet_free(pkt);
	}

	pkt = make_arp_rsp_pkt(GW_IP, mac);
	ut_arp_input(pkt); {
		assert(ut_tcp_output(NULL, 0) == 1);
	}

	ut_close(tsock, CLOSE_TYPE_CLOSE_DIRECTLY);

	ut_test_opts.remote_ip = 0;
}

static void test_zero_mac_update(void)
{
	struct tpa_ip ip;

	printf("testing %s ...\n", __func__);

	tpa_ip_set_ipv4(&ip, 0x12345678);
	neigh_update(&ip, (uint8_t *)"\x00\x00\x00\x00\x00\x00");
	assert(neigh_find(&ip) == NULL);
}

static void test_timeout_try_update_eth_hdr(void)
{
	struct tcp_sock *tsock;
	struct rte_ether_hdr eth_hdr;

	printf("testing %s ...\n",  __func__);

	tsock = ut_tcp_connect();

	ut_write_assert(tsock, 1000);
	assert(ut_tcp_output(NULL, -1) == 1);

	ut_simulate_rto_timeout(tsock);

	eth_hdr = tsock->net_hdr.eth;
	memset(&tsock->net_hdr.eth, 0, sizeof(tsock->net_hdr.eth));

	assert(ut_tcp_output(NULL, -1) == 1); {
		assert(memcmp(&eth_hdr, &tsock->net_hdr.eth, sizeof(eth_hdr)) == 0);
		assert(tsock->stats_base[WARN_NEIGH_CHANGED] == 1);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

#define ARP_WITH_NO_REPLY_COUNT		(NEIGH_QUEUE_LEN + 1)

/*
 * A test to make sure:
 * - we will not flood ARP requets
 * - normal ARP request will not be blocked by the bad ones (with bad ip)
 */
static void test_arp_with_no_reply(void)
{
	struct tcp_sock *tsocks[ARP_WITH_NO_REPLY_COUNT];
	uint64_t count;
	int sid;
	int i;

	printf("testing %s ...\n", __func__);

	tcp_cfg.syn_retries = 2;
	for (i = 0; i < ARP_WITH_NO_REPLY_COUNT; i++) {
		sid = ut_connect_to("192.168.1.250", 80, NULL); {
			assert(sid >= 0);
			tsocks[i] = tsock_get_by_sid(sid);
		}
	}

	/* wait until all socks are closed due to connection timeout */
	for (i = 0; i < ARP_WITH_NO_REPLY_COUNT; i++) {
		while (tsocks[i]->state != TCP_STATE_CLOSED) {
			ut_tcp_output(NULL, 0); {
				/* make sure no ARP flood was made */
				assert(worker->stats_base[ARP_SOLICIT] <= ARP_WITH_NO_REPLY_COUNT * 20);
			}
		}
	}

	/* make sure we are in the neigh wait queue */
	count = worker->stats_base[ERR_NEIGH_ENQUEUE];
	ut_connect_to("192.168.1.250", SERVER_PORT, NULL);
	ut_tcp_output(NULL, 0); {
		assert(worker->stats_base[ERR_NEIGH_ENQUEUE] == count);
	}
}

int main(int argc, char *argv[])
{
	skip_arp = 1;
	setenv("TPA_ARP_ACCEPT_GARP", "1", 1);
	ut_init(argc, argv);

	test_arp_missing_basic();
	test_arp_evict_basic();
	test_arp_evict_full();
	test_gw_arp_missing();
	test_zero_mac_update();
	test_timeout_try_update_eth_hdr();

	test_arp_with_no_reply();

	return 0;
}
