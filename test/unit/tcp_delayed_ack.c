/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <unistd.h>

#include "test_utils.h"

static void test_tcp_quickack(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	int i;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	/*
	 * no delayed ack at quickack stage; not that ACK in handshake
	 * stage consumes one quota.
	 */
	for (i = 0; i < TSOCK_QUICKACK_COUNT - 1; i++) {
		pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt, 1000);
		ut_tcp_input_one(tsock, pkt);
		assert(ut_tcp_output(&pkt, 1) == 1); {
			assert(TCP_SEG(pkt)->flags == TCP_FLAG_ACK);
			assert(TCP_SEG(pkt)->len == 0);
			packet_free(pkt);
		}
	}

	/* a larger value to avoid false alarm due to huge schedule latency */
	tcp_cfg.delayed_ack = 2 * 1000 * 1000;
	pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt, 1000);
	ut_tcp_input_one(tsock, pkt);
	assert(ut_tcp_output(NULL, -1) == 0);

	usleep(tcp_cfg.delayed_ack + 100 * 1000);
	assert(ut_tcp_output(&pkt, 1) == 1); {
		assert(TCP_SEG(pkt)->flags == TCP_FLAG_ACK);
		assert(TCP_SEG(pkt)->len == 0);
		packet_free(pkt);
	}

	ut_close(tsock, CLOSE_TYPE_RESET);
}

static void test_tcp_delayed_ack_disabled(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();
	tsock->quickack = 0;

	/* no delayed ack when it's disabled */
	tcp_cfg.delayed_ack = 0;

	pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt, 1000);
	ut_tcp_input_one(tsock, pkt);
	assert(ut_tcp_output(&pkt, 1) == 1); {
		assert(TCP_SEG(pkt)->flags == TCP_FLAG_ACK);
		assert(TCP_SEG(pkt)->len == 0);
		packet_free(pkt);
	}

	ut_close(tsock, CLOSE_TYPE_RESET);
}

static void test_tcp_delayed_2_full_stream(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();
	tsock->quickack = 0;

	tcp_cfg.delayed_ack = UINT32_MAX;

	pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt, tsock->snd_mss);
	ut_tcp_input_one(tsock, pkt);
	assert(ut_tcp_output(NULL, -1) == 0);

	pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt, tsock->snd_mss);
	ut_tcp_input_one(tsock, pkt);
	assert(ut_tcp_output(&pkt, 1) == 1); {
		assert(TCP_SEG(pkt)->flags == TCP_FLAG_ACK);
		assert(TCP_SEG(pkt)->len == 0);
		packet_free(pkt);
	}

	ut_close(tsock, CLOSE_TYPE_RESET);
}

static void test_tcp_delayed_ack_with_ooo(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	int i;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();
	tsock->quickack = 0;

	/* no delayed ack on ooo pkts */
	for (i = 0; i < 3; i++) {
		pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt + 1000 * (i + 1), 1000);
		ut_tcp_input_one(tsock, pkt);
		assert(ut_tcp_output(&pkt, 1) == 1); {
			assert(TCP_SEG(pkt)->flags == TCP_FLAG_ACK);
			assert(TCP_SEG(pkt)->len == 0);
			packet_free(pkt);
		}
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_tcp_quickack();
	test_tcp_delayed_ack_disabled();
	test_tcp_delayed_2_full_stream();
	test_tcp_delayed_ack_with_ooo();

	return 0;
}
