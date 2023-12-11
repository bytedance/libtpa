/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>

#include "test_utils.h"

#define DATA_SIZE	1000

static void test_tcp_output_partial_ack_basic(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	int ret;

	printf("testing tcp_output partial ack basic ...\n");

	tsock = ut_tcp_connect();

	ret = ut_write_assert(tsock, DATA_SIZE);
	assert(ret == DATA_SIZE);
	ut_tcp_output(NULL, -1); {
		assert((uint32_t)(tsock->snd_nxt - tsock->snd_isn) == DATA_SIZE + 1);
	}


	pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt - 2);
	ut_tcp_input_one(tsock, pkt); {
		assert(tcp_txq_unfinished_pkts(&tsock->txq) == 1);
	}

	pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt - 1);
	ut_tcp_input_one(tsock, pkt); {
		assert(tcp_txq_unfinished_pkts(&tsock->txq) == 1);
	}

	pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt);
	ut_tcp_input_one(tsock, pkt); {
		assert(tcp_txq_unfinished_pkts(&tsock->txq) == 0);
		assert(tsock->snd_una == tsock->snd_nxt);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_output_partial_ack_overlap(void)
{
	struct tcp_sock *tsock;
	struct packet *pkts[4];
	uint32_t ack;
	int ret;

	printf("testing tcp_output partial ack ...\n");

	tsock = ut_tcp_connect();

	ret = ut_write_assert(tsock, DATA_SIZE);
	assert(ret == DATA_SIZE);
	ret = ut_write_assert(tsock, DATA_SIZE);
	assert(ret == DATA_SIZE);
	ut_tcp_output(NULL, -1); {
		assert((uint32_t)(tsock->snd_nxt - tsock->snd_isn) == DATA_SIZE * 2 + 1);
	}

	ack = tsock->snd_una + 1;
	pkts[0] = ut_inject_ack_packet(tsock, ack); ack += 700;
	pkts[1] = ut_inject_ack_packet(tsock, ack); ack += 700;
	pkts[2] = ut_inject_ack_packet(tsock, ack); ack  = tsock->snd_nxt;
	pkts[3] = ut_inject_ack_packet(tsock, ack);
	ut_tcp_input(tsock, pkts, 4); {
		assert(tcp_txq_unfinished_pkts(&tsock->txq) == 0);
		assert(tsock->snd_una == tsock->snd_nxt);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_output_partial_ack_stress(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	uint32_t ack;
	int ret;
	int i;

	printf("testing tcp_output partial ack stress ...\n");

	tsock = ut_tcp_connect();

#define NR_PKT	10
	for (i = 0; i < NR_PKT; i++) {
		ret = ut_write_assert(tsock, DATA_SIZE);
		assert(ret == DATA_SIZE);
		ut_tcp_output(NULL, -1); {
			assert((uint32_t)(tsock->snd_nxt - tsock->snd_isn) == DATA_SIZE * (i + 1) + 1);
		}
	}

	ack = tsock->snd_una + 1;
	for (i = 0; i < NR_PKT * DATA_SIZE; i++) {
		pkt = ut_inject_ack_packet(tsock, ack + i);
		ut_tcp_input_one(tsock, pkt); {
			assert(tsock->snd_una == ack + i);
		}
	}
	assert(tsock->snd_una == tsock->snd_nxt);
	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_output_partial_ack_stress_harder(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	uint32_t ack;
	int ret;
	int i;

	printf("testing tcp_output partial ack stress harder ...\n");

	tsock = ut_tcp_connect();

#define NR_PKT	10
	for (i = 0; i < NR_PKT; i++) {
		ret = ut_write_assert(tsock, DATA_SIZE);
		assert(ret == DATA_SIZE);
		ut_tcp_output(NULL, -1); {
			assert((uint32_t)(tsock->snd_nxt - tsock->snd_isn) == DATA_SIZE * (i + 1) + 1);
		}
	}

	WHILE_NOT_TIME_UP() {
		ack = tsock->snd_una + rand() % 1024;
		if (ack == tsock->snd_nxt)
			ack += 1;

		pkt = ut_inject_ack_packet(tsock, ack);
		ut_tcp_input_one(tsock, pkt); {
			assert(seq_lt(tsock->snd_una, tsock->snd_nxt));
			assert(tcp_txq_unfinished_pkts(&tsock->txq) > 0);

			/* drain */
			ut_tcp_output(NULL, -1);
		}
	}
	printf("un-acked=%u txq_active_count=%u\n",
		(uint32_t)(tsock->snd_nxt - tsock->snd_una),
		tcp_txq_unfinished_pkts(&tsock->txq));
	ut_close(tsock, CLOSE_TYPE_4WAY);
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_tcp_output_partial_ack_basic();
	test_tcp_output_partial_ack_overlap();
	test_tcp_output_partial_ack_stress();
	test_tcp_output_partial_ack_stress_harder();

	return 0;
}
