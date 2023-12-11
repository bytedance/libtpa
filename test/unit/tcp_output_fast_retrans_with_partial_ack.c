/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>

#include "test_utils.h"

static void test_tcp_output_fast_retrans_with_partial_ack(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	uint32_t ack;
	int i;

	printf("testing tcp_output fast retransmit with partial ack ...\n");

	tsock = ut_tcp_connect();

	ut_write_assert(tsock, MESSAGE_SIZE);
	ut_write_assert(tsock, MESSAGE_SIZE);
	ut_tcp_output(NULL, -1); {
		assert(tcp_txq_unfinished_pkts(&tsock->txq) >= 1);
	}

	/*
	 * inject 4 acks; the first one actually ACKs one byte and the later
	 * 3 are dup acks
	 */
	ack = tsock->snd_una + 1;
	for (i = 0; i < 4; i++) {
		pkt = ut_inject_ack_packet(tsock, ack);
		ut_tcp_input_one(tsock, pkt); {
			assert(tcp_txq_unfinished_pkts(&tsock->txq) >= 1);
		}
	}
	assert(tsock->retrans_stage == FAST_RETRANS);
	assert(tcp_txq_unfinished_pkts(&tsock->txq) >= 1);

	/* ack all; mark the end of fast-retrans */
	pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt);
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->retrans_stage == NONE);
		assert(tsock->snd_una == tsock->snd_nxt);
		assert(ut_tcp_output(NULL, 0) >= 1);
	}

	ut_tsock_txq_drain(tsock);

	ut_dump_tsock_stats(tsock);
	ut_assert_mbuf_count();
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_tcp_output_fast_retrans_with_partial_ack();

	return 0;
}
