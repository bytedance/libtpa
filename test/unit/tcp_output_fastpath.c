/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>

#include "test_utils.h"

static void test_tcp_output_fastpath_basic(void)
{
	struct tcp_sock *tsock;
	int i;

	printf("testing tcp_output fastpath [basic] ...\n");

	tsock = ut_tcp_connect();

	for (i = 0; i < 3; i++) {
		ut_write_assert(tsock, MESSAGE_SIZE);
		ut_tsock_txq_drain(tsock);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_output_fastpath_basic2(void)
{
	struct tcp_sock *tsock;
	struct packet *pkts[2];
	int i;

	printf("testing tcp_output fastpath [basic2] ...\n");

	tsock = ut_tcp_connect();

	for (i = 0; i < 2; i++) {
		ut_write_assert(tsock, 1000);
	} {
		if (tsock->tso_enabled == 0) {
			assert(ut_tcp_output(pkts, 2) == 2);
			assert((uint32_t)(TCP_SEG(pkts[0])->seq - tsock->snd_isn) == 1);
			assert((uint32_t)(TCP_SEG(pkts[1])->seq - tsock->snd_isn) == 1 + tsock->snd_mss);
			packet_free_batch(pkts, 2);
		} else {
			assert(ut_tcp_output(pkts, -1) == 1);
			assert(pkts[0]->mbuf.pkt_len - pkts[0]->hdr_len == 2000);
			packet_free(pkts[0]);
		}
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_tcp_output_fastpath_basic();
	test_tcp_output_fastpath_basic2();

	return 0;
}
