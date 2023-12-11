/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>

#include "test_utils.h"

static void test_tcp_output_seq(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;

	printf("testing tcp_output seq ...\n");

	tsock = ut_tcp_connect();

	/*
	 * write 3 seg; 1 is allowed to xmit
	 */
	tsock->snd_cwnd = tsock->snd_mss;
	ut_write_assert(tsock, 1000);
	ut_write_assert(tsock, 1000);
	ut_write_assert(tsock, 1000);
	assert(ut_tcp_output(NULL, -1) == 1);

	pkt = ut_inject_ack_packet(tsock, tsock->snd_una + 3000);
	ut_tcp_input_one(tsock, pkt); {
		/* make sure an invalid ACK will not move snd_una */
		assert(tsock->snd_una == tsock->snd_isn + 1);
		assert(ut_tcp_output(NULL, -1) == 1);
	}

	/* do the real ack */
	pkt = ut_inject_ack_packet(tsock, tsock->snd_una + tsock->snd_mss);
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->snd_una == tsock->snd_nxt);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_tcp_output_seq();

	return 0;
}
