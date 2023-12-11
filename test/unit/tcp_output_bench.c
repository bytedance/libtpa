/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <unistd.h>

#include "test_utils.h"

static void test_tcp_output_bench_basic(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	int ret;

	printf("testing tcp_output bench [basic] ...\n");

	tsock = ut_tcp_connect();

	WHILE_NOT_TIME_UP() {
		do {
			ret = ut_write_assert(tsock, MESSAGE_SIZE);
		} while (ret == MESSAGE_SIZE);
		ut_tcp_output_skip_csum_verify(NULL, -1); {
			assert(tcp_txq_unfinished_pkts(&tsock->txq) >= 1);
		}

		pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt);
		ut_tcp_input_one(tsock, pkt); {
			assert(tsock->snd_una == tsock->snd_nxt);
		}

		ut_measure_rate(tsock, 1000 * 1000);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_tcp_output_bench_basic();

	return 0;
}
