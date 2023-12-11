/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <unistd.h>

#include "test_utils.h"

static void test_tcp_output_fast_retrans_bench(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	uint32_t ack;
	int ret;
	int i;

	printf("testing tcp_output bench [with fast retrans] ...\n");

	tsock = ut_tcp_connect();

	WHILE_NOT_TIME_UP() {
		do {
			ret = ut_write_assert(tsock, MESSAGE_SIZE);
		} while (ret == MESSAGE_SIZE);
		ut_tcp_output_skip_csum_verify(NULL, -1);

		if (rand() % 100 <= 10) {
			uint32_t inflight_size = tsock->snd_nxt - tsock->snd_una;
			int nr_dup_ack = rand() % (inflight_size / tsock->snd_mss + 1);

			ack = tsock->snd_una + rand() % (inflight_size - 100) + 1;
			nr_dup_ack = RTE_MAX(nr_dup_ack, 3);

			for (i = 0; i < nr_dup_ack; i++) {
				pkt = ut_inject_ack_packet(tsock, ack);
				ut_tcp_input_one(tsock, pkt);
			}
		} else if (rand() % 100 <= 20) {
			usleep(10);
			pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt);
			ut_tcp_input_one(tsock, pkt); {
				assert(tsock->snd_nxt == tsock->snd_una);
			}
		}

		ut_measure_rate(tsock, 1000 * 1000);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_tcp_output_fast_retrans_bench();

	return 0;
}
