/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <unistd.h>

#include "test_utils.h"

#define UT_KEEPALIVE_INTERVAL	(500 * 1000) /* 500ms */

static void test_tcp_keepalive_basic(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	usleep(UT_KEEPALIVE_INTERVAL * 2); {
		assert(ut_tcp_output(&pkt, 1) == 1); {
			assert(TCP_SEG(pkt)->len == 0);
			assert(TCP_SEG(pkt)->seq == tsock->snd_una - 1);
			assert(TCP_SEG(pkt)->flags == TCP_FLAG_ACK);
			assert(tsock->keepalive_shift == 1);
			packet_free(pkt);
		}
	}

	pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt);
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->keepalive_shift == 0);
		assert(!timer_is_stopped(&tsock->timer_keepalive));
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_keepalive_timeout(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	int i;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	tcp_cfg.retries = 4;
	for (i = 0; i < tcp_cfg.retries; i++) {
		usleep(UT_KEEPALIVE_INTERVAL * 2);

		assert(ut_tcp_output(&pkt, 1) == 1); {
			assert(TCP_SEG(pkt)->len == 0);
			assert(tsock->keepalive_shift == i + 1);
		}
	}

	usleep(UT_KEEPALIVE_INTERVAL * 2);
	assert(ut_tcp_output(NULL, -1) == 0);

	ut_close(tsock, CLOSE_TYPE_CLOSE_DIRECTLY);
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	tcp_cfg.keepalive = UT_KEEPALIVE_INTERVAL;

	test_tcp_keepalive_basic();
	test_tcp_keepalive_timeout();

	return 0;
}
