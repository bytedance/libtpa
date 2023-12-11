/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <getopt.h>
#include <sys/uio.h>

#include "test_utils.h"

static void test_tcp_input_wnd_basic(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	struct tpa_iovec iov[3];
	int sum = 0;
	int i;

	printf("testing tcp rcv wnd basic ...\n");

	tsock = ut_tcp_connect();

	for (i = 0; i < TSOCK_RXQ_LEN_DEFAULT + 1; i++) {
		pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt, 1);
		ut_tcp_input_one(tsock, pkt); {
			assert(tsock->rcv_wnd > 0);
			assert(tsock->rcv_wnd < TCP_WINDOW_MAX);

			/* drain */
			ut_tcp_output(NULL, -1);
		}
	}
	assert(tcp_rxq_free_count(&tsock->rxq) == 0);
	assert(tsock->stats_base[ERR_TCP_RXQ_ENQUEUE_FAIL] == 1);

	while (sum < TSOCK_RXQ_LEN_DEFAULT) {
		int size;

		size = tpa_zreadv(tsock->sid, iov, 3);
		assert(size > 0 && size <= 3);

		for (i = 0; i < size; i++)
			iov[i].iov_read_done(iov[i].iov_base, iov[i].iov_param);

		sum += size;
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
	printf("\trcv_wnd: %u\n", tsock->rcv_wnd);
}

static void test_tcp_input_wnd_full(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	struct tpa_iovec iov;
	int i;

	printf("testing tcp rcv wnd full ...\n");

	tsock = ut_tcp_connect();

	for (i = 0; i < TSOCK_RXQ_LEN_DEFAULT; i++) {
		pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt, 1400);
		ut_tcp_input_one(tsock, pkt); {
			assert(tsock->rcv_wnd < TCP_WINDOW_MAX);

			/* drain */
			ut_tcp_output(NULL, -1);
		}
	}

	assert(tsock->rcv_wnd == 0);
	assert(tcp_rxq_free_count(&tsock->rxq) == 0);

	/* test window update */
	tpa_zreadv(tsock->sid, &iov, 1); {
		iov.iov_read_done(iov.iov_base, iov.iov_param);

		assert(ut_tcp_output(&pkt, 1) == 1); {
			assert(TCP_SEG(pkt)->len == 0);
			assert(TCP_SEG(pkt)->flags == TCP_FLAG_ACK);
			assert(tsock->stats_base[WND_UPDATE] == 1);

			packet_free(pkt);
		}
	}

	ut_close(tsock, CLOSE_TYPE_RESET);
	printf("\trcv_wnd: %u\n", tsock->rcv_wnd);
}

int main(int argc, char **argv)
{
	ut_init(argc, argv);

	test_tcp_input_wnd_basic();
	test_tcp_input_wnd_full();

	return 0;
}
