/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <getopt.h>
#include <sys/uio.h>

#include "test_utils.h"

static void test_tcp_output_wnd_basic(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;

	printf("testing tcp output wnd basic ...\n");

	tsock = ut_tcp_connect();

	/* set a small snd wnd */
	tsock->snd_wnd = 500;
	ut_write_assert(tsock, 500);
	ut_write_assert(tsock, 1);
	assert(ut_tcp_output(&pkt, 1) == 1); {
		assert(TCP_SEG(pkt)->len == 500);
		assert(tcp_txq_inflight_pkts(&tsock->txq) == 1);
		assert(tcp_txq_to_send_pkts(&tsock->txq) == 1);
		packet_free(pkt);
	}

	/* restore a sane value */
	tsock->snd_wnd = 5000;
	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_output_wnd_basic2(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;

	printf("testing tcp output wnd basic2 ...\n");

	tsock = ut_tcp_connect();

	/* set a small snd wnd */
	tsock->snd_wnd = 500;
	ut_write_assert(tsock, 499);
	ut_write_assert(tsock, 2);
	ut_write_assert(tsock, 1);
	ut_tcp_output(&pkt, 1); {
		assert(TCP_SEG(pkt)->len == 500);
		assert(tcp_txq_inflight_pkts(&tsock->txq) == 1);
		assert(tcp_txq_to_send_pkts(&tsock->txq) == 2);
		packet_free(pkt);
	}

	/* restore a sane value */
	tsock->snd_wnd = 5000;
	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_output_0wnd_probe(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;

	printf("testing tcp output wnd zero wnd probe ...\n");

	tsock = ut_tcp_connect();

	/* set 0 zero wnd */
	tsock->snd_wnd = 0;
	ut_write_assert(tsock, 499);
	assert(ut_tcp_output(&pkt, 1) == 0);

	usleep(tsock->rto + 1000);
	assert(ut_tcp_output(&pkt, 1) == 1); {
		assert(TCP_SEG(pkt)->len == 0);
		assert(TCP_SEG(pkt)->flags == TCP_FLAG_ACK);

		packet_free(pkt);
	}

	/* restore a sane value */
	tsock->snd_wnd = 5000;
	ut_close(tsock, CLOSE_TYPE_4WAY);
}

int main(int argc, char **argv)
{
	ut_init(argc, argv);

	test_tcp_output_wnd_basic();
	test_tcp_output_wnd_basic2();
	test_tcp_output_0wnd_probe();

	return 0;
}
