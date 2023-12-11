/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <unistd.h>

#include <rte_malloc.h>

#include "test_utils.h"

static void test_tcp_connect_basic(void)
{
	struct tcp_sock *tsock;

	printf("testing %s ...\n", __func__);

	tsock = do_ut_tcp_connect(ut_test_opts.has_ts, ut_test_opts.mss,
				  ut_test_opts.wscale, ut_test_opts.sack);

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_connect_small_init_snd_wnd(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	int mss = 1448;

	printf("testing %s ...\n", __func__);

	/* syn */
	tsock = ut_trigger_connect();
	assert(ut_tcp_output(NULL, -1) == 1);

	/* syn-ack: inject a small init wnd */
	pkt = make_synack_packet(tsock, 0, mss, 0, 0);
	ut_packet_tcp_hdr(pkt)->rx_win = htons(mss/2);
	ut_tcp_input_one(tsock, pkt);

	ut_close(tsock, CLOSE_TYPE_4WAY);
}


static void test_tcp_connect_out_of_mem(void)
{
	printf("testing %s ...\n", __func__);

	/* exhaust dpdk mem */
	while (1) {
		if (!rte_malloc(NULL, 1024, 64))
			break;
	}

	assert(ut_connect_to(SERVER_IP_STR, 8080, NULL) < 0);
}

static void test_tcp_connect_addrinuse(void)
{
	struct tpa_sock_opts opts;
	int sid;

	printf("testing %s ...\n", __func__);

	sid = ut_connect_to(SERVER_IP_STR, SERVER_PORT, NULL);
	assert(sid >= 0);

	memset(&opts, 0, sizeof(opts));
	opts.local_port = htons(sock_ctrl->socks[sid].local_port);
	assert(ut_connect_to(SERVER_IP_STR, SERVER_PORT, &opts) == -1);
	assert(errno == EADDRINUSE);

	/* make sure tsock_free of above unsuccessfull socket will not free the port */
	assert(ut_connect_to(SERVER_IP_STR, SERVER_PORT, &opts) == -1);
	assert(errno == EADDRINUSE);

	ut_close(&sock_ctrl->socks[sid], CLOSE_TYPE_CLOSE_DIRECTLY);
}

static void test_tcp_connect_invalid_addr(void)
{
	printf("testing %s ...\n", __func__);

	/* invalid ip */
	assert(ut_connect_to("hello", 80, NULL) < 0); {
		assert(errno == EINVAL);
	}

	assert(ut_connect_to("0.0.0.0", 80, NULL) < 0); {
		assert(errno == EINVAL);
	}

	/* invalid port */
	assert(ut_connect_to("127.0.0.1", 0, NULL) < 0); {
		assert(errno == EINVAL);
	}
}

static void test_tcp_connect_recv_rst_before_xmit_syn(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	int sid;

	printf("testing %s ...\n", __func__);

	sid = ut_connect_to(SERVER_IP_STR, SERVER_PORT, NULL); {
		tsock = &sock_ctrl->socks[sid];
	}

	pkt = ut_inject_ack_packet(tsock, 1234);
	ut_tcp_input_one(tsock, pkt);

	/*
	 * We should not send anything else besides the SYN packet.
	 * Above packet would be dropped, silently.
	 */
	assert(ut_tcp_output(NULL, -1) == 1);

	ut_close(tsock, CLOSE_TYPE_CLOSE_DIRECTLY);
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_tcp_connect_basic();
	test_tcp_connect_small_init_snd_wnd();
	test_tcp_connect_addrinuse();
	test_tcp_connect_invalid_addr();
	test_tcp_connect_recv_rst_before_xmit_syn();

	/*
	 * XXX: this test should be run last, as it exhausts DPDK memory
	 * Note that sock rxq/txq no longer use DPDK memory, therefore,
	 * below test won't reall work. So disable it.
	 *
	test_tcp_connect_out_of_mem();
	 */

	return 0;
}
