/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <getopt.h>
#include <sys/uio.h>

#include "test_utils.h"

/*
 * test key points:
 * - basic
 *
 * - tcp_input fastpath
 *
 * - remote-write with (partial or full) seq overlaps
 *   say, with seq [100 - 200), [100 - 300), [200 - 201), etc
 *
 * - remote-write with (partial or full) seq outside of the
 *   (left or right) window
 *
 * - gro (if supported)
 *   - readv with iov size (say 1) less than the mbuf chain len
 *   - trim multiple mbuf segs
 *
 * Asserts:
 * - read size
 * - counters (say nr_with_fastpath, PKT_RECV, PKT_RECV, etc)
 * - rxq
 */

static void test_tcp_input_basic(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;

	printf("testing basic tcp_input ...\n");

	tsock = ut_tcp_connect();

	pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt, 1000);
	ut_tcp_input_one(tsock, pkt);
	assert(ut_readv(tsock, 1) == 1000);

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_input_with_seq_overlap(void)
{
	struct tcp_sock *tsock;
	struct packet *pkts[5];

	printf("testing tcp_input with seq overlap ...\n");

	tsock = ut_tcp_connect();

	/*
	 *                       0                       1000
	 * pkt 0:                |-----------------------|
	 *                 -100         200
	 * pkt 1:            |-----------|
	 *                                       800       1100
	 * pkt 2:                                 |---------|
	 *                         100               900
	 * pkt 3:                   |-----------------|
	 *             -200                                  1200
	 * pkt 4:        |-------------------------------------|
	 */
	pkts[0] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 0,   1000);
	pkts[1] = ut_inject_data_packet(tsock, tsock->rcv_nxt - 100, 300);
	pkts[2] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 800, 300);
	pkts[3] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 100, 800);
	pkts[4] = ut_inject_data_packet(tsock, tsock->rcv_nxt - 200, 1400);
	ut_tcp_input(tsock, pkts, 5);
	assert(ut_readv(tsock, 3) == 1200);

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_input_with_seq_outside_window(void)
{
	struct tcp_sock *tsock;
	struct packet *pkts[4];
	struct packet *pkt;
	uint32_t left;
	uint32_t right;

	printf("testing tcp_input with seq outside rcv win ...\n");

	tsock = ut_tcp_connect();

	/*
	 *                        left                     right
	 *                         |-----------------------|
	 *             -300   -100
	 * pkt 0:      |-------|
	 *                -200          300
	 * pkt 1:           |------------|
	 *                                             -100        300
	 * pkt 2:                                      |------------|
	 *                                                   100        400
	 * pkt 3:                                             |----------|
	 */
	left = tsock->rcv_nxt;
	right = tsock->rcv_nxt + tsock->rcv_wnd;
	pkts[0] = ut_inject_data_packet(tsock, left  - 300, 200);
	pkts[1] = ut_inject_data_packet(tsock, left  - 200, 500);
	pkts[2] = ut_inject_data_packet(tsock, right - 100, 400);
	pkts[3] = ut_inject_data_packet(tsock, right + 100, 300);

	ut_tcp_input(tsock, pkts, 4); {
		assert(ut_readv(tsock, 2) == 300);
		assert(tsock->nr_ooo_pkt == 1);

		pkt = TAILQ_FIRST(&tsock->rcv_ooo_queue);
		assert(TCP_SEG(pkt)->len == 100);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_input_dupack(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	int i;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	ut_write_assert(tsock, 1000);
	ut_tcp_output(NULL, -1);

	/* inject 2 dup acks */
	for (i = 0; i < 2; i++) {
		pkt = ut_inject_ack_packet(tsock, tsock->snd_una);
		ut_tcp_input_one(tsock, pkt); {
			assert(tcp_txq_unfinished_pkts(&tsock->txq) == 1);
		}
	}

	pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt);
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->nr_dupack == 0);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_tcp_input_basic();
	test_tcp_input_with_seq_overlap();
	test_tcp_input_with_seq_outside_window();
	test_tcp_input_dupack();

	return 0;
}
