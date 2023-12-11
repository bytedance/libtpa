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
 *
 * RFC 793:
 *
 *  Segment Receive  Test
 *  Length  Window
 *  ------- -------  -------------------------------------------
 *     0       0     SEG.SEQ = RCV.NXT
 *     0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
 *    >0       0     not acceptable
 *    >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
 *                or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
 */

#define SEQ_GOOD	0
#define SEQ_BAD		1

static uint32_t wnd;

#define do_test_tcp_seq(tsock, seq, payload_len, err)		do { 	\
	struct packet *pkt;						\
									\
	pkt = ut_inject_data_packet(tsock, seq, payload_len);		\
	tsock->stats_base[ERR_TCP_INVALID_SEQ] = 0;			\
	ut_tcp_input_one(tsock, pkt);					\
									\
	assert(tsock->stats_base[ERR_TCP_INVALID_SEQ] == err);		\
	/* reset rcv_nxt and rcv_wnd*/					\
	tsock->rcv_nxt = UINT32_MAX;					\
	tsock->rcv_wnd = wnd;						\
} while (0)

static void test_tcp_seq(void)
{
	struct tcp_sock *tsock;

	printf("testing seq ...\n");

	tsock = ut_tcp_connect();

	/* set this on purpose; so that seq wrap also could be tested */
	tsock->rcv_nxt = UINT32_MAX;

	/* case 0: len == 0, wnd == 0 */
	tsock->rcv_wnd = 0;
	do_test_tcp_seq(tsock, tsock->rcv_nxt,     0, SEQ_GOOD);
	do_test_tcp_seq(tsock, tsock->rcv_nxt - 1, 0, SEQ_BAD);
	do_test_tcp_seq(tsock, tsock->rcv_nxt + 1, 0, SEQ_BAD);

	/* case 1: len == 0, wnd > 0 */
	wnd = tsock->rcv_wnd = 1 << 20;
	do_test_tcp_seq(tsock, tsock->rcv_nxt,           0, SEQ_GOOD);
	do_test_tcp_seq(tsock, tsock->rcv_nxt + wnd - 1, 0, SEQ_GOOD);
	do_test_tcp_seq(tsock, tsock->rcv_nxt + wnd,     0, SEQ_BAD);
	do_test_tcp_seq(tsock, tsock->rcv_nxt - 1,       0, SEQ_BAD);

	/* case 2: len > 0, wnd == 0 */
	wnd = tsock->rcv_wnd = 0;
	do_test_tcp_seq(tsock, tsock->rcv_nxt,           1, SEQ_BAD);
	do_test_tcp_seq(tsock, tsock->rcv_nxt + wnd - 1, 1, SEQ_BAD);
	do_test_tcp_seq(tsock, tsock->rcv_nxt + wnd,     1, SEQ_BAD);
	do_test_tcp_seq(tsock, tsock->rcv_nxt - 1,       1, SEQ_BAD);

	/* case 3: len > 0, wnd > 0 */
	wnd = tsock->rcv_wnd = 1 << 20;
	int len = 1000;
	do_test_tcp_seq(tsock, tsock->rcv_nxt - len,     len, SEQ_BAD);
	do_test_tcp_seq(tsock, tsock->rcv_nxt - len + 1, len, SEQ_GOOD);
	do_test_tcp_seq(tsock, tsock->rcv_nxt + wnd - 1, len, SEQ_GOOD);
	do_test_tcp_seq(tsock, tsock->rcv_nxt + wnd,     len, SEQ_BAD);
}

int main(int argc, char **argv)
{
	ut_init(argc, argv);

	test_tcp_seq();
}
