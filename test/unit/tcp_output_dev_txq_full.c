/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>

#include "test_utils.h"

/*
 * TODO: need be refined: every time we change dev or tcp txq size,
 * we break this case
 */
static void test_tcp_output_dev_txq_full(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	char buf[500];
	int ret;
	int i;

	printf("testing tcp_output [dev txq full] ...\n");

	tsock = ut_tcp_connect();
	tsock->snd_cwnd = 512 << 20;
	tsock->snd_wnd  = 512 << 20;

#define NR_PKT		((TXQ_BUF_SIZE + 1) * 2)
	for (i = 0; i < NR_PKT; i++) {
		ret = ut_write_assert(tsock, sizeof(buf));
		assert(ret == sizeof(buf));
	}

	ut_tcp_output(NULL, 0);
	assert(tsock->stats_base[ERR_DEV_TXQ_FULL] == 1);
	for (i = 0; i < tcp_txq_unfinished_pkts(&tsock->txq); i++) {
		pkt = tcp_txq_peek_una(tsock, i); {
			assert(TCP_SEG(pkt)->len <= tsock->snd_mss);
			assert((uint32_t)(TCP_SEG(pkt)->seq - tsock->snd_una) == i * sizeof(buf));
		}
	}

	/* try again to xmit the un-sent pkt */
	ut_tcp_output(NULL, 0);
	for (i = 0; i < tcp_txq_unfinished_pkts(&tsock->txq); i++) {
		pkt = tcp_txq_peek_una(tsock, i); {
			assert(TCP_SEG(pkt)->len <= tsock->snd_mss);
			assert((uint32_t)(TCP_SEG(pkt)->seq - tsock->snd_una) == i * sizeof(buf));
		}
		packet_free_seg(pkt);
	}
	assert(tsock->stats_base[BYTE_XMIT] == NR_PKT * sizeof(buf));
	assert(tsock->stats_base[PKT_XMIT]  == NR_PKT);
	assert((uint32_t)(tsock->snd_nxt - tsock->snd_una) == NR_PKT * sizeof(buf));

	ut_dump_tsock_stats(tsock);
	ut_assert_mbuf_count();
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	ut_with_timer = 0;

	test_tcp_output_dev_txq_full();

	return 0;
}
