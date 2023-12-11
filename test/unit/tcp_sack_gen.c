/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>

#include "test_utils.h"

/*
 * case 1: The first 4 segments are received but the last 4 are dropped.
 */
static void test_tcp_sack_gen_rfc2018_case1(void)
{
	struct tcp_sock *tsock;
	struct packet *pkts[8];
	struct packet *pkt;
	struct tcp_opts opts;
	int i;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	for (i = 0; i < 4; i++)
		pkts[i] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 500 * i, 500);

	ut_tcp_input(tsock, pkts, 4);
	assert(ut_tcp_output(&pkt, 1) == 1); {
		assert(parse_tcp_opts(&opts, pkt) == 0);
		assert(opts.nr_sack == 0);

		ut_readv(tsock, 4);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

/*
 * case 2: The first segment is dropped but the remaining 7 are received.
 */
static void test_tcp_sack_gen_rfc2018_case2(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	struct tcp_opts opts;
	int i;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	tsock->rcv_nxt = 5000;
	for (i = 1; i < 8; i++) {
		pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt + 500 * i, 500);
		ut_tcp_input_one(tsock, pkt);

		assert(ut_tcp_output(&pkt, 1) == 1); {
			assert(parse_tcp_opts(&opts, pkt) == 0);
			assert(opts.nr_sack == 1);
			assert(opts.nr_sack == 1);
			assert(opts.sack_blocks[0].start == 5500);
			assert(opts.sack_blocks[0].end   == 5500 + 500 * i);
		}
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

/*
 * case 3: The 2nd, 4th, 6th, and 8th (last) segments are dropped.
 */
static void test_tcp_sack_gen_rfc2018_case3(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	struct tcp_opts opts;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();
	tsock->rcv_nxt = 5000;

	/* 1st pkt */
	pkt = ut_inject_data_packet(tsock, 5000, 500);
	ut_tcp_input_one(tsock, pkt);
	assert(ut_tcp_output(&pkt, 1) == 1); {
		assert(TCP_SEG(pkt)->ack == 5500);

		assert(parse_tcp_opts(&opts, pkt) == 0);
		assert(opts.nr_sack == 0);
	}

	/* 3rd pkt */
	pkt = ut_inject_data_packet(tsock, 6000, 500);
	ut_tcp_input_one(tsock, pkt);
	assert(ut_tcp_output(&pkt, 1) == 1); {
		assert(TCP_SEG(pkt)->ack == 5500);

		assert(parse_tcp_opts(&opts, pkt) == 0);
		assert(opts.nr_sack == 1);
		assert(opts.sack_blocks[0].start == 6000);
		assert(opts.sack_blocks[0].end   == 6500);
	}

	/* 5th pkt */
	pkt = ut_inject_data_packet(tsock, 7000, 500);
	ut_tcp_input_one(tsock, pkt);
	assert(ut_tcp_output(&pkt, 1) == 1); {
		assert(TCP_SEG(pkt)->ack == 5500);

		assert(parse_tcp_opts(&opts, pkt) == 0);
		assert(opts.nr_sack == 2);

		assert(opts.sack_blocks[0].start == 7000);
		assert(opts.sack_blocks[0].end   == 7500);

		assert(opts.sack_blocks[1].start == 6000);
		assert(opts.sack_blocks[1].end   == 6500);
	}

	/* 7th pkt */
	pkt = ut_inject_data_packet(tsock, 8000, 500);
	ut_tcp_input_one(tsock, pkt);
	assert(ut_tcp_output(&pkt, 1) == 1); {
		assert(TCP_SEG(pkt)->ack == 5500);

		assert(parse_tcp_opts(&opts, pkt) == 0);
		assert(opts.nr_sack == 3);

		assert(opts.sack_blocks[0].start == 8000);
		assert(opts.sack_blocks[0].end   == 8500);

		assert(opts.sack_blocks[1].start == 7000);
		assert(opts.sack_blocks[1].end   == 7500);

		assert(opts.sack_blocks[2].start == 6000);
		assert(opts.sack_blocks[2].end   == 6500);
	}

	/* 4th pkt */
	pkt = ut_inject_data_packet(tsock, 6500, 500);
	ut_tcp_input_one(tsock, pkt);
	assert(ut_tcp_output(&pkt, 1) == 1); {
		assert(TCP_SEG(pkt)->ack == 5500);

		assert(parse_tcp_opts(&opts, pkt) == 0);
		assert(opts.nr_sack == 2);

		assert(opts.sack_blocks[0].start == 6000);
		assert(opts.sack_blocks[0].end   == 7500);

		assert(opts.sack_blocks[1].start == 8000);
		assert(opts.sack_blocks[1].end   == 8500);
	}

	/* 2nd pkt */
	pkt = ut_inject_data_packet(tsock, 5500, 500);
	ut_tcp_input_one(tsock, pkt);
	assert(ut_tcp_output(&pkt, 1) == 1); {
		assert(TCP_SEG(pkt)->ack == 7500);

		assert(parse_tcp_opts(&opts, pkt) == 0);
		assert(opts.nr_sack == 1);

		assert(opts.sack_blocks[0].start == 8000);
		assert(opts.sack_blocks[0].end   == 8500);
	}

	ut_readv(tsock, 7);

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_sack_gen_with_tso(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	struct tcp_opts opts;

	printf("testing %s ...\n", __func__);

	ut_test_opts.with_tso = 1;
	tsock = ut_tcp_connect();

	/* trigger sack generation */
	pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt + 1, 500);
	ut_tcp_input_one(tsock, pkt);
	assert(ut_tcp_output(&pkt, 1) == 1); {
		assert(parse_tcp_opts(&opts, pkt) == 0);
		assert(opts.nr_sack == 1);
		packet_free(pkt);
	}

	ut_write_assert(tsock, tsock->snd_mss + 1);
	assert(ut_tcp_output(&pkt, 1) == 1); {
		assert(opts.nr_sack == 1);
		assert(pkt->mbuf.tso_segsz == tsock->snd_mss - TCP_OPT_SACK_SPACE(1));
		packet_free(pkt);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_tcp_sack_gen_rfc2018_case1();
	test_tcp_sack_gen_rfc2018_case2();
	test_tcp_sack_gen_rfc2018_case3();

	test_tcp_sack_gen_with_tso();

	return 0;
}
