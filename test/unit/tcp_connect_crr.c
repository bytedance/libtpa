/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <unistd.h>

#include "test_utils.h"

/* simulate crr test */
static void test_tcp_connect_crr_basic(void)
{
	struct tcp_sock *tsock;
	uint64_t nr_tsock;
	int rss_before;
	int rss_after;

	printf("testing %s ...\n", __func__);

	rss_before = get_rss_size_in_mb();
	nr_tsock = 0;

	WHILE_NOT_TIME_UP() {
		tsock = ut_tcp_connect();
		ut_close(tsock, CLOSE_TYPE_4WAY);

		nr_tsock += 1;
	}
	rss_after = get_rss_size_in_mb();

	printf("%lu socks created in total\n", nr_tsock);
	printf("rss diff: %d - %d = %d\n", rss_after, rss_before, rss_after - rss_before);
	assert(rss_after - rss_before < 100);
}

#define NR_OPEN_SOCK		4096

/* close tsocks in batch */
static void test_tcp_connect_crr_basic2(void)
{
	struct tcp_sock *tsocks[NR_OPEN_SOCK];
	uint64_t nr_tsock;
	int rss_before;
	int rss_after;
	int i;

	printf("testing %s ...\n", __func__);

	rss_before = get_rss_size_in_mb();
	nr_tsock = 0;

	WHILE_NOT_TIME_UP() {
		tsocks[nr_tsock++] = ut_tcp_connect();

		if (nr_tsock == NR_OPEN_SOCK) {
			for (i = 0; i < nr_tsock; i++)
				ut_close(tsocks[i], CLOSE_TYPE_4WAY);

			nr_tsock = 0;
		}
	}

	for (i = 0; i < nr_tsock; i++)
		ut_close(tsocks[i], CLOSE_TYPE_4WAY);

	rss_after = get_rss_size_in_mb();

	printf("%lu socks created in total\n", nr_tsock);
	printf("rss diff: %d - %d = %d\n", rss_after, rss_before, rss_after - rss_before);
	assert(rss_after - rss_before < 100);
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);
	ut_test_opts.silent = 1;

	test_tcp_connect_crr_basic();
	test_tcp_connect_crr_basic2();

	return 0;
}
