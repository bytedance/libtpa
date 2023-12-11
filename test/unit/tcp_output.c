/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>

#include "test_utils.h"

static void test_tcp_output_basic(void)
{
	struct tcp_sock *tsock;
	int ret;

	printf("testing tcp_output basic ...\n");

	tsock = ut_tcp_connect();

	ret = ut_write_assert(tsock, MESSAGE_SIZE);
	assert(ret == MESSAGE_SIZE);
	assert(ut_tcp_output(NULL, 0) >= 1);

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_tcp_output_basic();

	return 0;
}
