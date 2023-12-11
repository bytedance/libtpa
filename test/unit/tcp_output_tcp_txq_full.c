/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>

#include "test_utils.h"

static void test_tcp_output_tcp_txq_full(void)
{
	struct tcp_sock *tsock;
	int ret;

	printf("testing tcp_output [tcp txq full] ...\n");

	tsock = ut_tcp_connect();

	/* simulate tcp_txq full */
	tsock->txq.write = tsock->txq.size;

	ret = ut_write(tsock, MESSAGE_SIZE);
	assert(ret == -1 && errno == EAGAIN);

	/* restore sane value */
	tsock->txq.write = tsock->txq.una;

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_tcp_output_tcp_txq_full();

	return 0;
}
