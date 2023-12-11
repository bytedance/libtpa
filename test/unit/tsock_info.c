/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <sys/mman.h>

#include "test_utils.h"

#define INFO_ASSERT(x)	assert(memcmp(&info.x, &tsock->x, sizeof(info.x)) == 0)

static void test_tsock_info_basic(void)
{
	struct tcp_sock *tsock;
	struct tpa_sock_info info;

	printf("testing %s...\n", __func__);

	tsock = ut_tcp_connect();
	assert(tpa_sock_info_get(tsock->sid, &info) == 0); {
		INFO_ASSERT(local_port);
		INFO_ASSERT(remote_port);
		INFO_ASSERT(local_ip);
		INFO_ASSERT(remote_ip);

		assert(info.worker == worker);
	}

	assert(tpa_sock_info_get(-1, &info) == -1);
	assert(tpa_sock_info_get(1, &info) == -1);

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_tsock_info_basic();

	return 0;
}
