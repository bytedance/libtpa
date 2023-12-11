/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>

#include "test_utils.h"

static void test_sock_table_basic(void)
{
	struct tcp_sock tsock;
	struct sock_key key;

	memset(&tsock, 0, sizeof(tsock));
	tpa_ip_set_ipv4(&tsock.local_ip, CLIENT_IP);
	tpa_ip_set_ipv4(&tsock.remote_ip, SERVER_IP);
	tsock.local_port = htons(3456);
	tsock.remote_port = htons(80);

	sock_key_init(&key, &tsock.remote_ip, ntohs(tsock.remote_port),
		      &tsock.local_ip, ntohs(tsock.local_port));

	assert(sock_table_add(&worker->sock_table, &key, &tsock) == 0);
	assert(sock_table_lookup(&worker->sock_table, &key) == &tsock);
	assert(sock_table_del(&worker->sock_table, &key) == 0);
}

/* TODO:
 * - full size test: make sure tcp_cfg.nr_max_sock entry can be stored
 * - stress test
 */

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_sock_table_basic();

	return 0;
}
