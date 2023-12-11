/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>

#include "test_utils.h"

static void test_tcp_output_invalid_ack(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	uint32_t snd_una;
	int count;
	int ret;

	printf("testing tcp_output invalid ack ...\n");

	tsock = ut_tcp_connect();

	ret = ut_write_assert(tsock, MESSAGE_SIZE);
	assert(ret == MESSAGE_SIZE);
	tcp_output(worker);
	count = tcp_txq_unfinished_pkts(&tsock->txq);
	assert(count >= 1);

	snd_una = tsock->snd_una;
	pkt = ut_inject_ack_packet(tsock, tsock->snd_una - 1);
	ut_tcp_input_one(tsock, pkt);
	/* TODO: check ACK pkts sent out */
	assert(tsock->snd_una == snd_una);
	assert(tcp_txq_unfinished_pkts(&tsock->txq) == count);

	pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt + 1);
	ut_tcp_input_one(tsock, pkt);
	assert(tsock->snd_una == snd_una);
	assert(tcp_txq_unfinished_pkts(&tsock->txq) == count);

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_tcp_output_invalid_ack();

	return 0;
}
