/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>

#include "test_utils.h"

static void test_tcp_sack_rcv_basic(void)
{
	struct tcp_sack_block blocks[3];
	struct tcp_sock *tsock;
	struct tx_desc **descs;
	struct packet *pkt;
	int ret;
	int i;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	for (i = 0; i < 10; i++) {
		ret = ut_write_assert(tsock, 1000); assert(ret == 1000);
	}
	ut_tcp_output(NULL, -1);

	blocks[0] = (struct tcp_sack_block) { tsock->snd_una + 8000, tsock->snd_una + 10000 };
	blocks[1] = (struct tcp_sack_block) { tsock->snd_una + 2500, tsock->snd_una + 5001 };
	blocks[2] = (struct tcp_sack_block) { tsock->snd_una + 500,  tsock->snd_una + 2400 };
	pkt = ut_inject_sack_packet(tsock, tsock->snd_una, blocks, 3);
	ut_tcp_input_one(tsock, pkt); {
		descs = (struct tx_desc **)tsock->txq.descs;

		assert(!!(descs[0]->flags & TX_DESC_FLAG_SACKED) == 0);
		assert(!!(descs[1]->flags & TX_DESC_FLAG_SACKED) == 1);
		assert(!!(descs[2]->flags & TX_DESC_FLAG_SACKED) == 0);
		assert(!!(descs[3]->flags & TX_DESC_FLAG_SACKED) == 1);
		assert(!!(descs[4]->flags & TX_DESC_FLAG_SACKED) == 1);
		assert(!!(descs[5]->flags & TX_DESC_FLAG_SACKED) == 0);
		assert(!!(descs[6]->flags & TX_DESC_FLAG_SACKED) == 0);
		assert(!!(descs[7]->flags & TX_DESC_FLAG_SACKED) == 0);
		assert(!!(descs[8]->flags & TX_DESC_FLAG_SACKED) == 1);
		assert(!!(descs[9]->flags & TX_DESC_FLAG_SACKED) == 0);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_tcp_sack_rcv_basic();

	return 0;
}
