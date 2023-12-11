/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <unistd.h>

#include "test_utils.h"

#define UT_TSOCK_TXQ_LEN		4
#define NR_DESC				32

static struct tx_desc *descs[NR_DESC];

static void tcp_txq_create(struct tcp_txq *txq, int queue_len)
{
	txq->descs = malloc(queue_len * sizeof(void *));
	tcp_txq_init(txq, queue_len);
}

static int __rte_noinline txq_enqueue_bulk(struct tcp_txq *txq, uint16_t nr_desc)
{
	return tcp_txq_enqueue_bulk(txq, (void **)descs, nr_desc);
}

static void test_tsock_txq_basic(void)
{
	struct tcp_txq txq;

	printf("testing tsock txq [basic] ...\n");

	tcp_txq_create(&txq, UT_TSOCK_TXQ_LEN);

	assert(txq_enqueue_bulk(&txq, 1) == 0); {
		assert(tcp_txq_peek_una(&txq, 0) == descs[0]);
		assert(tcp_txq_peek_una(&txq, 1) == NULL);
	}

	tcp_txq_update_una(&txq, 1);
}

static void test_tsock_txq_full(void)
{
	struct tcp_txq txq;
	int i;

	printf("testing tsock txq [full] ...\n");

	tcp_txq_create(&txq, UT_TSOCK_TXQ_LEN);

	for (i = 0; i < txq.size; i++) {
		assert(txq_enqueue_bulk(&txq, 1) == 0); {
			assert(tcp_txq_peek_una(&txq, i) == descs[0]);
			assert(tcp_txq_peek_una(&txq, i + 1) == NULL);
		}
	}

	assert(txq_enqueue_bulk(&txq, 1) == -1);
	tcp_txq_update_una(&txq, txq.size);
}

static void test_tsock_txq_full_wrapped(void)
{
	struct tcp_txq txq;
	int i;

	printf("testing tsock txq [full and wrapped] ...\n");

	tcp_txq_create(&txq, UT_TSOCK_TXQ_LEN);

	txq.una = -2;
	txq.nxt = -2;
	txq.write = -2;

	for (i = 0; i < txq.size; i++) {
		assert(txq_enqueue_bulk(&txq, 1) == 0); {
			assert(tcp_txq_peek_una(&txq, i) == descs[0]);
			assert(tcp_txq_peek_una(&txq, i + 1) == NULL);
		}
	}

	assert(txq_enqueue_bulk(&txq, 1) == -1);
}

static void test_tsock_txq_stress(void)
{
	struct tcp_txq txq;
	int len;
	int i;

	printf("testing tsock txq [stress] ...\n");

	tcp_txq_create(&txq, TSOCK_TXQ_LEN_DEFAULT);

	WHILE_NOT_TIME_UP() {
		len = rand() % txq.size;
		for (i = 0; i < len; i++) {
			assert(txq_enqueue_bulk(&txq, 1) == 0); {
				assert(tcp_txq_peek_una(&txq, i) == descs[0]);
				assert(tcp_txq_peek_una(&txq, i + 1) == NULL);
			}
		}

		tcp_txq_update_una(&txq, len);
	}
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_tsock_txq_basic();
	test_tsock_txq_full();
	test_tsock_txq_full_wrapped();
	test_tsock_txq_stress();

	return 0;
}
