/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <unistd.h>

#include "test_utils.h"

/*
 * To test 2 cases:
 * - small writes that can be chaind
 * - TSO
 */

static void test_tcp_output_chain_basic(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	struct packet *pkt_out;
	char buf[10];
	int ret;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	ret = ut_write_assert(tsock, sizeof(buf)); assert(ret == sizeof(buf));
	ret = ut_write_assert(tsock, sizeof(buf)); assert(ret == sizeof(buf));
	ut_tcp_output(&pkt_out, 1); {
		assert((uint32_t)(tsock->snd_nxt - tsock->snd_isn) == sizeof(buf) * 2 + 1);
		assert(pkt_out->mbuf.nb_segs == 3); /* one hdr + 2 data segs */
		packet_free(pkt_out);
	}

	pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt);
	ut_tcp_input_one(tsock, pkt); {
		assert(tcp_txq_unfinished_pkts(&tsock->txq) == 0);
		assert(tsock->snd_una == tsock->snd_nxt);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

/* TODO: add testcase for mbuf alloc failure and hdr prepend error */
static void test_tcp_output_chain_dev_txq_full(void)
{
	struct tcp_sock *tsock;
	struct port_txq *txq = dev_port_txq(0, worker->queue);
	struct packet *pkt;
	char buf[10];
	int ret;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	/* simulate dev txq full */
	txq->nr_pkt = TXQ_BUF_SIZE;

	ret = ut_write_assert(tsock, sizeof(buf)); assert(ret == sizeof(buf));
	ret = ut_write_assert(tsock, sizeof(buf)); assert(ret == sizeof(buf));
	ret = ut_write_assert(tsock, sizeof(buf)); assert(ret == sizeof(buf));
	ut_tcp_output_no_drain(); {
		assert(tsock->snd_nxt == (uint32_t)(tsock->snd_isn + 1));

		/* restore sane value */
		txq->nr_pkt = 0;
	}

	/* write one more seg and xmit again when dev txq is not full */
	ret = ut_write_assert(tsock, sizeof(buf)); assert(ret == sizeof(buf));
	assert(ut_tcp_output(&pkt, 1) == 1); {
		assert(tsock->snd_nxt == (uint32_t)(tsock->snd_isn + 1 + 4 * sizeof(buf)));
		packet_free(pkt);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_output_chain_rto_retrans(void)
{
	struct tcp_sock *tsock;
	char buf[10];
	int ret;
	int i;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	for (i = 0; i < 10; i++) {
		/* let's send one seg at a time */
		tsock->snd_cwnd = (i + 1) * sizeof(buf);

		ret = ut_write_assert(tsock, sizeof(buf)); assert(ret == sizeof(buf));
		assert(ut_tcp_output(NULL, -1) == 1); {
			assert(tsock->snd_nxt == (uint32_t)(tsock->snd_isn + 1 + (i+1) * sizeof(buf)));
		}
	}

	/* simulate timeout */
	usleep(tsock->rto + 0.2 * 1e6);
	assert(ut_tcp_output(NULL, -1) == 1); {
		assert(tsock->rto_shift == 1);
	}

	/* simulate timeout again */
	usleep(tsock->rto * 2 + 0.2 * 1e6);
	cycles_update_begin(worker);
	ut_timer_process(); {
		assert(tsock->rto_shift == 2);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_output_chain_stress(void)
{
	struct tcp_sock *tsock;
	uint32_t max_size = 1<<20;
	uint32_t len;
	int ret;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	/* don't let initial wnd limit us */
	tsock->snd_wnd  = (32<<20);
	tsock->snd_cwnd = (32<<20);

	while (1) {
		/* 5% chance with big writes while the left with small writes */
		if (rand() % 100 <= 5)
			len = rand() % max_size + 1;
		else
			len = rand() % 1500 + 1;

		ret = ut_write_assert(tsock, len); {
			ut_tcp_output(NULL, -1);
		}

		if (ret < 0)
			break;
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_output_chain_stress_harder(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	uint32_t max_size = 1<<20;
	uint32_t len;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	/* don't let initial wnd limit us */
	tsock->snd_wnd  = (32<<20);
	tsock->snd_cwnd = (32<<20);
	tsock->snd_wscale = TCP_WSCALE_MAX;

	WHILE_NOT_TIME_UP() {
		/* 5% chance with big writes while the left with small writes */
		if (rand() % 100 <= 5)
			len = rand() % max_size + 1;
		else
			len = rand() % 1500 + 1;

		ut_write_assert(tsock, len); {
			ut_tcp_output(NULL, -1);
		}

		pkt = ut_inject_ack_packet(tsock, tsock->snd_una + rand() % 2000);
		ut_tcp_input_one_and_drain(tsock, pkt);
	}

	pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt);
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->snd_una == tsock->snd_nxt);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_output_chain_many(void)
{
	struct tcp_sock *tsock;
	size_t size = TSOCK_TXQ_LEN_DEFAULT;
	int i;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	for (i = 0; i < size; i++) {
		assert(ut_write(tsock, 1) == 1);
	}

	ut_tcp_output(NULL, 0); {
		assert((uint32_t)(tsock->snd_nxt - tsock->snd_isn) == size + 1);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_tcp_output_chain_basic();
	test_tcp_output_chain_dev_txq_full();
	test_tcp_output_chain_rto_retrans();
	test_tcp_output_chain_stress();
	test_tcp_output_chain_stress_harder();
	test_tcp_output_chain_many();

	return 0;
}
