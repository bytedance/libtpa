/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>

#include "test_utils.h"

#define DATA_SIZE	1000

/*
 * TODO:
 * - dup acks with no outstanding data
 */
static void test_tcp_output_fast_retrans_basic(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	uint32_t ack;
	int ret;
	int i;

	printf("testing tcp_output fast retransmit [basic] ...\n");

	tsock = ut_tcp_connect();

	ret = ut_write_assert(tsock, DATA_SIZE);
	ut_tcp_output(NULL, -1); {
		assert(ret == DATA_SIZE);
		assert((uint32_t)(tsock->snd_nxt - tsock->snd_isn) == DATA_SIZE + 1);
		assert(tcp_txq_unfinished_pkts(&tsock->txq) == 1);
	}

	/* inject 3 dup acks */
	ack = tsock->snd_una;
	for (i = 0; i < 3; i++) {
		pkt = ut_inject_ack_packet(tsock, ack);
		ut_tcp_input_one(tsock, pkt); {
			assert(tcp_txq_unfinished_pkts(&tsock->txq) == 1);
		}
	}
	assert(tsock->retrans_stage == FAST_RETRANS);
	assert(tcp_txq_unfinished_pkts(&tsock->txq) == 1);

	/* mark the end of fast-retrans */
	pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt);
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->retrans_stage == NONE);
		assert(tsock->snd_una == tsock->snd_nxt);
		assert(tcp_txq_unfinished_pkts(&tsock->txq) == 0);
		assert(ut_tcp_output(NULL, 1) == 1);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

/* test pkt chain in fast retrans */
static void test_tcp_output_fast_retrans_basic2(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	uint32_t ack;
	int ret;
	int i;

	printf("testing tcp_output fast retransmit [basic2] ...\n");

	tsock = ut_tcp_connect();

	/* 3 segs */
	ret = ut_write_assert(tsock, DATA_SIZE);
	ret = ut_write_assert(tsock, DATA_SIZE);
	ret = ut_write_assert(tsock, DATA_SIZE);
	ut_tcp_output(NULL, -1); {
		assert(ret == DATA_SIZE);
		assert((uint32_t)(tsock->snd_nxt - tsock->snd_isn) == DATA_SIZE * 3 + 1);
		assert(tcp_txq_unfinished_pkts(&tsock->txq) == 3);
	}

	/* inject 3 dup acks */
	ack = tsock->snd_una;
	for (i = 0; i < 3; i++) {
		pkt = ut_inject_ack_packet(tsock, ack);
		ut_tcp_input_one(tsock, pkt); {
			assert(tcp_txq_unfinished_pkts(&tsock->txq) == 3);
		}
	}
	assert (ut_tcp_output(&pkt, 1) == 1); {
		assert(tsock->retrans_stage == FAST_RETRANS);
		assert(tcp_txq_unfinished_pkts(&tsock->txq) == 3);

		assert(pkt->mbuf.pkt_len == tsock->snd_mss + pkt->hdr_len);
		packet_free(pkt);
	}

	/* mark the end of fast-retrans */
	pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt);
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->retrans_stage == NONE);
		assert(tsock->snd_una == tsock->snd_nxt);
		assert(tcp_txq_unfinished_pkts(&tsock->txq) == 0);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_output_fast_retrans_multi_drop(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	uint32_t ack;
	int i;

	printf("testing tcp_output fast retransmit [multi drop] ...\n");

	tsock = ut_tcp_connect();

	ut_write_assert(tsock, DATA_SIZE);
	ut_write_assert(tsock, DATA_SIZE);
	ut_tcp_output(NULL, -1); {
		assert((uint32_t)(tsock->snd_nxt - tsock->snd_una) == 2 * DATA_SIZE);
		assert(tcp_txq_unfinished_pkts(&tsock->txq) == 2);
	}

	/* inject 3 dup acks */
	ack = tsock->snd_una + 24;
	for (i = 0; i < 4; i++) {
		pkt = ut_inject_ack_packet(tsock, ack);
		ut_tcp_input_one(tsock, pkt); {
			assert(tcp_txq_unfinished_pkts(&tsock->txq) == 2);
		}
	}; {
		assert(tsock->retrans_stage == FAST_RETRANS);
		assert(tcp_txq_unfinished_pkts(&tsock->txq) == 2);
		assert(ut_tcp_output(NULL, 1) == 1);
	}

	/* we still miss one last byte */
	pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt - 1);
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->retrans_stage == FAST_RETRANS);
		assert(tsock->snd_una == tsock->snd_nxt - 1);
		assert(tcp_txq_unfinished_pkts(&tsock->txq) == 1);
	}

	/* mark the end of retrans */
	pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt);
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->retrans_stage == NONE);
		assert(tsock->snd_una == tsock->snd_nxt);
		assert(tcp_txq_unfinished_pkts(&tsock->txq) == 0);
		assert(ut_tcp_output(NULL, 1) == 1);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_output_fast_retrans_seq_wrap(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	uint32_t ack;
	uint32_t off;
	int ret;
	int i;

	printf("testing tcp_output fast retransmit [seq wrap] ...\n");

	tsock = ut_tcp_connect();

	off = UINT32_MAX - tsock->snd_una + 1;
	if (off < UINT32_MAX / 2)
		off += UINT32_MAX / 2;
	tsock->snd_una += off;
	tsock->snd_nxt += off;
	tsock->data_seq_nxt += off;
	assert(tsock->snd_una < tsock->snd_recover);

	ret = ut_write_assert(tsock, DATA_SIZE);
	ut_tcp_output(NULL, -1); {
		assert(ret == DATA_SIZE);
		assert(tsock->snd_nxt - tsock->snd_una == DATA_SIZE);
		assert(tcp_txq_unfinished_pkts(&tsock->txq) == 1);
	}

	/* inject 3 dup acks */
	ack = tsock->snd_una + 2;
	for (i = 0; i < 4; i++) {
		pkt = ut_inject_ack_packet(tsock, ack);
		ut_tcp_input_one(tsock, pkt); {
			assert(tcp_txq_unfinished_pkts(&tsock->txq) == 1);
		}
	}
	assert(tsock->retrans_stage == FAST_RETRANS);
	assert(tcp_txq_unfinished_pkts(&tsock->txq) == 1);

	/* mark the end of fast-retrans */
	pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt);
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->retrans_stage == NONE);
		assert(tsock->snd_una == tsock->snd_nxt);
		assert(tcp_txq_unfinished_pkts(&tsock->txq) == 0);
		assert(ut_tcp_output(NULL, 1) == 1);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_output_fast_retrans_stress(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	uint32_t ack;
	int ret;
	int i;

#define NR_WARM_UP_PKT		10240

	printf("testing tcp_output fast retransmit [stress] ...\n");

	tsock = ut_tcp_connect();

	for (i = 0; i < NR_WARM_UP_PKT; i++) {
		ut_write_assert(tsock, 65536);
		ut_tcp_output(NULL, -1);

		pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt);
		ut_tcp_input_one(tsock, pkt);
	}
	assert(tsock->snd_cwnd > tcp_cfg.cwnd_init);

	WHILE_NOT_TIME_UP() {
		do {
			ret = ut_write_assert(tsock, DATA_SIZE);
			ut_tcp_output(NULL, -1);
		} while (ret == DATA_SIZE);

		if (rand() % 100 <= 1) {
			uint32_t inflight_size = tsock->snd_nxt - tsock->snd_una;
			int nr_dup_ack = rand() % (inflight_size / tsock->snd_mss + 1);

			ack = tsock->snd_una + rand() % (inflight_size - 100) + 1;
			nr_dup_ack = RTE_MAX(nr_dup_ack, 3);

			for (i = 0; i < nr_dup_ack; i++) {
				pkt = ut_inject_ack_packet(tsock, ack);
				ut_tcp_input_one(tsock, pkt);
			}
		} else if (rand() % 100 <= 20) {
			pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt);
			ut_tcp_input_one(tsock, pkt); {
				assert(tsock->snd_nxt == tsock->snd_una);
			}
		}
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_output_fast_retrans_mbuf_chains(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	char buf[400];
	uint32_t ack;
	int ret;
	int i;

	printf("testing tcp_output fast retransmit [with mbuf chains] ...\n");

	tsock = ut_tcp_connect();

#define NR_PKT		10
	for (i = 0; i < NR_PKT; i++) {
		ret = ut_write_assert(tsock, sizeof(buf));
		assert(ret == sizeof(buf));
	}
	ut_tcp_output(NULL, -1); {
		assert((uint32_t)(tsock->snd_nxt - tsock->snd_isn) == NR_PKT * sizeof(buf) + 1);
		assert(tcp_txq_unfinished_pkts(&tsock->txq) == NR_PKT);
	}

	/* inject 3 dup acks */
	ack = tsock->snd_una;
	for (i = 0; i < 3; i++) {
		pkt = ut_inject_ack_packet(tsock, ack);
		ut_tcp_input_one(tsock, pkt); {
			assert(tcp_txq_unfinished_pkts(&tsock->txq) == NR_PKT);
		}
	}
	assert(tsock->retrans_stage == FAST_RETRANS);
	assert(ut_tcp_output(NULL, 0) == 1);


	/* ack segs one by one */
	for (i = 0; i < NR_PKT - 2; i++) {
		pkt = ut_inject_ack_packet(tsock, tsock->snd_una + sizeof(buf));
		ut_tcp_input_one(tsock, pkt); {
			assert(tsock->retrans_stage == FAST_RETRANS);
		}
	}

	/* ack the last seg */
	pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt);
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->retrans_stage == NONE);
		ut_tcp_output(NULL, 0);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_output_fast_retrans_dev_txq_full(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	struct port_txq *txq = dev_port_txq(0, worker->queue);
	uint32_t ack;
	int ret;
	int i;

	printf("testing tcp_output fast retransmit [txq full] ...\n");

	tsock = ut_tcp_connect();

	ret = ut_write_assert(tsock, DATA_SIZE);
	ut_tcp_output(NULL, -1); {
		assert(ret == DATA_SIZE);
		assert((uint32_t)(tsock->snd_nxt - tsock->snd_isn) == DATA_SIZE + 1);
		assert(tcp_txq_unfinished_pkts(&tsock->txq) == 1);
	}

	/* simulate dev txq full */
	assert(txq->nr_pkt == 0);
	txq->nr_pkt = TXQ_BUF_SIZE;

	/* inject 3 dup acks */
	ack = tsock->snd_una;
	for (i = 0; i < 3; i++) {
		pkt = ut_inject_ack_packet(tsock, ack);
		ut_tcp_input_one(tsock, pkt); {
			assert(tcp_txq_unfinished_pkts(&tsock->txq) == 1);
		}
	}
	assert(tcp_txq_unfinished_pkts(&tsock->txq) == 1);
	assert(tsock->stats_base[PKT_FAST_RE_XMIT_ERR] == 1);

	/* TODO: we should really not enter recovery state when fast rexmit failed */
	assert(tsock->retrans_stage == FAST_RETRANS);

	/* restore sane value */
	txq->nr_pkt = 0;
	ut_close(tsock, CLOSE_TYPE_4WAY);
}

/*
 * make sure fast retrans doesn't send new data out
 */
static void test_tcp_output_fast_retrans_new_write(void)
{
	struct tcp_sock *tsock;
	struct packet *pkts[4];
	struct packet *pkt;
	uint32_t cwnd;
	uint32_t snd_nxt;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	cwnd = tsock->snd_cwnd;
	ut_zwrite(tsock, cwnd + 1); /* leaves one byte untransfered for that desc */
	ut_tcp_output(NULL, -1);

	/* another write */
	ut_zwrite(tsock, cwnd);

	/* inject dup acks; need 4, as the first does ack something */
	snd_nxt = tsock->snd_nxt;
	pkts[0] = ut_inject_ack_packet(tsock, snd_nxt - 1);
	pkts[1] = ut_inject_ack_packet(tsock, snd_nxt - 1);
	pkts[2] = ut_inject_ack_packet(tsock, snd_nxt - 1);
	pkts[3] = ut_inject_ack_packet(tsock, snd_nxt - 1);
	ut_tcp_input(tsock, pkts, 4); {
		ut_tcp_output(&pkt, 1); {
			assert(TCP_SEG(pkt)->seq == snd_nxt - 1);
			assert(TCP_SEG(pkt)->len == 1);

			packet_free(pkt);
		}
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_tcp_output_fast_retrans_basic();
	test_tcp_output_fast_retrans_basic2();
	test_tcp_output_fast_retrans_seq_wrap();
	test_tcp_output_fast_retrans_multi_drop();
	test_tcp_output_fast_retrans_stress();
	test_tcp_output_fast_retrans_mbuf_chains();
	test_tcp_output_fast_retrans_dev_txq_full();
	test_tcp_output_fast_retrans_new_write();

	return 0;
}
