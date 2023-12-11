/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <getopt.h>
#include <sys/uio.h>

#include "test_utils.h"

static void ooo_queue_sanity_check(struct tcp_sock *tsock)
{
	struct packet *prev = NULL;
	struct packet *pkt;

	TAILQ_FOREACH(pkt, &tsock->rcv_ooo_queue, node) {
		if (prev) {
			assert(seq_lt(TCP_SEG(prev)->seq, TCP_SEG(pkt)->seq));
			assert(seq_lt(TCP_SEG(prev)->seq + TCP_SEG(prev)->len - 1, TCP_SEG(pkt)->seq));
		}
		prev = pkt;
	}
}

static void test_tcp_input_ooo_basic(void)
{
	struct tcp_sock *tsock;
	struct packet *pkts[4];
	struct tpa_iovec iov[4];
	uint32_t off = 0;

	printf("testing tcp_input with out of order rcv ...\n");

	tsock = ut_tcp_connect();

	pkts[0] = ut_inject_data_packet(tsock, tsock->rcv_nxt + off, 1000); off += 1000;
	pkts[1] = ut_inject_data_packet(tsock, tsock->rcv_nxt + off, 1000); off += 1000;
	pkts[2] = ut_inject_data_packet(tsock, tsock->rcv_nxt + off, 1000); off += 1000;
	pkts[3] = ut_inject_data_packet(tsock, tsock->rcv_nxt + off, 1000); off += 1000;

	ut_tcp_input_one(tsock, pkts[2]); {
		assert(tpa_zreadv(tsock->sid, iov, 4) == -1 && errno == EAGAIN);
		assert(!TAILQ_EMPTY(&tsock->rcv_ooo_queue));
	}

	ut_tcp_input_one(tsock, pkts[1]); {
		assert(tpa_zreadv(tsock->sid, iov, 4) == -1 && errno == EAGAIN);
		assert(!TAILQ_EMPTY(&tsock->rcv_ooo_queue));
	}

	ut_tcp_input_one(tsock, pkts[0]); {
		assert(tpa_zreadv(tsock->sid, iov, 4) == 3000);
		assert(TAILQ_EMPTY(&tsock->rcv_ooo_queue));
		iov[0].iov_read_done(iov[0].iov_base, iov[0].iov_param);
		iov[1].iov_read_done(iov[1].iov_base, iov[1].iov_param);
		iov[2].iov_read_done(iov[2].iov_base, iov[2].iov_param);
	}

	ut_tcp_input_one(tsock, pkts[3]); {
		assert(tpa_zreadv(tsock->sid, iov, 4) == 1000);
		assert(tsock->last_ack_sent == tsock->rcv_nxt);
		assert(TAILQ_EMPTY(&tsock->rcv_ooo_queue));
		iov[0].iov_read_done(iov[0].iov_base, iov[0].iov_param);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_input_ooo_overlap(void)
{
	struct tcp_sock *tsock;
	struct packet *pkts[64];
	struct packet *pkt;

	printf("testing tcp_input with out of order rcv with seq overlap ...\n");

	tsock = ut_tcp_connect();

	/*
	 *                            1000                 2000
	 * pkt 0:                      |--------------------|
	 *            500 600
	 * pkt 1:      |---|
	 *                  700    900
	 * pkt 2:            |------|
	 *                  700    900
	 * pkt 3:            |------|
	 *                     800       1100
	 * pkt 4:               |---------|
	 *                  700                               2100
	 * pkt 5:            |---------------------------------|
	 *                                   1200     1300
	 * pkt 6:                             |--------|
	 *                                                   2099   2300
	 * pkt 7:                                             |------|
	 *                                               2000   2200
	 * pkt 8:                                         |------|
	 *                                                            2400  2500
	 * pkt 9:                                                       |-----|
	 */
	pkts[0] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 1000, 1000);
	pkts[1] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 500,  100);
	pkts[2] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 700,  200);
	pkts[3] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 700,  200);
	pkts[4] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 800,  300);
	pkts[5] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 700,  1400);
	pkts[6] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 1200, 200);
	pkts[7] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 2099, 201);
	pkts[8] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 2000, 200);
	pkts[9] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 2400, 100);

	ut_tcp_input(tsock, pkts, 10); {
		assert(tcp_rxq_readable_count(&tsock->rxq) == 0);
		assert(tsock->nr_ooo_pkt == 4);

		pkt = TAILQ_FIRST(&tsock->rcv_ooo_queue);
		assert(TCP_SEG(pkt)->seq == tsock->rcv_nxt + 500 && TCP_SEG(pkt)->len == 100);

		pkt = TAILQ_NEXT(pkt, node);
		assert(TCP_SEG(pkt)->seq == tsock->rcv_nxt + 700 && TCP_SEG(pkt)->len == 1400);

		pkt = TAILQ_NEXT(pkt, node);
		assert(TCP_SEG(pkt)->seq == tsock->rcv_nxt + 2100 && TCP_SEG(pkt)->len == 200);

		pkt = TAILQ_NEXT(pkt, node);
		assert(TCP_SEG(pkt)->seq == tsock->rcv_nxt + 2400 && TCP_SEG(pkt)->len == 100);

		printf("\tnr_ooo_pkt:\t %u\n", tsock->nr_ooo_pkt);

		assert(tsock->nr_sack_block == 3);
		assert(tsock->sack_blocks[0].start == tsock->rcv_nxt + 2400);
		assert(tsock->sack_blocks[0].end   == tsock->rcv_nxt + 2400 + 100);

		assert(tsock->sack_blocks[1].start == tsock->rcv_nxt + 700);
		assert(tsock->sack_blocks[1].end   == tsock->rcv_nxt + 700 + 1600);

		assert(tsock->sack_blocks[2].start == tsock->rcv_nxt + 500);
		assert(tsock->sack_blocks[2].end   == tsock->rcv_nxt + 500 + 100);

		/* drain acks */
		ut_tcp_output(NULL, -1);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_input_ooo_tcp_rxq_enqueue_failure(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	int i;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	/* make sure tcp_cfg.rcv_ooo_limit equal to rxq size */
	tcp_cfg.rcv_ooo_limit = tsock->rxq.size;
	for (i = 0; i < tsock->rxq.size; i++) {
		pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt + (i + 1) * 1000, 1000);
		ut_tcp_input_one(tsock, pkt); {
			assert(tsock->nr_ooo_pkt == i + 1);
		}
	}

	/* fill the hole */
	pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt, 1000);
	ut_tcp_input_one(tsock, pkt); {
		/*
		 * the rxq is full; we have one more IN-ORDER pkt left
		 * in the ooo queue
		 */
		assert(tsock->nr_ooo_pkt == 1);
		assert(tsock->stats_base[ERR_TCP_RXQ_ENQUEUE_FAIL] == 1);
	}

	/* drain the tcp rxq */
	assert(ut_readv(tsock, tsock->rxq.size) == tsock->rxq.size * 1000);

	/* reject last pkt should deliver above IN-ORDER pkt in ooo queue to tsock rxq */
	pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt, 1000);
	ut_tcp_input_one(tsock, pkt); {
		assert(ut_readv(tsock, tsock->rxq.size) == 1000);
		assert(tsock->nr_ooo_pkt == 0);
		assert(tsock->nr_sack_block == 0);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_input_ooo_tcp_rxq_enqueue_failure2(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	int i;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	/* make sure tcp_cfg.rcv_ooo_limit equal to rxq size */
	tcp_cfg.rcv_ooo_limit = tsock->rxq.size;
	for (i = 0; i < tsock->rxq.size; i++) {
		pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt + (i + 1) * 1000, 1000);
		ut_tcp_input_one(tsock, pkt); {
			assert(tsock->nr_ooo_pkt == i + 1);
		}
	}

	/* fill the hole */
	pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt, 1000);
	ut_tcp_input_one(tsock, pkt); {
		/*
		 * the rxq is full; we have one more IN-ORDER pkt left
		 * in the ooo queue
		 */
		assert(tsock->nr_ooo_pkt == 1);
		assert(tsock->stats_base[ERR_TCP_RXQ_ENQUEUE_FAIL] == 1);
	}

	/* drain the tcp rxq */
	assert(ut_readv(tsock, tsock->rxq.size) == tsock->rxq.size * 1000);

	/* inject a new data should deliver above IN-ORDER pkt in ooo queue to tsock rxq */
	pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt + 1000, 1000);
	ut_tcp_input_one(tsock, pkt); {
		assert(ut_readv(tsock, tsock->rxq.size) == 1000 * 2);
		assert(tsock->nr_ooo_pkt == 0);
		assert(tsock->nr_sack_block == 0);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_input_ooo_tcp_rxq_enqueue_failure3(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	int i;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	/* make sure tcp_cfg.rcv_ooo_limit equal to rxq size */
	tcp_cfg.rcv_ooo_limit = tsock->rxq.size;
	for (i = 0; i < tsock->rxq.size; i++) {
		pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt + (i + 1) * 1000, 1000);
		ut_tcp_input_one(tsock, pkt); {
			assert(tsock->nr_ooo_pkt == i + 1);
		}
	}

	/* fill the hole */
	pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt, 1000);
	ut_tcp_input_one(tsock, pkt); {
		/*
		 * the rxq is full; we have one more IN-ORDER pkt left
		 * in the ooo queue
		 */
		assert(tsock->nr_ooo_pkt == 1);
		assert(tsock->stats_base[ERR_TCP_RXQ_ENQUEUE_FAIL] == 1);
	}

	/* drain the tcp rxq */
	assert(ut_readv(tsock, tsock->rxq.size) == tsock->rxq.size * 1000);

	/* reject (partial of) last pkt should deliver above IN-ORDER pkt in ooo queue to tsock rxq */
	pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt, 1);
	ut_tcp_input_one(tsock, pkt); {
		assert(ut_readv(tsock, tsock->rxq.size) == 1000);
		assert(tsock->nr_ooo_pkt == 0);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_input_ooo_predict(void)
{
	struct tcp_sock *tsock;
	struct packet *pkts[4];

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	pkts[0] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 1000, 1001);
	pkts[1] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 2001, 1002);
	pkts[2] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 3003, 1003);
	pkts[3] = ut_inject_data_packet(tsock, tsock->rcv_nxt,        1000);

	ut_tcp_input(tsock, pkts, 4); {
		assert(tcp_rxq_readable_count(&tsock->rxq) == 4);
		assert(tsock->nr_ooo_pkt == 0);
		assert(tsock->nr_sack_block == 0);
		assert(tsock->last_ooo_pkt == NULL);
		assert(tsock->stats_base[PKT_RECV_OOO_PREDICT] == 2);

		assert(ut_readv(tsock, 1) == 1000);
		assert(ut_readv(tsock, 1) == 1001);
		assert(ut_readv(tsock, 1) == 1002);
		assert(ut_readv(tsock, 1) == 1003);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_input_ooo_predict_overlap(void)
{
	struct tcp_sock *tsock;
	struct packet *pkts[3];
	struct packet *pkt;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	pkts[0] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 2000, 1000);
	pkts[1] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 1000, 500);
	pkts[2] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 1500, 700);

	ut_tcp_input(tsock, pkts, 3); {
		assert(tcp_rxq_readable_count(&tsock->rxq) == 0);
		assert(tsock->nr_ooo_pkt == 3);
		assert(tsock->stats_base[PKT_RECV_OOO_PREDICT] == 0);

		pkt = TAILQ_FIRST(&tsock->rcv_ooo_queue);
		assert(TCP_SEG(pkt)->seq == tsock->rcv_nxt + 1000 && TCP_SEG(pkt)->len == 500);

		pkt = TAILQ_NEXT(pkt, node);
		assert(TCP_SEG(pkt)->seq == tsock->rcv_nxt + 1500 && TCP_SEG(pkt)->len == 500);

		pkt = TAILQ_NEXT(pkt, node);
		assert(TCP_SEG(pkt)->seq == tsock->rcv_nxt + 2000 && TCP_SEG(pkt)->len == 1000);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_input_ooo_stress(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	struct packet *p;
	struct tpa_iovec iov;
	uint32_t seq;
	uint32_t end;
	uint16_t len;
	int i;

	printf("stressing tcp_input with out of order rcv ...\n");

	tsock = ut_tcp_connect();

	for (i = 0; i < 8192; i++) {
		seq = rand() % tsock->rcv_wnd;
		len = rand() % 1400;

		pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt + 1 + seq, len + 1);
		/* assert no loop gonna happen */
		TAILQ_FOREACH(p, &tsock->rcv_ooo_queue, node) {
			assert(p != pkt);
		}

		ut_tcp_input_one(tsock, pkt); {
			ooo_queue_sanity_check(tsock);
			assert(tcp_rxq_readable_count(&tsock->rxq) == 0);
			assert(!TAILQ_EMPTY(&tsock->rcv_ooo_queue));

			assert(ut_tcp_output(&pkt, 1) == 1);
			assert(TCP_SEG(pkt)->ack == tsock->rcv_nxt);
			packet_free(pkt);
		}
	}

	seq = tsock->rcv_nxt;
	end = tsock->rcv_nxt + tsock->rcv_wnd;
	while (seq_lt(seq, end)) {
		len = rand() % 1000 + 1;
		if (seq_gt(seq + len, end))
			len = end - seq;

		pkt = ut_inject_data_packet(tsock, seq, len);
		/* assert no loop gonna happen */
		TAILQ_FOREACH(p, &tsock->rcv_ooo_queue, node) {
			assert(p != pkt);
		}

		ut_tcp_input_one(tsock, pkt); {
			ooo_queue_sanity_check(tsock);
			assert(seq_lt(seq, tsock->rcv_nxt));

			p = TAILQ_FIRST(&tsock->rcv_ooo_queue);
			if (p)
				assert(seq_lt(seq, TCP_SEG(p)->seq));

			/* drain */
			ut_tcp_output(NULL, -1);
			while (tpa_zreadv(tsock->sid, &iov, 1) > 0)
				iov.iov_read_done(iov.iov_base, iov.iov_param);
		}

		seq += len;
	}

	printf("\tnr_ooo_pkt:\t %u\n", tsock->nr_ooo_pkt);

	assert(tsock->nr_ooo_pkt == 0);
	assert(tsock->nr_sack_block == 0);
	assert(tsock->stats_base[BYTE_RECV] == TSOCK_RCV_WND_DEFAULT(tsock));

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_input_ooo_stress_harder(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	struct packet *p;
	uint32_t seq;
	uint16_t len;

	printf("stressing tcp_input with out of order rcv [harder] ...\n");

	tsock = ut_tcp_connect();

	WHILE_NOT_TIME_UP() {
		seq = rand() % tsock->rcv_wnd + tsock->rcv_nxt - rand() % (tsock->rcv_wnd / 4);
		len = rand() % 1400;

		pkt = ut_inject_data_packet(tsock, seq, len);


		if ((rand() % 100) <= 3)
			tsock_drop_ooo_mbufs(tsock);

		/* assert no loop gonna happen */
		TAILQ_FOREACH(p, &tsock->rcv_ooo_queue, node) {
			assert(p != pkt);
		}

		ut_tcp_input_one_and_drain(tsock, pkt); {
			ooo_queue_sanity_check(tsock);
		}
	}

	printf("\tnr_ooo_pkt:\t %u\n", tsock->nr_ooo_pkt);

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_tcp_input_ooo_basic();
	test_tcp_input_ooo_overlap();
	test_tcp_input_ooo_tcp_rxq_enqueue_failure();
	test_tcp_input_ooo_tcp_rxq_enqueue_failure2();
	test_tcp_input_ooo_tcp_rxq_enqueue_failure3();
	test_tcp_input_ooo_predict();
	test_tcp_input_ooo_predict_overlap();
	test_tcp_input_ooo_stress();
	test_tcp_input_ooo_stress_harder();

	return 0;
}
