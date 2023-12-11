/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022, ByteDance Ltd. and/or its Affiliates
 * Author: Tao Liu <liutao.xyz@bytedance.com>
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <getopt.h>
#include <sys/uio.h>

#include "test_utils.h"

static void test_tcp_input_merge_basic(void)
{
	struct tcp_sock *tsock;
	struct packet *pkts[4];

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	ut_make_input_pkt_bulk(tsock, pkts, 4, (int []){100, 200, 150, 250});
	ut_tcp_input(tsock, pkts, 4); {
		assert(tsock->stats_base[PKT_RECV_MERGE] == 4);
		assert(ut_readv(tsock, 4) == 700);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_input_merge_with_ack(void)
{
	struct tcp_sock *tsock;
	struct packet *pkts[4];

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	pkts[0] = ut_inject_ack_packet(tsock, tsock->snd_nxt);
	ut_make_input_pkt_bulk(tsock, &pkts[1], 3, (int []){100, 200, 300});
	ut_tcp_input(tsock, pkts, 4); {
		assert(ut_readv(tsock, 1) == 100);
	}

	ut_close(tsock, CLOSE_TYPE_RESET);
}

static void test_tcp_input_merge_ooo_reverse_order(void)
{
	struct tcp_sock *tsock;
	struct packet *pkts[3];

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	pkts[0] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 2000, 1000);
	pkts[1] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 1000, 1000);
	pkts[2] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 0, 1000);

	ut_tcp_input(tsock, pkts, 2); {
		assert(ut_readv(tsock, 1) == -1 && errno == EAGAIN);
		assert(tsock->stats_base[PKT_RECV_MERGE] == 0);
	}

	ut_tcp_input_one(tsock, pkts[2]); {
		assert(ut_readv(tsock, 1) == 1000);
		assert(ut_readv(tsock, 2) == 2000);
		assert(tsock->stats_base[PKT_RECV_MERGE] == 0);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_input_merge_ooo_interleaved(void)
{
	struct tcp_sock *tsock;
	struct packet *pkts[30];
	uint32_t off = 0;
	int i;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	/* 10 pkt out of order */
	for (i = 9; i >= 0; i--) {
		pkts[i] = ut_inject_data_packet(tsock, tsock->rcv_nxt + off, 1000);
		off += 1000;
	}
	/* 10 pkt ordered, merged count: 10 */
	for (i = 10; i < 20; i++) {
		pkts[i] = ut_inject_data_packet(tsock, tsock->rcv_nxt + off, 1000);
		off += 1000;
	}
	/* 5 pkt out of order */
	for (i = 24; i >= 20; i--) {
		pkts[i] = ut_inject_data_packet(tsock, tsock->rcv_nxt + off, 1000);
		off += 1000;
	}
	/* 5 pkt ordered, merged count: 5 */
	for (i = 25; i < 30; i++) {
		pkts[i] = ut_inject_data_packet(tsock, tsock->rcv_nxt + off, 1000);
		off += 1000;
	}

	ut_tcp_input(tsock, pkts, 30); {
		assert(ut_readv(tsock, 30) == 30 * 1000);
		assert(tsock->stats_base[PKT_RECV_MERGE] == (10 + 5));
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_input_merge_ooo_partial_mergeable(void)
{
	struct tcp_sock *tsock;
	struct packet *pkts[8];

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	pkts[0] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 1000, 1000);
	pkts[1] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 0,    1000);
	pkts[2] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 2000, 1000);
	pkts[3] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 3000, 1000);
	pkts[4] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 5000, 1000);
	pkts[5] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 4000, 1000);
	pkts[6] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 6000, 1000);
	pkts[7] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 7000, 1000);

	ut_tcp_input(tsock, pkts, 8); {
		assert(ut_readv(tsock, 8) == 8000);
		assert(tsock->stats_base[PKT_RECV_MERGE] == 2 + 2);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_input_merge_seq_overlap(void)
{
	struct tcp_sock *tsock;
	struct packet *pkts[10];
	struct tpa_iovec iov[3];
	uint32_t rcv_nxt;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();
	rcv_nxt = tsock->rcv_nxt;

	/*
	 *                       0                     1000
	 * pkt 0:                |-----------------------|
	 *                 -100    100
	 * pkt 1:            |------|
	 *                         100  200
	 * pkt 2:                   |----|
	 *                                       800 900
	 * pkt 3:                                 |---|
	 *                                           900   1100
	 * pkt 4:                                     |------|
	 *                         100      500
	 * pkt 5:                   |--------|
	 *                                  500      900
	 * pkt 6:                            |--------|
	 *             -200      0
	 * pkt 7:        |-------|
	 *                       0               800
	 * pkt 8:                |----------------|
	 *                                       800          1200
	 * pkt 9:                                 |-------------|
	 */
	pkts[0] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 0,   1000);
	pkts[1] = ut_inject_data_packet(tsock, tsock->rcv_nxt - 100, 200);
	pkts[2] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 100, 100);
	pkts[3] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 800, 100);
	pkts[4] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 900, 200);
	pkts[5] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 100, 400);
	pkts[6] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 500, 400);
	pkts[7] = ut_inject_data_packet(tsock, tsock->rcv_nxt - 200, 200);
	pkts[8] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 0,   800);
	pkts[9] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 800, 400);
	ut_tcp_input(tsock, pkts, 10); {
		assert(tsock->rcv_nxt - rcv_nxt == 1200);
		assert(tpa_zreadv(tsock->sid, iov, 3) == 1200); {
			assert(iov[0].iov_len == 1000);
			assert(iov[1].iov_len == 100); // cut head
			assert(iov[2].iov_len == 100); // cut head
			iov[0].iov_read_done(iov[0].iov_base, iov[0].iov_param);
			iov[1].iov_read_done(iov[1].iov_base, iov[1].iov_param);
			iov[2].iov_read_done(iov[2].iov_base, iov[2].iov_param);
		}

		/* no merge is enabled for ooo pkts */
		assert(tsock->stats_base[PKT_RECV_MERGE] == 0);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_input_merge_seq_overlap_ooo(void)
{
	struct tcp_sock *tsock;
	struct packet *pkts[32];
	struct packet *pkt;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();
	/*
	 *                                1300   1500
	 * pkt 0:                           |-----|
	 *                                      1500   1700
	 * pkt 1:                                 |------|
	 *        500 600
	 * pkt 2:  |---|
	 *                        1000  1200
	 * pkt 3:                   |----|
	 *                              1200  1400
	 * pkt 4:                        |----| (chain 1000-1400, cut tail 1300-1400)
	 *                      900 1100
	 * pkt 5:                |----|
	 *                          1100 1200
	 * pkt 6:                     |--| (chain 900-1200, cut tail 1000-1200)
	 *                700     1000
	 * pkt 7:          |--------|
	 *                        1000 1200
	 * pkt 8:                   |----| (chain 700-1200, replace 900-1000, cut tail 1000-1200)
	 *                700                        1700
	 * pkt 9:          |-----------------------------| (replace 700 - 1700)
	 *                                       1500 1600
	 * pkt 10:                                 |---|
	 *                                           1600 1800
	 * pkt 11:                                     |---|
	 *                                               1800 2000
	 * pkt 12:                                         |---| (chain 1500-2000, cut head 1500-1700)
	 *                                               1750 2000
	 * pkt 13:                                        |----|
	 *                                                    2000 2200
	 * pkt 14:                                             |----| (chain 1750-2200, cut head 1750-2000)
	 *                                                     2100  2300
	 * pkt 15:                                               |-----|
	 *                                                           2300   2500
	 * pkt 16:                                                     |-----| (chain 2100-2500, cut head 2100-2200)
	 *                                                     2100  2300
	 * pkt 17:                                               |-----|
	 *                                                           2300 2400
	 * pkt 18:                                                     |--|
	 *                                                              2400  2600
	 * pkt 19:                                                        |----| (chain 2100-2600, cut head 2100-2200, replace 2200-2500)
	 *                                              1700                  2600
	 * pkt 20:                                       |---------------------| (replace 1700 - 2600)
	 */
	pkts[0] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 1300, 200);
	pkts[1] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 1500, 200);
	pkts[2] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 500, 100);
	pkts[3] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 1000, 200);
	pkts[4] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 1200, 200);
	pkts[5] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 900, 200);
	pkts[6] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 1100, 100);
	pkts[7] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 700, 300);
	pkts[8] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 1000, 200);
	pkts[9] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 700, 1000);
	pkts[10] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 1500, 100);
	pkts[11] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 1600, 200);
	pkts[12] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 1800, 200);
	pkts[13] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 1750, 250);
	pkts[14] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 2000, 200);
	pkts[15] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 2100, 200);
	pkts[16] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 2300, 200);
	pkts[17] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 2100, 200);
	pkts[18] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 2300, 100);
	pkts[19] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 2400, 200);
	pkts[20] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 1700, 900);
	ut_tcp_input(tsock, pkts, 21); {
		assert(tcp_rxq_readable_count(&tsock->rxq) == 0);
		assert(tsock->nr_ooo_pkt == 3);
		pkt = TAILQ_FIRST(&tsock->rcv_ooo_queue);
		assert(TCP_SEG(pkt)->seq == tsock->rcv_nxt + 500 && TCP_SEG(pkt)->len == 100);

		pkt = TAILQ_NEXT(pkt, node);
		assert(TCP_SEG(pkt)->seq == tsock->rcv_nxt + 700 && TCP_SEG(pkt)->len == 1000);

		pkt = TAILQ_NEXT(pkt, node);
		assert(TCP_SEG(pkt)->seq == tsock->rcv_nxt + 1700 && TCP_SEG(pkt)->len == 900);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_input_merge_ts_opt(void)
{
	struct tcp_sock *tsock;
	struct packet *pkts[2];

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	pkts[0] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 0,    1000);
	pkts[1] = ut_inject_data_packet(tsock, tsock->rcv_nxt + 1000, 1000);

	fill_opt_ts((uint8_t *)(ut_packet_tcp_hdr(pkts[0]) + 1), tsock->ts_recent, tsock->snd_ts);
	ut_tcp_input(tsock, pkts, 2); {
		assert(ut_readv(tsock, 2) == 2000);

		/* pkt has diff ts, should not be merged */
		assert(tsock->stats_base[PKT_RECV_MERGE] == 0);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void ut_tcp_input_mutil_sock(struct packet **pkts, uint16_t nr_pkt)
{
	cycles_update_begin(worker);
	ut_timer_process();

	ut_tcp_input_raw(NULL, pkts, nr_pkt);
}

static void test_tcp_input_merge_multi_sock(void)
{
	struct tcp_sock *tsock1, *tsock2;
	struct packet *pkts[8];

	printf("testing %s ...\n", __func__);
	tsock1 = ut_tcp_connect();
	tsock2 = ut_tcp_connect();

	pkts[0] = ut_inject_data_packet(tsock1, tsock1->rcv_nxt + 1000, 1000);
	pkts[1] = ut_inject_data_packet(tsock2, tsock2->rcv_nxt + 0,    1000);
	pkts[2] = ut_inject_data_packet(tsock1, tsock1->rcv_nxt + 0,    1000);
	pkts[3] = ut_inject_data_packet(tsock2, tsock2->rcv_nxt + 1000, 1000);

	pkts[4] = ut_inject_data_packet(tsock1, tsock1->rcv_nxt + 3000, 1000);
	pkts[5] = ut_inject_data_packet(tsock2, tsock2->rcv_nxt + 2000, 1000);
	pkts[6] = ut_inject_data_packet(tsock1, tsock1->rcv_nxt + 2000, 1000);
	pkts[7] = ut_inject_data_packet(tsock2, tsock2->rcv_nxt + 3000, 1000);

	ut_tcp_input_mutil_sock(pkts, 8); {
		assert(ut_readv(tsock1, 4) == 4000);
		assert(ut_readv(tsock2, 4) == 4000);

		assert(tsock1->stats_base[PKT_RECV_MERGE] == 0);
		assert(tsock2->stats_base[PKT_RECV_MERGE] == 4);
	}

	ut_close(tsock1, CLOSE_TYPE_4WAY);
	ut_close(tsock2, CLOSE_TYPE_4WAY);
}

static void test_tcp_input_merge_out_of_wnd_left(void)
{
	struct tcp_sock *tsock;
	struct packet *pkts[2];

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	ut_make_input_pkt_bulk_with_seq(tsock, pkts, 2, (int []){100, 200}, tsock->rcv_nxt - 300);
	ut_tcp_input(tsock, pkts, 2); {
		assert(tcp_rxq_readable_count(&tsock->rxq) == 0);
		assert(ut_readv(tsock, 1) == -1 && errno == EAGAIN);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_input_merge_out_of_wnd_left_partially(void)
{
	struct tcp_sock *tsock;
	struct packet *pkts[3];

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	ut_make_input_pkt_bulk_with_seq(tsock, pkts, 3, (int []){100, 200 + 1, 300}, tsock->rcv_nxt - 300);
	ut_tcp_input(tsock, pkts, 3); {
		assert(ut_readv(tsock, 1) == 1);
		assert(ut_readv(tsock, 1) == 300);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_input_merge_out_of_wnd_right(void)
{
	struct tcp_sock *tsock;
	struct packet *pkts[2];

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	ut_make_input_pkt_bulk_with_seq(tsock, pkts, 2, (int []){100, 200}, tsock->rcv_nxt + tsock->rcv_wnd);
	ut_tcp_input(tsock, pkts, 2); {
		assert(tcp_rxq_readable_count(&tsock->rxq) == 0);
		assert(ut_readv(tsock, 1) == -1 && errno == EAGAIN);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_input_merge_out_of_wnd_right_partially(void)
{
	struct tcp_sock *tsock;
	struct packet *pkts[3];
	struct packet *pkt;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	ut_make_input_pkt_bulk_with_seq(tsock, pkts, 3, (int []){100, 200, 300}, tsock->rcv_nxt + tsock->rcv_wnd - 1);
	ut_tcp_input(tsock, pkts, 3); {
		assert(tcp_rxq_readable_count(&tsock->rxq) == 0);

		assert(tsock->nr_ooo_pkt == 1);
		pkt = TAILQ_FIRST(&tsock->rcv_ooo_queue);
		assert(TCP_SEG(pkt)->seq == tsock->rcv_nxt + tsock->rcv_wnd - 1 && TCP_SEG(pkt)->len == 1);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_input_merge_stress(void)
{
	struct tcp_sock *tsock;
	struct packet *pkts[200];
	uint32_t right_wnd;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	WHILE_NOT_TIME_UP() {
		/*
		 * here is the thing, in each loop, we test
		 * - 30% pkts are at the left of the rcv wnd (partially or completely)
		 * - 20% pkts are OOO and inside the rcv wnd
		 * - 20% pkts are to be recv-ed next
		 * - 30% pkts are at the right of the rcv wnd (partially or completely)
		 */
		right_wnd = tsock->rcv_nxt + tsock->rcv_wnd;
		ut_make_input_pkt_bulk_randomly_with_seq(tsock, &pkts[0],   60, tsock->rcv_nxt - 60 * 1000 / 2);
		ut_make_input_pkt_bulk_randomly_with_seq(tsock, &pkts[60],  40, tsock->rcv_nxt + 40 * 1000 / 2);
		ut_make_input_pkt_bulk_randomly_with_seq(tsock, &pkts[100], 40, tsock->rcv_nxt);
		ut_make_input_pkt_bulk_randomly_with_seq(tsock, &pkts[140], 60, right_wnd - 60 * 1000 / 2);
		ut_tcp_input(tsock, pkts, 200); {
			assert(ut_readv(tsock, 65536) > 0);
		}

		/*
		 * Absorb pkts in the OOO queue if we have few mbufs left;
		 * otherwise, we will fail due to running out of mbufs.
		 */
		if (ut_free_mbuf_count() < 400) {
			while (seq_lt(tsock->rcv_nxt, right_wnd)) {
				ut_make_input_pkt_bulk_randomly_with_seq(tsock, pkts, 10, tsock->rcv_nxt);
				ut_tcp_input(tsock, pkts, 10); {
					assert(ut_readv(tsock, 65536) > 0);
				}
			}
			ut_assert_mbuf_count();
		}
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_tcp_input_merge_basic();
	test_tcp_input_merge_with_ack();
	test_tcp_input_merge_ooo_reverse_order();
	test_tcp_input_merge_ooo_interleaved();
	test_tcp_input_merge_ooo_partial_mergeable();
	test_tcp_input_merge_seq_overlap();
	test_tcp_input_merge_seq_overlap_ooo();
	test_tcp_input_merge_ts_opt();
	test_tcp_input_merge_multi_sock();
	test_tcp_input_merge_out_of_wnd_left();
	test_tcp_input_merge_out_of_wnd_left_partially();
	test_tcp_input_merge_out_of_wnd_right();
	test_tcp_input_merge_out_of_wnd_right_partially();
	test_tcp_input_merge_stress();

	return 0;
}
