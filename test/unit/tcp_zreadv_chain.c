/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <unistd.h>

#include "test_utils.h"

static void test_tcp_zreadv_chain_basic(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	struct tpa_iovec iov[3];
	int i;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();
	pkt = ut_make_input_pkt_chain(tsock, 3, (int []){300, 200, 100});
	tcp_rxq_enqueue_burst(&tsock->rxq, (void **)&pkt, 1); {
		assert(tpa_zreadv(tsock->sid, iov, 3) == 600); {
			assert(iov[0].iov_len == 300);
			assert(iov[1].iov_len == 200);
			assert(iov[2].iov_len == 100);

			for (i = 0; i < 3; i++)
				iov[i].iov_read_done(iov[i].iov_base, iov[i].iov_param);
		}
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_zreadv_chain_partial(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	struct tpa_iovec iov;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();
	pkt = ut_make_input_pkt_chain(tsock, 3, (int []){300, 200, 100});
	tcp_rxq_enqueue_burst(&tsock->rxq, (void **)&pkt, 1); {
		assert(tpa_zreadv(tsock->sid, &iov, 1) == 300); {
			iov.iov_read_done(iov.iov_base, iov.iov_param);
		}

		assert(tpa_zreadv(tsock->sid, &iov, 1) == 200); {
			iov.iov_read_done(iov.iov_base, iov.iov_param);
		}

		assert(tpa_zreadv(tsock->sid, &iov, 1) == 100); {
			iov.iov_read_done(iov.iov_base, iov.iov_param);
		}

		assert(tpa_zreadv(tsock->sid, &iov, 1) == -1);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_zreadv_chain_disordered_read_done(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	struct tpa_iovec iov[3];

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();
	pkt = ut_make_input_pkt_chain(tsock, 3, (int []){300, 200, 100});
	tcp_rxq_enqueue_burst(&tsock->rxq, (void **)&pkt, 1); {
		assert(tpa_zreadv(tsock->sid, iov, 3) == 600); {
			assert(iov[0].iov_len == 300);
			assert(iov[1].iov_len == 200);
			assert(iov[2].iov_len == 100);

			iov[2].iov_read_done(iov[2].iov_base, iov[2].iov_param); {
				assert(ut_free_mbuf_count() != ut_total_mbuf_count());
			}
			iov[0].iov_read_done(iov[0].iov_base, iov[0].iov_param); {
				assert(ut_free_mbuf_count() != ut_total_mbuf_count());
			}
			iov[1].iov_read_done(iov[1].iov_base, iov[1].iov_param); {
				/*
				 * we should free the whole pkt chain when the
				 * last segment is done with read.
				 */
				assert(ut_free_mbuf_count() == ut_total_mbuf_count());
			}
		}
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

#define relative_l5_off(pkt)	((pkt)->l5_off - (pkt)->l4_off - 20 - TCP_SEG(pkt)->opt_len)

static void test_tcp_zreadv_chain_cut_head(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	struct tpa_iovec iov;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();
	pkt = ut_make_input_pkt_chain(tsock, 3, (int []){100, 200, 300});
	tcp_packet_cut(pkt, 50, CUT_HEAD); {
		assert(TCP_SEG(pkt)->len == 550);
		assert(TCP_SEG(pkt)->seq == tsock->rcv_nxt + 50);
		assert(pkt->to_read->l5_len == 50);
		assert(relative_l5_off(pkt->to_read) == 50);
	}

	tcp_packet_cut(pkt, 100, CUT_HEAD); {
		assert(TCP_SEG(pkt)->len == 450);
		assert(TCP_SEG(pkt)->seq == tsock->rcv_nxt + 50 + 100);
		assert(pkt->to_read->l5_len == 150);
		assert(relative_l5_off(pkt->to_read) == 50);
	}

	tcp_rxq_enqueue_burst(&tsock->rxq, (void **)&pkt, 1); {
		assert(tpa_zreadv(tsock->sid, &iov, 1) == 150); {
			iov.iov_read_done(iov.iov_base, iov.iov_param);
		}

		assert(tpa_zreadv(tsock->sid, &iov, 1) == 300); {
			iov.iov_read_done(iov.iov_base, iov.iov_param);
		}
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_zreadv_chain_cut_tail(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	struct tpa_iovec iov;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();
	pkt = ut_make_input_pkt_chain(tsock, 3, (int []){100, 200, 300});
	tcp_packet_cut(pkt, 50, CUT_TAIL); {
		assert(TCP_SEG(pkt)->len == 550);
		assert(TCP_SEG(pkt)->seq == tsock->rcv_nxt);
		assert(pkt->to_read->l5_len == 100);
		assert(relative_l5_off(pkt->to_read) == 0);
	}

	tcp_packet_cut(pkt, 500, CUT_TAIL); {
		assert(TCP_SEG(pkt)->len == 50);
		assert(TCP_SEG(pkt)->seq == tsock->rcv_nxt);
		assert(pkt->to_read->l5_len == 50);
		assert(relative_l5_off(pkt->to_read) == 0);
	}

	tcp_rxq_enqueue_burst(&tsock->rxq, (void **)&pkt, 1); {
		assert(tpa_zreadv(tsock->sid, &iov, 1) == 50); {
			iov.iov_read_done(iov.iov_base, iov.iov_param);
		}
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_zreadv_chain_cut_all(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	pkt = ut_make_input_pkt_chain(tsock, 3, (int []){100, 200, 300});
	tcp_packet_cut(pkt, 600, CUT_HEAD); {
		assert(TCP_SEG(pkt)->len == 0);
		packet_free(pkt);
	}

	pkt = ut_make_input_pkt_chain(tsock, 3, (int []){100, 200, 300});
	tcp_packet_cut(pkt, 600, CUT_TAIL); {
		assert(TCP_SEG(pkt)->len == 0);
		packet_free(pkt);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_tcp_zreadv_chain_basic();
	test_tcp_zreadv_chain_partial();
	test_tcp_zreadv_chain_disordered_read_done();
	test_tcp_zreadv_chain_cut_head();
	test_tcp_zreadv_chain_cut_tail();
	test_tcp_zreadv_chain_cut_all();

	return 0;
}
