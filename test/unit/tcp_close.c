/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <unistd.h>

#include "test_utils.h"

static void test_tcp_close_half(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;

	printf("testing tcp_close [half] ...\n");

	tsock = ut_tcp_connect();

	tpa_close(tsock->sid);
	assert(ut_tcp_output(&pkt, 1) == 1); {
		assert(TCP_SEG(pkt)->flags & TCP_FLAG_FIN);
		assert(TCP_SEG(pkt)->flags & TCP_FLAG_ACK);
		assert((uint32_t)(TCP_SEG(pkt)->seq - tsock->snd_isn) == 1);
		assert(tsock->stats_base[FIN_XMIT] == 1);
		assert(tsock->stats_base[RST_XMIT] == 0);
		assert(tsock->state == TCP_STATE_FIN_WAIT_1);
		packet_free(pkt);
	}

	timer_stop(&tsock->timer_rto);
	timer_stop(&tsock->timer_wait);
	ut_dump_tsock_stats(tsock);
	ut_assert_mbuf_count();
}

static void test_tcp_close_wrong_ack(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	uint32_t fin_seq;

	printf("testing tcp_close with [wrong ack] ...\n");

	tsock = ut_tcp_connect();

	tpa_close(tsock->sid);
	assert(ut_tcp_output(&pkt, 1) == 1); {
		assert(TCP_SEG(pkt)->flags & TCP_FLAG_FIN);
		assert(TCP_SEG(pkt)->flags & TCP_FLAG_ACK);
		assert((uint32_t)(TCP_SEG(pkt)->seq - tsock->snd_isn) == 1);
		assert(tsock->stats_base[FIN_XMIT] == 1);
		assert(tsock->stats_base[RST_XMIT] == 0);
		assert(tsock->state == TCP_STATE_FIN_WAIT_1);

		fin_seq = TCP_SEG(pkt)->seq;
		packet_free(pkt);
	}

	/* inject a wrong ack */
	pkt = ut_inject_ack_packet(tsock, fin_seq);
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->state == TCP_STATE_FIN_WAIT_1);
	}

	timer_stop(&tsock->timer_rto);
	timer_stop(&tsock->timer_wait);
	ut_dump_tsock_stats(tsock);
	ut_assert_mbuf_count();
}

static void test_tcp_close_complete(void)
{
	struct tcp_sock *tsock;

	printf("testing tcp_close [complete] ...\n");

	tsock = ut_tcp_connect();

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_close_with_pending_send(void)
{
	struct tcp_sock *tsock;

	printf("testing tcp_close with [pending send buffer] ...\n");

	tsock = ut_tcp_connect();

	ut_write_assert(tsock, MESSAGE_SIZE);
	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_close_with_pending_send2(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;

	printf("testing tcp_close with [pending send buffer 2] ...\n");

	tsock = ut_tcp_connect();

	ut_write_assert(tsock, 1000);
	ut_write_assert(tsock, 1000);

	/* send one half first */
	tsock->snd_cwnd = 1000;
	ut_tcp_output(NULL, -1);

	tpa_close(tsock->sid);
	ut_tcp_output(NULL, -1); {
		assert(tsock->state == TCP_STATE_FIN_WAIT_1);
		assert(tcp_txq_to_send_pkts(&tsock->txq) == 1);
	}

	/* ack the first half */
	pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt);
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->state == TCP_STATE_FIN_WAIT_1);
	}

	/* a hack to go back the normal close procedure */
	tsock->snd_cwnd = 2000;
	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_close_with_pending_recv(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;

	printf("testing tcp_close with [pending recv buffer] ...\n");

	tsock = ut_tcp_connect();

	pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt, 1000);
	ut_tcp_input_one(tsock, pkt);

	ut_close(tsock, CLOSE_TYPE_RESET);
}

static void test_tcp_close_with_mbuf_chains(void)
{
	struct tcp_sock *tsock;

	printf("testing tcp_close with [mbuf chains] ...\n");

	tsock = ut_tcp_connect();

	ut_write_assert(tsock, 1);
	ut_write_assert(tsock, 1);
	ut_write_assert(tsock, 1);
	ut_write_assert(tsock, 1);
	ut_tcp_output(NULL, 0);

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_close_fin_retry(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;

	printf("testing tcp_close [fin retry] ...\n");

	tsock = ut_tcp_connect();

	tpa_close(tsock->sid);
	assert(ut_tcp_output(&pkt, 1) == 1); {
		assert(TCP_SEG(pkt)->flags & TCP_FLAG_FIN);
		assert(TCP_SEG(pkt)->flags & TCP_FLAG_ACK);
		assert((uint32_t)(TCP_SEG(pkt)->seq - tsock->snd_isn) == 1);
		assert(tsock->stats_base[FIN_XMIT] == 1);
		assert(tsock->stats_base[RST_XMIT] == 0);
		assert(tsock->state == TCP_STATE_FIN_WAIT_1);
		packet_free(pkt);
	}

	/* test fin retry */
	usleep(tsock->rto + 0.2 * 1e6);
	assert(ut_tcp_output(&pkt, 1) == 1); {
		assert(TCP_SEG(pkt)->flags & TCP_FLAG_FIN);
		assert(TCP_SEG(pkt)->flags & TCP_FLAG_ACK);
		assert((uint32_t)(TCP_SEG(pkt)->seq - tsock->snd_isn) == 1);
		assert(tsock->stats_base[FIN_XMIT] == 2);
		assert(tsock->stats_base[RST_XMIT] == 0);
		assert(tsock->state == TCP_STATE_FIN_WAIT_1);
		packet_free(pkt);
	}

	timer_stop(&tsock->timer_rto);
	timer_stop(&tsock->timer_wait);
	ut_dump_tsock_stats(tsock);
	ut_assert_mbuf_count();
}

static void test_tcp_close_fin_retry_with_pending_send(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;

	printf("testing tcp_close [fin retry with pending send] ...\n");

	tsock = ut_tcp_connect();

	ut_write_assert(tsock, MESSAGE_SIZE);
	tpa_close(tsock->sid);

	pkt = ut_drain_send_buff_at_close(tsock); {
		assert(TCP_SEG(pkt)->flags & TCP_FLAG_FIN);
		assert(TCP_SEG(pkt)->flags & TCP_FLAG_ACK);
		assert(tsock->stats_base[FIN_XMIT] == 1);
		assert(tsock->stats_base[RST_XMIT] == 0);
		assert(tsock->state == TCP_STATE_FIN_WAIT_1);
		packet_free(pkt);
	}

	/* test fin retry */
	usleep(tsock->rto + 0.2 * 1e6);
	pkt = ut_drain_send_buff_at_close(tsock); {
		assert(TCP_SEG(pkt)->flags & TCP_FLAG_FIN);
		assert(TCP_SEG(pkt)->flags & TCP_FLAG_ACK);
		assert(tsock->stats_base[FIN_XMIT] == 2);
		assert(tsock->stats_base[RST_XMIT] == 0);
		assert(tsock->state == TCP_STATE_FIN_WAIT_1);
		packet_free(pkt);
	}

	/* ack the fin to free the send buffer */
	pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt);
	ut_tcp_input_one(tsock, pkt);

	timer_stop(&tsock->timer_rto);
	timer_stop(&tsock->timer_wait);
	ut_dump_tsock_stats(tsock);
	ut_assert_mbuf_count();
}

static void test_tcp_close_fin_timeout(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	uint64_t start_ts_us;

	printf("testing tcp_close [fin timeout] ...\n");

	tsock = ut_tcp_connect();

	ut_write_assert(tsock, MESSAGE_SIZE);
	tpa_close(tsock->sid);

	pkt = ut_drain_send_buff_at_close(tsock); {
		assert(TCP_SEG(pkt)->flags & TCP_FLAG_FIN);
		assert(TCP_SEG(pkt)->flags & TCP_FLAG_ACK);
		assert(tsock->stats_base[FIN_XMIT] == 1);
		assert(tsock->stats_base[RST_XMIT] == 0);
		assert(tsock->state == TCP_STATE_FIN_WAIT_1);
		packet_free(pkt);
	}

	start_ts_us = worker->ts_us;
	tcp_cfg.retries = 2;
	while (1) {
		usleep(0.1 * 1e6);
		cycles_update_begin(worker);
		if (ut_timer_process() == 0)
			continue;

		if (tsock->state == TCP_STATE_CLOSED)
			break;

		printf(":: %d: fin re-xmit after %.2fs\n", tsock->rto_shift, (double)(worker->ts_us - start_ts_us) / 1e6);
		start_ts_us = worker->ts_us;

		pkt = ut_drain_send_buff_at_close(tsock); {
			assert(TCP_SEG(pkt)->flags & TCP_FLAG_FIN);
			assert(TCP_SEG(pkt)->flags & TCP_FLAG_ACK);
			assert(tsock->stats_base[RST_XMIT] == 0);
			assert(tsock->state == TCP_STATE_FIN_WAIT_1);
			packet_free(pkt);
		}
	}

	timer_stop(&tsock->timer_rto);
	timer_stop(&tsock->timer_wait);
	ut_dump_tsock_stats(tsock);
	ut_assert_mbuf_count();
}

static void test_tcp_close_rst_at_time_wait(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	uint32_t fin_seq;

	printf("testing tcp_close [rst at timeout] ...\n");

	tsock = ut_tcp_connect();

	tpa_close(tsock->sid);
	pkt = ut_drain_send_buff_at_close(tsock); {
		fin_seq = TCP_SEG(pkt)->seq;
		packet_free(pkt);
	}

	/* simulate the FIN|ACK from the remote end */
	pkt = ut_inject_ack_packet(tsock, fin_seq + 1);
	ut_packet_tcp_hdr(pkt)->tcp_flags |= TCP_FLAG_FIN;
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->state == TCP_STATE_TIME_WAIT);

		/* verify FIN ACK is sent out */
		assert(ut_tcp_output(&pkt, 1) == 1);
		assert(TCP_SEG(pkt)->flags == TCP_FLAG_ACK);
		packet_free(pkt);
	}

	pkt = ut_inject_rst_packet(tsock);
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->state == TCP_STATE_CLOSED);
		assert(tsock->sid == TSOCK_SID_FREEED);
	}

	timer_stop(&tsock->timer_rto);
	timer_stop(&tsock->timer_wait);
	ut_dump_tsock_stats(tsock);
	ut_assert_mbuf_count();
}

static void test_tcp_close_rst_at_close(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	int sid;

	printf("testing tcp_close [rst at close] ...\n");

	tsock = ut_tcp_connect();
	sid = tsock->sid;
	ut_close(tsock, CLOSE_TYPE_4WAY);

	pkt = ut_inject_rst_packet(tsock); {
		pkt->mbuf.ol_flags |= PKT_RX_FDIR_ID;
		pkt->mbuf.hash.fdir.hi = make_flow_mark(0, sid);

		/*
		 * simulate tsock reset (this sock is re-allocated)
		 */
		tsock->worker = NULL;
		ut_tcp_input_one(tsock, pkt);
	}
}

static void test_tcp_close_rcv_rst_after_fin_sent(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	uint32_t fin_seq;

	printf("testing tcp_close [rcv rst after fin sent] ...\n");

	tsock = ut_tcp_connect();

	tpa_close(tsock->sid);
	pkt = ut_drain_send_buff_at_close(tsock); {
		fin_seq = TCP_SEG(pkt)->seq;
		packet_free(pkt);
	}

	/* simulate the fin|ack|RST from the remote end */
	pkt = ut_inject_ack_packet(tsock, fin_seq + 1);
	ut_packet_tcp_hdr(pkt)->tcp_flags |= TCP_FLAG_FIN | TCP_FLAG_RST;
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->state == TCP_STATE_CLOSED);
		assert(tsock->sid == TSOCK_SID_FREEED);
	}

	timer_stop(&tsock->timer_rto);
	timer_stop(&tsock->timer_wait);
	ut_dump_tsock_stats(tsock);
	ut_assert_mbuf_count();
}

static void test_tcp_close_bunch_rst(void)
{
	struct tcp_sock *tsock;
	struct packet *pkts[BATCH_SIZE];
	int i;

	printf("testing tcp_close [rcv bunch RST] ...\n");

	tsock = ut_tcp_connect();

	for (i = 0; i < BATCH_SIZE; i++) {
		pkts[i] = ut_inject_rst_packet(tsock);
	}

	ut_tcp_input(tsock, pkts, BATCH_SIZE); {
		assert(tsock->state == TCP_STATE_CLOSED);
	}

	ut_close(tsock, CLOSE_TYPE_CLOSE_DIRECTLY);
}

static void test_tcp_close_recv_fin_ack_after_rto(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	uint32_t fin_seq;

	printf("testing tcp_close [recv remote fin ack after rto] ...\n");

	tsock = ut_tcp_connect();

	tpa_close(tsock->sid);

	pkt = ut_drain_send_buff_at_close(tsock); {
		fin_seq = TCP_SEG(pkt)->seq;
		packet_free(pkt);
	}

	/* simulate remote ACK delay */
	usleep(tsock->rto + 0.2 * 1e6);
	pkt = ut_inject_ack_packet(tsock, fin_seq + 1);
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->state == TCP_STATE_FIN_WAIT_2);
	}

	/* simulate the FIN from the remote end */
	pkt = ut_inject_ack_packet(tsock, fin_seq + 1);
	ut_packet_tcp_hdr(pkt)->tcp_flags |= TCP_FLAG_FIN;
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->state == TCP_STATE_TIME_WAIT);

		/* verify FIN ACK is sent out */
		assert(ut_tcp_output(&pkt, 1) == 1);
		assert(TCP_SEG(pkt)->flags == TCP_FLAG_ACK);
		packet_free(pkt);
	}

	timer_stop(&tsock->timer_rto);
	timer_stop(&tsock->timer_wait);
	ut_dump_tsock_stats(tsock);
	ut_assert_mbuf_count();
}

static void test_tcp_close_simultaneous_close(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	uint32_t fin_seq;

	printf("testing tcp_close with [simultaneous close] ...\n");

	tsock = ut_tcp_connect();

	tpa_close(tsock->sid);

	assert(ut_tcp_output(&pkt, 1) == 1); {
		assert(tsock->state == TCP_STATE_FIN_WAIT_1);

		fin_seq = TCP_SEG(pkt)->seq;
		packet_free(pkt);
	}

	/* simulate simultaneous close */
	pkt = ut_inject_ack_packet(tsock, fin_seq);
	ut_packet_tcp_hdr(pkt)->tcp_flags |= TCP_FLAG_FIN;
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->state == TCP_STATE_CLOSING);
	}


	/* ACK the FIN */
	pkt = ut_inject_ack_packet(tsock, fin_seq + 1);
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->state == TCP_STATE_TIME_WAIT);
	}

	ut_tcp_output(NULL, -1);
	timer_stop(&tsock->timer_rto);
	timer_stop(&tsock->timer_wait);
	ut_dump_tsock_stats(tsock);
	ut_assert_mbuf_count();
}

 /* make sure we would not stay at FIN_WAIT_2 state forever */
static void test_tcp_close_fin_wait2_hang(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;

	printf("testing tcp_close [fin_wait hang] ...\n");

	tsock = ut_tcp_connect();

	tpa_close(tsock->sid);
	ut_tcp_output(NULL, -1);

	/* speed up the time wait test */
	tcp_cfg.time_wait = 100 * 1000;

	pkt = ut_inject_ack_packet(tsock, tsock->snd_isn + 2);
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->state == TCP_STATE_FIN_WAIT_2);
	}

	usleep(tcp_cfg.time_wait + GRAGNULARITY * 1.1);
	ut_tcp_output(NULL, -1); {
		assert(tsock->state == TCP_STATE_CLOSED);
	}

	timer_stop(&tsock->timer_rto);
	ut_dump_tsock_stats(tsock);
	ut_assert_mbuf_count();
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_tcp_close_half();
	test_tcp_close_wrong_ack();
	test_tcp_close_complete();
	test_tcp_close_with_pending_send();
	test_tcp_close_with_pending_send2();
	test_tcp_close_with_pending_recv();
	test_tcp_close_with_mbuf_chains();
	test_tcp_close_fin_retry();
	test_tcp_close_fin_retry_with_pending_send();
	test_tcp_close_fin_timeout();
	test_tcp_close_rst_at_time_wait();
	test_tcp_close_rst_at_close();
	test_tcp_close_rcv_rst_after_fin_sent();
	test_tcp_close_bunch_rst();
	test_tcp_close_recv_fin_ack_after_rto();
	test_tcp_close_simultaneous_close();
	test_tcp_close_fin_wait2_hang();

	return 0;
}
