/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <unistd.h>

#include "test_utils.h"
#include "mem_file.h"

static void test_tcp_timeout_rto_basic(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	char buf[1000];
	int ret;

	printf("testing tcp timeout RTO [basic] ...\n");

	tsock = ut_tcp_connect();

	ret = ut_write_assert(tsock, sizeof(buf));
	assert(ret == sizeof(buf));
	ret = ut_write_assert(tsock, sizeof(buf));
	assert(ret == sizeof(buf));
	ut_tcp_output(NULL, -1); {
		assert((uint32_t)(tsock->snd_nxt - tsock->snd_una) == 2 * sizeof(buf));
	}

	ut_simulate_rto_timeout(tsock);

	/* retransmit */
	assert(ut_tcp_output(&pkt, 1) >= 1); {
		assert(tsock->retrans_stage == RTO);
		assert(TCP_SEG(pkt)->seq == tsock->snd_una);
		assert(TCP_SEG(pkt)->len >= sizeof(buf));
		packet_free(pkt);

		assert(ut_tcp_output(&pkt, 1) == 0);
	}

	/* ack the first seg; also partially ack the 2nd seg */
	pkt = ut_inject_ack_packet(tsock, tsock->snd_una + sizeof(buf) + 2);
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->retrans_stage == RTO);
		assert(tsock->snd_una == (uint32_t)(tsock->snd_nxt - sizeof(buf) + 2));
	}

	/* ack the 2nd seg */
	pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt);
	ut_tcp_input_one(tsock, pkt); {
		void *record;

		assert(tsock->retrans_stage == NONE);
		assert(tsock->snd_una == tsock->snd_nxt);
		assert(timer_is_stopped(&tsock->timer_rto));

		/* make sure a trace archive is generated */
		assert(rte_ring_dequeue(record_to_archive_list, &record) == 0);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_timeout_rto_timeout(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	char buf[1000];
	uint64_t start_ts_us;
	int ret;

	printf("testing tcp timeout RTO [timeout] ...\n");

	tsock = ut_tcp_connect();

	ret = ut_write_assert(tsock, sizeof(buf));
	assert(ret == sizeof(buf));
	ut_tcp_output(NULL, -1); {
		assert((uint32_t)(tsock->snd_nxt - tsock->snd_una) == sizeof(buf));
	}

	/* TODO: speed up it */
	start_ts_us = worker->ts_us;
	while (tsock->rto_shift < 3) {
		pkt = NULL;
		assert(ut_tcp_output(&pkt, 1) <= 1); {
			assert((uint32_t)(tsock->snd_nxt - tsock->snd_una) == sizeof(buf));
		}

		if (pkt) {
			printf(":: %d got pkt after %.2f\n", tsock->rto_shift, (double)(worker->ts_us - start_ts_us) / 1e6);
			start_ts_us = worker->ts_us;
			packet_free(pkt);
		}
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

/*
 * partially ack a chain of pkts
 */
static void test_tcp_timeout_rto_partial_ack(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	char buf[1];
	int ret;

	printf("testing tcp timeout RTO [partial ack] ...\n");

	tsock = ut_tcp_connect();

	ret = ut_write_assert(tsock, sizeof(buf));
	assert(ret == sizeof(buf));
	ret = ut_write_assert(tsock, sizeof(buf));
	assert(ret == sizeof(buf));
	assert(ut_tcp_output(NULL, 1) == 1); {
		assert((uint32_t)(tsock->snd_nxt - tsock->snd_una) == sizeof(buf) * 2);
	}

	/* ack the first seg */
	pkt = ut_inject_ack_packet(tsock, tsock->snd_una + sizeof(buf));
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->retrans_stage == NONE);
		assert(tsock->snd_una == (uint32_t)(tsock->snd_nxt - sizeof(buf)));
	}

	ut_simulate_rto_timeout(tsock);

	/* seg 2 is expected to be retransmited */
	assert(ut_tcp_output(&pkt, 1) == 1); {
		assert(tsock->retrans_stage == RTO);
		assert(TCP_SEG(pkt)->seq == tsock->snd_una);
		assert(TCP_SEG(pkt)->len == sizeof(buf));
		packet_free(pkt);

		assert(ut_tcp_output(&pkt, 1) == 0);
	}

	/* ack the 2nd seg */
	pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt);
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->retrans_stage == NONE);
		assert(tsock->snd_una == tsock->snd_nxt);
		assert(timer_is_stopped(&tsock->timer_rto));
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

/*
 * 1. send 4 pkts
 * 2. timeout
 * 3. retrans 1
 * 4. ack 3 (assuming no pkt lost happened)
 * 5. retrans the last 1
 */
static void test_tcp_timeout_rto_partial_ack2(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	uint32_t _cwnd_init = tcp_cfg.cwnd_init;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	tcp_cfg.cwnd_init = tsock->snd_mss;

	/* 1. */
	ut_write_assert(tsock, tsock->snd_mss);
	ut_write_assert(tsock, tsock->snd_mss);
	ut_write_assert(tsock, tsock->snd_mss);
	ut_write_assert(tsock, tsock->snd_mss);
	ut_tcp_output(NULL, -1);

	/* 2. */
	ut_simulate_rto_timeout(tsock); {
		/* 3. */
		assert(ut_tcp_output(&pkt, 1) == 1); {
			assert(TCP_SEG(pkt)->len == tsock->snd_mss);
			packet_free(pkt);
		}
	}

	/* 4. */
	pkt = ut_inject_ack_packet(tsock, tsock->snd_una + tsock->snd_mss * 3);
	tsock->snd_cwnd_ts_us = worker->ts_us; /* a trick to not update cwnd */
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->retrans_stage == RTO);
		assert(seq_lt(tsock->snd_una, tsock->snd_recover));

		/* 5. */
		assert(ut_tcp_output(&pkt, 1) == 1); {
			assert(TCP_SEG(pkt)->seq == tsock->snd_una);
			assert(TCP_SEG(pkt)->len == tsock->snd_mss);
			packet_free(pkt);
		}
	}

	pkt = ut_inject_ack_packet(tsock, tsock->snd_una + tsock->snd_mss);
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->retrans_stage == NONE);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);

	tcp_cfg.cwnd_init = _cwnd_init;
}

static void test_tcp_timeout_rto_ack_nxt(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	char buf[500];
	int ret;
	int i;

	printf("testing tcp timeout RTO [ACK NXT] ...\n");

	tsock = ut_tcp_connect();

#define NR_PKT		10
	for (i = 0; i < NR_PKT; i++) {
		ret = ut_write_assert(tsock, sizeof(buf));
		assert(ret == sizeof(buf));
	}
	ut_tcp_output(NULL, -1); {
		assert((uint32_t)(tsock->snd_nxt - tsock->snd_una) == NR_PKT * sizeof(buf));
	}

	/* ack the first seg */
	pkt = ut_inject_ack_packet(tsock, tsock->snd_una + sizeof(buf));
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->snd_una == (uint32_t)(tsock->snd_nxt - (NR_PKT - 1) * sizeof(buf)));
	}


	ut_simulate_rto_timeout(tsock);

	/* retransmit: only few segs are allowed to go out */
	assert(ut_tcp_output(&pkt, 1) >= 1); {
		assert(tsock->retrans_stage == RTO);

		assert(pkt->mbuf.nb_segs >= 2);
		assert(pkt->mbuf.data_len == pkt->hdr_len);
		assert(pkt->mbuf.next->data_len == 500);

		packet_free(pkt);

		/* no segs are allowed to go out */
		assert(ut_tcp_output(&pkt, 1) == 0);
	}

	/* ack all */
	pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt);
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->retrans_stage == NONE);
		assert(tsock->snd_una == tsock->snd_nxt);
		assert(tsock->txq.una == tsock->txq.nxt);
		assert(timer_is_stopped(&tsock->timer_rto));
		assert(tsock->stats_base[BYTE_XMIT] == sizeof(buf) * NR_PKT);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

/*
 * (5.1) Every time a packet containing data is sent (including a
 *       retransmission), if the timer is not running, start it running
 *       so that it will expire after RTO seconds (for the current value
 *       of RTO).
 */
static void test_tcp_timeout_rto_timer_rfc6298_5_1(void)
{
	struct tcp_sock *tsock;
	struct timer_snapshot snapshot;

	printf("testing %s ...\n",  __func__);

	tsock = ut_tcp_connect();

	/* start timer when it's not running */
	assert(timer_is_stopped(&tsock->timer_rto));
	ut_write_assert(tsock, 1000);
	assert(ut_tcp_output(NULL, -1) == 1); {
		ut_take_timer_snapshot(&tsock->timer_rto, &snapshot);
		assert(!timer_is_stopped(&tsock->timer_rto));
	}

	/* do not reset timer when it's already running */
	ut_write_assert(tsock, 1000);
	assert(ut_tcp_output(NULL, -1) == 1); {
		assert(ut_time_not_changed(&tsock->timer_rto, &snapshot));
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

/*
 * (5.2) When all outstanding data has been acknowledged, turn off the
 *       retransmission timer.
 */
static void test_tcp_timeout_rto_timer_rfc6298_5_2(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;

	printf("testing %s ...\n",  __func__);

	tsock = ut_tcp_connect();

	ut_write_assert(tsock, 1000);
	assert(ut_tcp_output(NULL, -1) == 1);

	/* timer should be stopped when all outstanding data has been acked */
	pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt);
	ut_tcp_input_one(tsock, pkt); {
		assert(timer_is_stopped(&tsock->timer_rto));
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

/*
 * (5.3) When an ACK is received that acknowledges new data, restart the
 *       retransmission timer so that it will expire after RTO seconds
 *       (for the current value of RTO).
 */
static void test_tcp_timeout_rto_timer_rfc6298_5_3(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	struct timer_snapshot snapshot;

	printf("testing %s ...\n",  __func__);

	tsock = ut_tcp_connect();

	ut_write_assert(tsock, 1000);
	assert(ut_tcp_output(NULL, -1) == 1); {
		ut_take_timer_snapshot(&tsock->timer_rto, &snapshot);
	}

	ut_write_assert(tsock, 1000);
	assert(ut_tcp_output(NULL, -1) == 1);

	/* acking the first one restarts the timer */
	pkt = ut_inject_ack_packet(tsock, tsock->snd_una + 1000);
	/*
	 * it's observed that "xmit 2 segs and recv the first ack" could be
	 * done in 1 us, that the RTO timer is not changed. Injecting a short
	 * delay here would avoid that.
	 */
	usleep(tsock->rto);
	ut_tcp_input_one(tsock, pkt); {
		assert(!ut_time_not_changed(&tsock->timer_rto, &snapshot));
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

/*
 * (5.4) Retransmit the earliest segment that has not been acknowledged
 *       by the TCP receiver.
 *
 * (5.5) The host MUST set RTO <- RTO * 2 ("back off the timer").  The
 *       maximum value discussed in (2.5) above may be used to provide
 *       an upper bound to this doubling operation.
 *
 * (5.6) Start the retransmission timer, such that it expires after RTO
 *       seconds (for the value of RTO after the doubling operation
 *       outlined in 5.5).
 */
static void test_tcp_timeout_rto_timer_rfc6298_5_4to6(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	struct timer_snapshot snapshot;

	printf("testing %s ...\n",  __func__);

	tsock = ut_tcp_connect();

	ut_write_assert(tsock, 1000);
	assert(ut_tcp_output(NULL, -1) == 1);

	ut_take_timer_snapshot(&tsock->timer_rto, &snapshot);
	ut_simulate_rto_timeout(tsock); {
		/* 5.4 */
		assert(ut_tcp_output(&pkt, 1) == 1); {
			assert(tsock->retrans_stage == RTO);
			assert(TCP_SEG(pkt)->len == 1000);
			packet_free(pkt);

			/* 5.5 & 5.6 */
			assert(tsock->rto_shift == 1);
			assert(!ut_time_not_changed(&tsock->timer_rto, &snapshot));
			assert(!timer_is_stopped(&tsock->timer_rto));

			assert(ut_tcp_output(NULL, -1) == 0);
		}
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_timeout_rto_timer_rfc6298_5_2_with_timeout(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;

	printf("testing %s ...\n",  __func__);

	tsock = ut_tcp_connect();

	ut_write_assert(tsock, 1000);
	assert(ut_tcp_output(NULL, -1) == 1);

	ut_simulate_rto_timeout(tsock); {
		assert(ut_tcp_output(NULL, 0) == 1);
	}

	/* acking all should stop the timer */
	pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt);
	ut_tcp_input_one(tsock, pkt); {
		assert(timer_is_stopped(&tsock->timer_rto));
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

/* RFC 6298 page 5:
 * Note that after retransmitting, once a new RTT measurement is
 * obtained (which can only happen when new data has been sent and
 * acknowledged), the computations outlined in Section 2 are performed,
 * including the computation of RTO, which may result in "collapsing"
 * RTO back down after it has been subject to exponential back off (rule
 * 5.5).
 */
static void test_tcp_timeout_rto_timer_rfc6298_5_3_with_timeout(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;

	printf("testing %s ...\n",  __func__);

	tsock = ut_tcp_connect();

	ut_write_assert(tsock, 1000);
	ut_write_assert(tsock, 1000);
	assert(ut_tcp_output(NULL, -1) == 2 - WITH_TSO);

	ut_simulate_rto_timeout(tsock); {
		assert(ut_tcp_output(NULL, 0) == 1);
	}

	/* an valid ACK (even it's doesn't ack all) should reset rto backoff */
	pkt = ut_inject_ack_packet(tsock, tsock->snd_una + 1000);
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->rto_shift == 0);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

/* a dupack should not reset RTO */
static void test_tcp_timeout_rto_timer_rfc6298_5_3_dupack(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	struct timer_snapshot snapshot;

	printf("testing %s ...\n",  __func__);

	tsock = ut_tcp_connect();

	ut_write_assert(tsock, 1000);
	assert(ut_tcp_output(NULL, -1) == 1); {
		ut_take_timer_snapshot(&tsock->timer_rto, &snapshot);
	}

	ut_write_assert(tsock, 1000);
	assert(ut_tcp_output(NULL, -1) == 1);

	pkt = ut_inject_ack_packet(tsock, tsock->snd_una);
	ut_tcp_input_one(tsock, pkt); {
		assert(ut_time_not_changed(&tsock->timer_rto, &snapshot));
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

/*
 * There was a bug: when rto and keepalive sits together in the same
 * timer slot, and it's the last RTO that triggers function
 * tsock_free, then it would trigger following assert
 * while processing the keepalive timer:
 *    debug_assert(timer->active == 1);
 *
 * Actually, the keepalive timer should not be processed as it will
 * be taken off from the timer list due to the tsock release triggered
 * due to RTO timeout. The reason we still referenced it was we got
 * a snapshot of the NEXT timer before processing RTO timeout.
 *
 * Below is a case that would trigger such assert with old code.
 */
static void test_tcp_timeout_rto_timeout_and_keepalive(void)
{
	struct tcp_sock *tsock;
	char buf[1000];
	int i;

	printf("testing tcp timeout RTO [timeout and keepalive] ...\n");

	tsock = ut_tcp_connect();

	ut_write_assert(tsock, sizeof(buf));
	ut_tcp_output(NULL, -1);

	tpa_close(tsock->sid);

	tcp_cfg.retries = 3;
	for (i = 0; i < tcp_cfg.retries; i++) {
		ut_simulate_rto_timeout(tsock);
		ut_tcp_output(NULL, 0);

		if (i == 1)
			timer_start(&tsock->timer_keepalive, worker->ts_us, tsock->rto << tsock->rto_shift);
	}
}

static void test_tcp_timeout_rto_false_retrans(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	ut_write_assert(tsock, tcp_cfg.cwnd_init);
	ut_tcp_output(NULL, -1);

	ut_simulate_rto_timeout(tsock);
	ut_tcp_output(NULL, 0);

	/* all data is acked; indicating it was false retrans */
	pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt);
	ut_tcp_input_one(tsock, pkt); {
		assert(tcp_txq_unfinished_pkts(&tsock->txq) == 0);
	}

	/* verify we are fine to transfer more */
	ut_write_assert(tsock, tcp_cfg.cwnd_init);
	ut_tcp_output(NULL, -1);

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_timeout_rto_stress(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	uint32_t ack;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	tcp_cfg.tcp_rto_min = 100 * 1000;
	WHILE_NOT_TIME_UP() {
		ut_write_assert(tsock, tsock->snd_mss * 2);
		ut_write_assert(tsock, tsock->snd_mss * 2);

		if (rand() % 1 <= 1)
			ut_simulate_rto_timeout(tsock);

		ack = tsock->snd_una + (rand() % (tsock->snd_nxt - tsock->snd_una + 1));
		pkt = ut_inject_ack_packet(tsock, ack);
		ut_tcp_input_one(tsock, pkt);
		ut_tcp_output(NULL, -1);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_tcp_timeout_rto_basic();
	test_tcp_timeout_rto_timeout();
	test_tcp_timeout_rto_partial_ack();
	test_tcp_timeout_rto_partial_ack2();
	test_tcp_timeout_rto_ack_nxt();
	test_tcp_timeout_rto_timer_rfc6298_5_1();
	test_tcp_timeout_rto_timer_rfc6298_5_2();
	test_tcp_timeout_rto_timer_rfc6298_5_3();
	test_tcp_timeout_rto_timer_rfc6298_5_4to6();
	test_tcp_timeout_rto_timer_rfc6298_5_2_with_timeout();
	test_tcp_timeout_rto_timer_rfc6298_5_3_with_timeout();
	test_tcp_timeout_rto_timer_rfc6298_5_3_dupack();
	test_tcp_timeout_rto_timeout_and_keepalive();
	test_tcp_timeout_rto_false_retrans();
	test_tcp_timeout_rto_stress();

	return 0;
}
