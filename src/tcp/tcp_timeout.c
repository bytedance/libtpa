/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>

#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_ip_frag.h>
#include <rte_tcp.h>

#include "tpa.h"
#include "tcp.h"
#include "sock.h"
#include "tcp_queue.h"
#include "trace.h"
#include "worker.h"
#include "tsock_trace.h"

#define IS_TIMER_RTO(tsock, timer)		(offsetof(struct tcp_sock, timer_rto)  == (uint8_t *)(timer) - (uint8_t *)(tsock))
#define IS_TIMER_WAIT(tsock, timer)		(offsetof(struct tcp_sock, timer_wait) == (uint8_t *)(timer) - (uint8_t *)(tsock))
#define IS_TIMER_KEEPALIVE(tsock, timer)	(offsetof(struct tcp_sock, timer_keepalive) == (uint8_t *)(timer) - (uint8_t *)(tsock))

/*
 * Per RFC2018 page 6:
 *
 * After a retransmit timeout the data sender SHOULD turn off all of the
 * SACKed bits, since the timeout might indicate that the data receiver
 * has reneged.
 */
static void clear_sacked(struct tcp_sock *tsock)
{
	struct tx_desc *desc;
	uint16_t idx = 0;

	while (1) {
		desc = tcp_txq_peek_for_write(&tsock->txq, tsock->txq.una, idx++);
		if (!desc)
			break;

		desc->flags &= ~TX_DESC_FLAG_SACKED;
	}

	tsock->sacked_bytes = 0;
}

static void tcp_timeout_rto(struct tpa_worker *worker, struct tcp_sock *tsock)
{
	int timeout = 0;
	uint32_t seq;

	WORKER_TSOCK_STATS_INC(worker, tsock, TCP_RTO_TIME_OUT);
	tsock->rto_shift += 1;
	vstats8_max_add(&tsock->rto_shift_max, tsock->rto_shift);

	if (tsock->state == TCP_STATE_SYN_SENT || tsock->state == TCP_STATE_SYN_RCVD)
		timeout = tsock->rto_shift >= tcp_cfg.syn_retries;
	else
		timeout = tsock->rto_shift >= tcp_cfg.retries;

	if (timeout) {
		int to_close;

		tsock->err = ETIMEDOUT;

		to_close = tsock->state == TCP_STATE_SYN_RCVD;
		tsock_set_state(tsock, TCP_STATE_CLOSED);

		if (tsock->close_issued || to_close)
			tsock_free(tsock);
		else
			tsock_event_add(tsock, TPA_EVENT_ERR);
		return;
	}

	if (tsock->rto_shift == 1) {
		struct tx_desc *desc = tcp_txq_peek_una_before_nxt(&tsock->txq, 0);

		if (desc)
			tsock->rto_start_ts = desc->ts_us;
	}

	clear_sacked(tsock);

	tsock->retrans_stage = RTO;
	tsock->snd_recover = tsock->snd_nxt;

	tsock->snd_ssthresh = RTE_MAX(tsock->snd_cwnd / 2, 2 * tsock->snd_mss);
	tsock->snd_cwnd = tsock->snd_mss;

	trace_tcp_rto(tsock, tsock->snd_ssthresh, tsock->rto_shift,
		      tsock->snd_cwnd, tsock->snd_recover);

	timer_start(&tsock->timer_rto, worker->ts_us, RTE_MIN(TCP_RTO_MAX, tsock->rto << tsock->rto_shift));
	if (tsock->state == TCP_STATE_SYN_SENT || tsock->state == TCP_STATE_SYN_RCVD)
		seq = tsock->snd_una + 1;
	else
		seq = tsock->snd_una;
	tcp_reset_retrans(tsock, seq, tsock->txq.una);
	tcp_retrans(worker, tsock);

	/*
	 * XXX: we still need this because tcp_retrans does not
	 * handle syn/fin retrans
	 */
	output_tsock_enqueue(tsock->worker, tsock);
}

static void tcp_timeout_wait(struct tpa_worker *worker, struct tcp_sock *tsock)
{
	WORKER_TSOCK_STATS_INC(worker, tsock, TCP_WAIT_TIME_OUT);

	tsock_set_state(tsock, TCP_STATE_CLOSED);
	tsock_free(tsock);
}

static void tcp_timeout_keepalive(struct tpa_worker *worker, struct tcp_sock *tsock)
{
	if (tsock->keepalive_shift++ >= tcp_cfg.retries) {
		WORKER_TSOCK_STATS_INC(worker, tsock, TCP_KEEPALIVE_TIME_OUT);
		tsock->err = ETIMEDOUT;

		tsock_set_state(tsock, TCP_STATE_CLOSED);

		if (tsock->close_issued)
			tsock_free(tsock);
		else
			tsock_event_add(tsock, TPA_EVENT_ERR);
		return;
	}

	if (tsock->state == TCP_STATE_ESTABLISHED) {
		tsock->flags |= TSOCK_FLAG_ACK_NEEDED;
		xmit_flag_packet_with_seq(worker, tsock, tsock->snd_una - 1);
		WORKER_TSOCK_STATS_INC(worker, tsock, TCP_KEEPALIVE_PROBE);

		timer_start(&tsock->timer_keepalive, worker->ts_us, tcp_cfg.keepalive);
	}
}

void tcp_timeout(struct timer *timer)
{
	struct tcp_sock *tsock = timer->arg;
	struct tpa_worker *worker = tsock->worker;

	trace_ts(tsock, worker->ts_us);

	/* this really should not happen ... */
	if (tsock->state == TCP_STATE_CLOSED) {
		int err = ERR_TCP_TIMEOUT_ON_CLOSED;

		trace_error(tsock, err);
		WORKER_TSOCK_STATS_INC(worker, tsock, err);
		return;
	}

	/* It is tricky, but we need to keep correct net header since ARP maping may change. */
	tsock_try_update_eth_hdr(worker, tsock);

	if (IS_TIMER_RTO(tsock, timer)) {
		tcp_timeout_rto(worker, tsock);
	} else if (IS_TIMER_WAIT(tsock, timer)) {
		tcp_timeout_wait(worker, tsock);
	} else if (IS_TIMER_KEEPALIVE(tsock, timer)) {
		tcp_timeout_keepalive(worker, tsock);
	} else {
		WORKER_TSOCK_STATS_INC(worker, tsock, ERR_TCP_TIMER_INVALID_TYPE);
	}
}
