/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _TSOCK_TRACE_H_
#define _TSOCK_TRACE_H_

#include "trace/tcp.h"
#include "trace/misc.h"

static inline void tsock_trace_xmit_syn(struct tcp_sock *tsock)
{
	if (tsock->trace) {
		trace_ts(tsock, tsock->worker->ts_us);

		tsock->trace->snd_isn = tsock->snd_isn;
		tsock->trace->snd_mss = tsock->snd_mss;
		tsock->trace->snd_wscale = tsock->snd_wscale;
	}

	trace_tcp_xmit_syn(tsock, tsock->flags);
	trace_tcp_snd_una(tsock, tsock->snd_una);
}

static inline void tsock_trace_rcv_pkt(struct tcp_sock *tsock, struct packet *pkt, uint64_t ts_us)
{
	if (unlikely(tsock->state == TCP_STATE_LISTEN))
		rte_spinlock_lock(&tsock->lock);

	trace_ts(tsock, ts_us);

	trace_tcp_rcv_pkt(tsock, TCP_SEG(pkt)->seq, TCP_SEG(pkt)->ack, TCP_SEG(pkt)->wnd,
			  TCP_SEG(pkt)->len, TCP_SEG(pkt)->flags, pkt->nr_read_seg);

	if (unlikely(tsock->state == TCP_STATE_LISTEN))
		rte_spinlock_unlock(&tsock->lock);
}

static inline void tsock_trace_ack_sent_data(struct tcp_sock *tsock, struct tx_desc *desc,
					     uint32_t acked_len, int nr_acked_desc, uint64_t now)
{

	trace_tcp_ack_sent_data(tsock, acked_len, nr_acked_desc, desc->seq,
				desc->len, now - desc->ts_us, desc->flags,
				tsock->partial_ack);
}

static inline void tsock_trace_established(struct tcp_sock *tsock)
{
	if (tsock->trace) {
		tsock->trace->snd_isn = tsock->snd_isn;
		tsock->trace->snd_mss = tsock->snd_mss;
		tsock->trace->snd_wscale = tsock->snd_wscale;
		tsock->trace->rcv_isn = tsock->rcv_isn;

		trace_tcp_established(tsock, tsock->snd_nxt, tsock->snd_cwnd,
				      tsock->snd_ssthresh, tsock->rcv_nxt);
	}
}

static inline void tsock_trace_zwritev(struct tcp_sock *tsock, int nr_iov, int nr_pkt,
				       size_t size, int nr_fallback)
{
	trace_tcp_zwritev(tsock, size, nr_iov, nr_pkt,
			  tcp_txq_inflight_pkts(&tsock->txq),
			  tcp_txq_to_send_pkts(&tsock->txq), nr_fallback);
}

static inline void tsock_trace_xmit_pkt(struct tcp_sock *tsock, struct packet *pkt, int error)
{
	uint64_t now = tsock->worker->ts_us;

	if (likely(pkt)) {
		if (unlikely(tsock->state == TCP_STATE_LISTEN))
			rte_spinlock_lock(&tsock->lock);

		if (tsock->xmit_trace_ts != (uint16_t)now) {
			trace_ts(tsock, tsock->worker->ts_us);
			tsock->xmit_trace_ts = (uint16_t)now;
		}

		trace_tcp_xmit_pkt(tsock, TCP_SEG(pkt)->seq, pkt->mbuf.pkt_len - pkt->hdr_len, pkt->hdr_len,
				   tsock->snd_nxt, pkt->flags,
				   tsock->snd_wnd, pkt->mbuf.nb_segs, TCP_SEG(pkt)->flags,
				   us_to_tcp_ts(tsock->worker->ts_us));

		if (unlikely(tsock->state == TCP_STATE_LISTEN))
			rte_spinlock_unlock(&tsock->lock);
	}

	if (unlikely(error))
		trace_error(tsock, error);
}

static inline void tsock_trace_fast_retrans(struct tcp_sock *tsock, int stage)
{
	trace_tcp_fast_retrans(tsock, tsock->snd_ssthresh, stage,
			       tsock->snd_cwnd, tsock->snd_recover);
}

static inline void tsock_trace_sack(struct tcp_sock *tsock, uint8_t type,
				    struct tcp_sack_block *blocks, int nr_sack)
{
	uint32_t start;
	uint32_t len;
	uint16_t r16;
	uint8_t  r8;
	int i;

	for (i = 0; i < nr_sack; i++) {
		start = blocks[i].start;
		len   = blocks[i].end - start;

		SACK_TRACE_PACK_R16_R8(r16, r8, len, type);
		trace_tcp_sack(tsock, start, r16, r8);
	}
}

#endif
