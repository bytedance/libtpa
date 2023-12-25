/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022, ByteDance Ltd. and/or its Affiliates
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
#include "log.h"

struct iov_ctx {
	uint32_t nr_iov;
	uint32_t idx;
	ssize_t  size;
	struct tpa_iovec *iov;
	struct tcp_sock *tsock;
};

static inline void tsock_read_latency_update(struct tcp_sock *tsock, struct packet *pkt)
{
	vstats_add(&tsock->read_lat.submit, pkt->read_tsc.submit - pkt->read_tsc.start);
	vstats_add(&tsock->read_lat.drain, pkt->read_tsc.drain - pkt->read_tsc.start);
	vstats_add(&tsock->read_lat.complete, rte_rdtsc() - pkt->read_tsc.start);
	vstats_add(&tsock->read_lat.last_write, rte_rdtsc() - tsock->last_ts[LAST_TS_WRITE]);
}

static void iov_buf_free(void *addr, void *param)
{
	struct tcp_sock *tsock;
	struct packet *pkt = param;

	if (--pkt->nr_read_seg == 0) {
		tsock = pkt->tsock;

		if (unlikely(pkt->flags & PKT_FLAG_MEASURE_READ_LATENCY))
			tsock_read_latency_update(tsock, pkt);

		tsock->worker->nr_in_process_mbuf -= pkt->mbuf.nb_segs;

		debug_assert(pkt->mbuf.pool == generic_pkt_pool->pool[0] ||
			     pkt->mbuf.pool == generic_pkt_pool->pool[1]);
		packet_free(pkt);
	}
}

static inline size_t pkt_to_iov_one_seg(struct tpa_iovec *iov,
					struct packet *head,
					struct packet *pkt)
{
	iov->iov_base = tcp_payload_addr(pkt);
	iov->iov_phys = tcp_payload_phys_addr(pkt);
	iov->iov_len  = pkt->l5_len;
	iov->iov_read_done = iov_buf_free;
	iov->iov_param     = head;

	TCP_SEG(head)->len -= pkt->l5_len;
	if (TCP_SEG(head)->len == 0 && (head->flags & PKT_FLAG_MEASURE_READ_LATENCY))
		head->read_tsc.drain = rte_rdtsc();

	return iov->iov_len;
}

static inline int pkt_to_iov(struct iov_ctx *ctx, struct packet *pkt)
{
	struct packet *to_read = pkt->to_read;
	struct tpa_iovec *iov = ctx->iov;

	while (TCP_SEG(pkt)->len && ctx->idx < ctx->nr_iov) {
		ctx->size += pkt_to_iov_one_seg(&iov[ctx->idx++], pkt, to_read);
		to_read = (struct packet *)(to_read->mbuf.next);
	}

	if (TCP_SEG(pkt)->len) {
		pkt->to_read = to_read;
		return -1;
	}

	return 0;
}

/* Note that this macro has return statement */
#define TSOCK_READ_CHECK(tsock)		do {				\
	if (unlikely(tsock->close_issued)) {				\
		errno = EBADF;						\
		return -1;						\
	}								\
	if (unlikely(tsock->err != 0)) {				\
		errno = tsock->err;					\
		return -1;						\
	}								\
									\
	if (unlikely(tsock->state == TCP_STATE_LISTEN) ||		\
		     tsock->state == TCP_STATE_CLOSED) {		\
		errno = ENOTCONN;					\
		return -1;						\
	}								\
} while (0)

ssize_t tsock_zreadv(struct tcp_sock *tsock, struct tpa_iovec *iov, int nr_iov)
{
	struct tcp_rxq *rxq = &tsock->rxq;
	struct iov_ctx ctx = {
		.nr_iov	= nr_iov,
		.iov	= iov,
		.idx	= 0,
		.size	= 0,
	};
	struct packet *pkt;
	uint32_t nr_pkt = 0;

	TSOCK_READ_CHECK(tsock);

	while (1) {
		pkt = tcp_rxq_peek_unread(rxq, nr_pkt);
		if (!pkt)
			break;

		/*
		 * A negative return means the pkt chain is not consumed;
		 * we should not update the rxq unread pointer here.
		 */
		if (pkt_to_iov(&ctx, pkt) < 0)
			break;
		nr_pkt += 1;

		/*
		 * for debug purpose, and it's not accurate when the pkt
		 * chain is partially consumed. See above comment.
		 */
		tsock->worker->nr_in_process_mbuf += pkt->mbuf.nb_segs;
	}

	if (ctx.size == 0) {
		if (tsock->flags & TSOCK_FLAG_EOF)
			return 0;

		errno = EAGAIN;
		return -1;
	}
	tcp_rxq_update_unread(rxq, nr_pkt);
	vstats_add(&tsock->read_size, ctx.size);

	if (unlikely(tsock->rcv_wnd == 0)) {
		tsock->flags |= TSOCK_FLAG_ACK_NEEDED;
		output_tsock_enqueue(tsock->worker, tsock);
		WORKER_TSOCK_STATS_INC(tsock->worker, tsock, WND_UPDATE);
	}
	tsock->rcv_wnd += ctx.size;

	if (unlikely(trace_cfg.more_trace))
		trace_tcp_zreadv(tsock, ctx.size, nr_iov, ctx.idx, tcp_rxq_readable_count(&tsock->rxq));

	return ctx.size;
}

static inline int do_parse_tcp_packet(struct packet *pkt)
{
	struct rte_tcp_hdr *th;
	uint16_t tcp_hdr_len;

	th = packet_tcp_hdr(pkt);
	tcp_hdr_len = (th->data_off >> 4) << 2;
	pkt->l5_off = pkt->l4_off + tcp_hdr_len;
	pkt->hdr_len = pkt->l5_off - pkt->l2_off;
	if (unlikely(pkt->mbuf.pkt_len < pkt->hdr_len))
		return -ERR_PKT_INVALID_LEN;

	pkt->src_port = th->src_port;
	pkt->dst_port = th->dst_port;

	TCP_SEG(pkt)->seq   = ntohl(th->sent_seq);
	TCP_SEG(pkt)->ack   = ntohl(th->recv_ack);
	TCP_SEG(pkt)->wnd   = ntohs(th->rx_win);
	TCP_SEG(pkt)->flags = th->tcp_flags;
	TCP_SEG(pkt)->len   = pkt->ip_payload_len - tcp_hdr_len;
	TCP_SEG(pkt)->opt_len = tcp_hdr_len - sizeof(struct rte_tcp_hdr);

	pkt->l5_len = TCP_SEG(pkt)->len;
	pkt->tail = pkt;
	pkt->nr_read_seg = 1;

	return 0;
}

int parse_tcp_packet(struct packet *pkt)
{
	return do_parse_tcp_packet(pkt);
}

int parse_tcp_opts(struct tcp_opts *opts, struct packet *pkt)
{
	uint8_t *p = (uint8_t *)(packet_tcp_hdr(pkt) + 1);
	uint32_t len = TCP_SEG(pkt)->opt_len;
	uint32_t off = 0;
	struct tcp_opt *opt;
	int ret = 0;
	int i;

	memset(opts, 0, sizeof(*opts));

	while (off < len) {
		opt = (struct tcp_opt *)(p + off);

		if (opt->type == TCP_OPT_EOL_KIND)
			return 0;

		if (opt->type == TCP_OPT_NOP_KIND) {
			off += 1;
			continue;
		}

		if (opt->len < 2)
			return -ERR_INVALID_TCP_OPT_LEN;

		off += opt->len;
		if (off > len)
			return -ERR_INVALID_TCP_OPT_LEN;

		switch (opt->type) {
		case TCP_OPT_MSS_KIND:
			opts->mss = ntohs(opt->u16[0]);
			opts->has_mss = 1;
			break;

		case TCP_OPT_WSCALE_KIND:
			opts->wscale = opt->u8[0];
			opts->has_wscale = 1;

			/* XXX: log error per RFC */
			if (opts->wscale > TCP_WSCALE_MAX)
				opts->wscale = TCP_WSCALE_MAX;
			break;

		case TCP_OPT_TS_KIND:
			opts->ts.val = ntohl(opt->u32[0]);
			opts->ts.ecr = ntohl(opt->u32[1]);
			opts->has_ts = 1;
			pkt->flags |= PKT_FLAG_HAS_TS_OPT;
			TCP_SEG(pkt)->ts_val = opts->ts.val;
			TCP_SEG(pkt)->ts_ecr = opts->ts.ecr;
			break;

		case TCP_OPT_SACK_PERM_KIND:
			opts->has_sack_perm = 1;
			break;

		case TCP_OPT_SACK_KIND:
			RTE_BUILD_BUG_ON(sizeof(struct tcp_sack_block) != 8);

			if (opt->len > TCP_OPT_SACK_LEN(TCP_MAX_NR_SACK_BLOCK))
				return -ERR_INVALID_TCP_OPT_LEN;

			if ((opt->len - 2) % sizeof(struct tcp_sack_block) != 0)
				return -ERR_INVALID_TCP_OPT_LEN;

			opts->nr_sack = (opt->len - 2) / sizeof(struct tcp_sack_block);
			memcpy(opts->sack_blocks, (char *)opt + 2, opt->len - 2);
			for (i = 0; i < opts->nr_sack; i++) {
				opts->sack_blocks[i].start = ntohl(opts->sack_blocks[i].start);
				opts->sack_blocks[i].end   = ntohl(opts->sack_blocks[i].end);
			}
			break;

		default:
			ret = -ERR_INVALID_TCP_OPT_TYPE;
			break;
		}
	}

	return ret;
}

#define TS_OPT_HDR	(TCP_OPT_NOP_KIND << 24 | TCP_OPT_NOP_KIND << 16 | \
			 TCP_OPT_TS_KIND  << 8  | TCP_OPT_TS_LEN  << 0)

static inline int parse_ts_opt_fast(struct packet *pkt)
{
	uint32_t *addr = (uint32_t *)(packet_tcp_hdr(pkt) + 1);

	if (likely(addr[0] == htonl(TS_OPT_HDR))) {
		TCP_SEG(pkt)->ts_val = ntohl(addr[1]);
		TCP_SEG(pkt)->ts_ecr = ntohl(addr[2]);
		pkt->flags |= PKT_FLAG_HAS_TS_OPT;
		return 0;
	}

	return -1;
}

static inline int tcp_rcv_enqueue(struct tpa_worker *worker, struct tcp_sock *tsock,
				  struct packet *pkt)
{
	if (unlikely(TCP_SEG(pkt)->len > tsock->rcv_wnd))
		tcp_packet_cut(pkt, TCP_SEG(pkt)->len - tsock->rcv_wnd, CUT_TAIL);

	if (unlikely(TCP_SEG(pkt)->len == 0))
		return 0;

	if (unlikely(tcp_rxq_enqueue_burst(&tsock->rxq, (void **)&pkt, 1) != 1))
		return -ERR_TCP_RXQ_ENQUEUE_FAIL;

	tsock->rcv_nxt += TCP_SEG(pkt)->len;
	tsock->rcv_wnd -= TCP_SEG(pkt)->len;

	WORKER_TSOCK_STATS_ADD(worker, tsock, BYTE_RECV, TCP_SEG(pkt)->len);
	tsock_event_add(tsock, TPA_EVENT_IN);

	if (unlikely(pkt->flags & PKT_FLAG_MEASURE_READ_LATENCY))
		pkt->read_tsc.submit = rte_rdtsc();

	tsock_update_last_ts(tsock, LAST_TS_RCV_DATA);
	trace_tcp_rcv_enqueue(tsock, tsock->rcv_nxt, TCP_SEG(pkt)->len,
			      tsock->rcv_wnd, tcp_rxq_readable_count(&tsock->rxq));

	return 0;
}

static int sack_merge(struct tcp_sack_block *blk, uint32_t start, uint32_t end)
{
	if (seq_lt(end, blk->start) || seq_gt(start, blk->end))
		return 0;

	if (seq_lt(start, blk->start))
		blk->start = start;
	if (seq_gt(end, blk->end))
		blk->end = end;

	return 1;
}

/*
 * Note that the caller has to make sure the first blk
 * point to the latest sack segment.
 */
static void sack_try_merge_blocks(struct tcp_sock *tsock)
{
	struct tcp_sack_block *blk = &tsock->sack_blocks[0];
	int nr_sack = 1;
	int i;

	for (i = 1; i < tsock->nr_sack_block; i++) {
		if (!sack_merge(blk, tsock->sack_blocks[i].start, tsock->sack_blocks[i].end))
			tsock->sack_blocks[nr_sack++] = tsock->sack_blocks[i];
	}

	tsock->nr_sack_block = nr_sack;
}

#define SACK_SWAP(a, b)		do {	\
	struct tcp_sack_block tmp;	\
	tmp  = *(a);			\
	*(a) = *(b);			\
	*(b) = tmp;			\
} while (0)

static void sack_update(struct tcp_sock *tsock, uint32_t start, uint32_t len)
{
	struct tcp_sack_block *blk;
	uint32_t end = start + len;
	int nr_to_shift;
	int i;

	if (!tsock->sack_ok)
		return;

	for (i = 0; i < tsock->nr_sack_block; i++) {
		blk = &tsock->sack_blocks[i];
		if (sack_merge(blk, start, end)) {
			/* we only make sure the new sack go to the front */
			SACK_SWAP(blk, &tsock->sack_blocks[0]);
			sack_try_merge_blocks(tsock);
			goto trace;
		}
	}

	/*
	 * no sack merge happened; shift the sack blocks to right and
	 * then put the new one in front
	 */
	nr_to_shift = RTE_MIN(tsock->nr_sack_block, TCP_MAX_NR_SACK_BLOCK - 1);
	memmove(&tsock->sack_blocks[1], &tsock->sack_blocks[0],
		nr_to_shift * sizeof(struct tcp_sack_block));
	tsock->nr_sack_block = nr_to_shift + 1;

	tsock->sack_blocks[0].start = start;
	tsock->sack_blocks[0].end   = end;

trace:
	tsock_trace_sack(tsock, SACK_UPDATE, tsock->sack_blocks, tsock->nr_sack_block);
}

/*
 * Do the last regulation: remove seqs have been recv-ed.
 */
static void sack_regulate(struct tcp_sock *tsock)
{
	struct tcp_sack_block *blk;
	int nr_sack = 0;
	int i;

	for (i = 0; i < tsock->nr_sack_block; i++) {
		blk = &tsock->sack_blocks[i];
		if (seq_gt(blk->start, tsock->rcv_nxt))
			tsock->sack_blocks[nr_sack++] = *blk;
	}

	if (tsock->nr_sack_block != nr_sack) {
		tsock->nr_sack_block = nr_sack;
		tsock_trace_sack(tsock, SACK_REGULATE, tsock->sack_blocks, tsock->nr_sack_block);

		debug_assert(tsock->nr_sack_block <= TCP_MAX_NR_SACK_BLOCK);
	}
}

void tsock_remove_ooo_pkt(struct tcp_sock *tsock, struct packet *pkt)
{
	TAILQ_REMOVE(&tsock->rcv_ooo_queue, pkt, node);
	tsock->nr_ooo_pkt -= 1;
	tsock->worker->nr_ooo_mbuf -= pkt->mbuf.nb_segs;

	if (tsock->last_ooo_pkt == pkt)
		tsock->last_ooo_pkt = NULL;
}

/*
 * TODO: according to the sack RFC2018 page 10, we should update the
 * sack when ooo mbufs are dropped:
 *
 *   Except for the newest segment, all SACK blocks MUST NOT report
 *   any old data which is no longer actually held by the receiver.
 */
void tsock_drop_ooo_mbufs(struct tcp_sock *tsock)
{
	struct packet *pkt;
	int nr_to_drop;
	int i;

	if (tsock->nr_ooo_pkt == 0)
		return;

	nr_to_drop = RTE_MAX(tsock->nr_ooo_pkt / 4, 1);
	for (i = 0; i < nr_to_drop; i++) {
		pkt = TAILQ_LAST(&tsock->rcv_ooo_queue, packet_list);
		if (pkt) {
			WORKER_TSOCK_STATS_ADD(tsock->worker, tsock, OOO_MBUF_DROPPED,
					       pkt->mbuf.nb_segs);

			tsock_remove_ooo_pkt(tsock, pkt);
			packet_free(pkt);

			if (tsock->last_ooo_pkt == pkt)
				tsock->last_ooo_pkt = NULL;
		}
	}
}

static void ooo_queue_drain(struct tpa_worker *worker, struct tcp_sock *tsock)
{
	struct packet *pkt;
	struct packet *next;

	pkt = TAILQ_FIRST(&tsock->rcv_ooo_queue);
	while (pkt) {
		int err;

		if (TCP_SEG(pkt)->seq != tsock->rcv_nxt)
			break;

		err = tcp_rcv_enqueue(worker, tsock, pkt);
		if (err) {
			/*
			 * It's not really an error; it's just not delivered to
			 * the tsock rxq yet, but it'd be still kept in the OOO
			 * queue. A next data pkt (no matter in order or not )
			 * would deliver it to the tsock rxq.
			 *
			 * XXX: if no more data transmitted from the remote side,
			 * the pkt should stay in the OOO queue untill remote side
			 * starts the retrans. Well, we have OOO pkts; retrans
			 * happens.
			 */
			WORKER_TSOCK_STATS_INC(worker, tsock, -err);
			return;
		}

		next = TAILQ_NEXT(pkt, node);
		tsock_remove_ooo_pkt(tsock, pkt);

		pkt = next;
	}

	sack_regulate(tsock);

	if (tsock->nr_ooo_pkt == 0) {
		uint32_t recover_time = worker->ts_us - tsock->ooo_start_ts;

		debug_assert(TAILQ_EMPTY(&tsock->rcv_ooo_queue));

		vstats_add(&tsock->ooo_recover_time, recover_time);
		trace_tcp_ooo(tsock, OOO_RECOVERED, recover_time);
		tsock_trace_archive(tsock->trace, "ooo-%.3fms",
				    (double)recover_time / 1e3);
		tsock->last_ooo_pkt = NULL;

		/*
		 * Ideally, nr_sack_block should go 0 here, if we update
		 * the sack blocks when we drop ooo mbufs.
		 */
		tsock->nr_sack_block = 0;
	}
}

static int ooo_queue_insert(struct tcp_sock *tsock, struct packet *prev, struct packet *pkt)
{
	int to_cut;

	to_cut = TCP_SEG(pkt)->seq + TCP_SEG(pkt)->len - (tsock->rcv_nxt + tsock->rcv_wnd);
	if (to_cut > 0) {
		trace_tcp_ooo(tsock, OOO_CUT_BEYOND_WND, to_cut);
		tcp_packet_cut(pkt, to_cut, CUT_TAIL);
	}

	if (TCP_SEG(pkt)->len == 0)
		return -ERR_TCP_RCV_OOO_DUP;

	if (TCP_SEG(pkt)->seq != tsock->rcv_nxt && tsock->nr_ooo_pkt >= tcp_cfg.rcv_ooo_limit) {
		trace_tcp_ooo(tsock, OOO_DROP_DUE_TO_OOO_LIMIT, 0);
		return -ERR_TCP_RCV_OOO_LIMIT;
	}

	if (prev)
		TAILQ_INSERT_AFTER(&tsock->rcv_ooo_queue, prev, pkt, node);
	else
		TAILQ_INSERT_HEAD(&tsock->rcv_ooo_queue, pkt, node);

	sack_update(tsock, TCP_SEG(pkt)->seq, TCP_SEG(pkt)->len);
	tsock->nr_ooo_pkt += 1;
	tsock->worker->nr_ooo_mbuf += pkt->mbuf.nb_segs;
	tsock->last_ooo_pkt = pkt;
	trace_tcp_ooo(tsock, OOO_QUEUED, (TCP_SEG(pkt)->len << 16) | tsock->nr_ooo_pkt);

	return 0;
}

static int tcp_rcv_data_ooo(struct tpa_worker *worker, struct tcp_sock *tsock,
			    struct packet *pkt)
{
	struct packet *prev = NULL;
	struct packet *next;
	struct packet *tmp;
	int to_cut;

	WORKER_TSOCK_STATS_INC(worker, tsock, PKT_RECV_OOO);
	if (tsock->nr_ooo_pkt == 0)
		tsock->ooo_start_ts = worker->ts_us;

	/* a predict for handling ooo pkt, therefore, a faster path */
	if (tsock->last_ooo_pkt && TAILQ_NEXT(tsock->last_ooo_pkt, node) == NULL) {
		uint32_t end_seq;

		end_seq = TCP_SEG(tsock->last_ooo_pkt)->seq + TCP_SEG(tsock->last_ooo_pkt)->len;
		if (end_seq == TCP_SEG(pkt)->seq) {
			prev = tsock->last_ooo_pkt;
			WORKER_TSOCK_STATS_INC(worker, tsock, PKT_RECV_OOO_PREDICT);
			goto insert;
		}
	}

	TAILQ_FOREACH(next, &tsock->rcv_ooo_queue, node) {
		debug_assert(seq_ge(TCP_SEG(next)->seq, tsock->rcv_nxt) && TCP_SEG(next)->len > 0);
		debug_assert(prev == NULL || seq_gt(TCP_SEG(next)->seq, TCP_SEG(prev)->seq));
		if (seq_gt(TCP_SEG(next)->seq, TCP_SEG(pkt)->seq))
			break;
		prev = next;
	}

	if (prev) {
		if (TCP_SEG(pkt)->seq == TCP_SEG(prev)->seq &&
		    TCP_SEG(pkt)->len >  TCP_SEG(prev)->len) {
			/* this one completely overlaps the prev one; replace it */
			trace_tcp_ooo(tsock, OOO_DROP_PREV_AND_REPLACE, TCP_SEG(prev)->len);

			tmp = prev;
			prev = TAILQ_PREV(prev, packet_list, node);
			tsock_remove_ooo_pkt(tsock, tmp);
			packet_free(tmp);
		} else {
			to_cut = TCP_SEG(prev)->seq + TCP_SEG(prev)->len - TCP_SEG(pkt)->seq;
			if (to_cut > 0) {
				if (to_cut >= TCP_SEG(pkt)->len) {
					trace_tcp_ooo(tsock, OOO_DROP_CURR, TCP_SEG(prev)->seq);
					return -ERR_TCP_RCV_OOO_DUP;
				}

				trace_tcp_ooo(tsock, OOO_CUT_LEFT, to_cut);
				tcp_packet_cut(pkt, to_cut, CUT_HEAD);
			}
		}
	}

	while (next) {
		to_cut = TCP_SEG(pkt)->seq + TCP_SEG(pkt)->len - TCP_SEG(next)->seq;
		if (to_cut <= 0)
			break;

		if (to_cut < TCP_SEG(next)->len) {
			trace_tcp_ooo(tsock, OOO_CUT_RIGHT, to_cut);
			tcp_packet_cut(pkt, to_cut, CUT_TAIL);
			break;
		}

		trace_tcp_ooo(tsock, OOO_DROP_NEXT, TCP_SEG(next)->seq);
		WORKER_TSOCK_STATS_INC(worker, tsock, ERR_TCP_RCV_OOO_DUP);

		tmp = next;
		next = TAILQ_NEXT(next, node);

		tsock_remove_ooo_pkt(tsock, tmp);
		packet_free(tmp);
	}

insert:
	return ooo_queue_insert(tsock, prev, pkt);
}

static inline void tsock_set_ack_flag(struct tcp_sock *tsock, int ack_now_flag)
{
	if (tsock->quickack) {
		tsock->quickack -= 1;
		ack_now_flag = TSOCK_FLAG_ACK_NOW;
	}

	/*
	 * rfc1122 4.2.3.2 (page 96):
	 *
	 * A TCP SHOULD implement a delayed ACK, but an ACK should not be
	 * excessively delayed; in particular, ..., and in a stream of
	 * full-sized segments there SHOULD be an ACK for at least every
	 * second segment.
	 */
	if (tcp_cfg.delayed_ack == 0 || tsock->rcv_nxt - tsock->last_ack_sent >= tsock->snd_mss)
		ack_now_flag = TSOCK_FLAG_ACK_NOW;

	tsock->flags |= TSOCK_FLAG_ACK_NEEDED | ack_now_flag;
}

static inline int tcp_rcv_data(struct tpa_worker *worker, struct tcp_sock *tsock,
			       struct packet *pkt)
{
	uint32_t to_cut;
	int err;

	if (unlikely(TCP_SEG(pkt)->len == 0)) {
		if (has_flag_fin(pkt) && TCP_SEG(pkt)->seq == tsock->rcv_nxt)
			tsock->rcv_nxt += 1;

		return 0;
	}

	if (seq_lt(TCP_SEG(pkt)->seq, tsock->rcv_nxt)) {
		to_cut = tsock->rcv_nxt - TCP_SEG(pkt)->seq;
		if (to_cut >= TCP_SEG(pkt)->len) {
			/* XXX: this should never happen? */
			debug_assert(0);
			TCP_SEG(pkt)->len = 0;
			return 0;
		}

		tcp_packet_cut(pkt, to_cut, CUT_HEAD);
	}

	if (TCP_SEG(pkt)->seq == tsock->rcv_nxt) {
		struct packet *ooo_head = TAILQ_FIRST(&tsock->rcv_ooo_queue);

		if (ooo_head && seq_ge(TCP_SEG(pkt)->seq + TCP_SEG(pkt)->len, TCP_SEG(ooo_head)->seq))
			goto ooo_rcv;

		tsock_set_ack_flag(tsock, 0);
		return tcp_rcv_enqueue(worker, tsock, pkt);
	}

ooo_rcv:
	tsock_reset_quickack(tsock);
	tsock_set_ack_flag(tsock, TSOCK_FLAG_ACK_NOW);

	err = tcp_rcv_data_ooo(worker, tsock, pkt);

	/*
	 * always try to drain the ooo queue even if tcp_rcv_data_ooo
	 * may fail, as we may have left some IN-ORDER pkts in the ooo
	 * queue: see ooo_queue_drain for more details.
	 */
	ooo_queue_drain(worker, tsock);

	return err;
}

/*
 * Check Congestion Avoidance and Control by Van Jacobson for details.
 */
static inline void rtt_update(struct tpa_worker *worker, struct tcp_sock *tsock, int rtt)
{
	rtt = RTE_MIN(rtt, TCP_RTT_MAX);
	tsock->rtt = rtt;

	if (likely(tsock->srtt)) {
		rtt -= (tsock->srtt >> 3);
		tsock->srtt += rtt;

		if (rtt < 0) {
			rtt = -rtt;
			rtt = RTE_MIN(rtt, TCP_RTT_MAX);
		}
		rtt -= (tsock->rttvar >> 2);
		tsock->rttvar += rtt;
	} else {
		tsock->srtt   = rtt << 3;
		tsock->rttvar = rtt << 1;
	}

	tsock->rto = (tsock->srtt >> 3) + RTE_MAX(tcp_cfg.tcp_rto_min, tsock->rttvar);
	tsock->rto = RTE_MIN(tsock->rto, TCP_RTO_MAX);

	trace_tcp_rtt(tsock, tsock->rtt, tsock->srtt, tsock->rttvar, tsock->rto);
}

static inline void tsock_write_latency_update(struct tcp_sock *tsock, struct tx_desc *desc, uint64_t now)
{
	vstats_add(&tsock->write_lat.submit, desc->tsc_submit - desc->tsc_start);
	vstats_add(&tsock->write_lat.xmit,   desc->tsc_xmit   - desc->tsc_start);
	vstats_add(&tsock->write_lat.complete, now - desc->tsc_start);
}

static inline int ack_sent_data(struct tpa_worker *worker, struct tcp_sock *tsock,
				struct packet *ack_pkt, uint32_t acked_len, uint32_t *rtt)
{
	struct tcp_txq *txq = &tsock->txq;
	struct tx_desc *desc;
	uint16_t nr_acked_pkt;
	uint64_t now = 0;

	trace_tcp_snd_una(tsock, tsock->snd_una + acked_len);

	nr_acked_pkt = 0;
	*rtt = 0;
	do {
		desc = tcp_txq_peek_una(txq, nr_acked_pkt);
		tsock_trace_ack_sent_data(tsock, desc, acked_len,
					  nr_acked_pkt, worker->ts_us);

		/* XXX: it should be abnormal to go here */
		debug_assert(desc != NULL);
		debug_assert(desc->len > 0);
		debug_assert(desc->seq + tsock->partial_ack == tsock->snd_una);

		if (tsock->partial_ack + acked_len < desc->len) {
			/* partial ack */
			tsock->partial_ack += acked_len;
			tsock->snd_una     += acked_len;
			break;
		}

		tsock->snd_una += desc->len - tsock->partial_ack;
		acked_len      -= desc->len - tsock->partial_ack;
		tsock->partial_ack = 0;

		if (unlikely(desc->flags & TX_DESC_FLAG_SACKED))
			tsock->sacked_bytes -= desc->len;

		/* rtt for retransmit pkts is excluded */
		if (*rtt == 0 && (desc->flags & TX_DESC_FLAG_RETRANS) == 0)
			*rtt = worker->ts_us - desc->ts_us;

		if (unlikely(desc->flags & TX_DESC_FLAG_MEASURE_LATENCY)) {
			if (!now)
				now = rte_rdtsc();
			tsock_write_latency_update(tsock, desc, now);
		}

		nr_acked_pkt += 1;
		tx_desc_done(desc, worker);
	} while (acked_len > 0);

	/*
	 * Before we have done the retransmit of all packets between UNA
	 * and NXT, we might get an ACK that acks all data at (or after,
	 * in case new data transmited) NXT. In such case, we should reset
	 * the txq nxt pointer here.
	 */
	debug_assert((int16_t)(txq->nxt - txq->una) >= 0);
	if ((uint16_t)(txq->nxt - txq->una) < nr_acked_pkt)
		txq->nxt = txq->una + nr_acked_pkt;

	tcp_txq_update_una(txq, nr_acked_pkt);
	trace_tcp_update_txq(tsock, tcp_txq_inflight_pkts(&tsock->txq), tcp_txq_to_send_pkts(&tsock->txq));

	if (tcp_txq_free_count(txq))
		tsock_event_add(tsock, TPA_EVENT_OUT);

	return 0;
}

static inline void set_cwnd(struct tcp_sock *tsock, uint32_t cwnd)
{
	tsock->snd_cwnd = RTE_MAX(RTE_MIN(cwnd, tcp_cfg.cwnd_max), tsock->snd_mss);
	trace_tcp_update_cwnd(tsock, tsock->snd_cwnd);
}

static inline void update_cwnd(struct tpa_worker *worker, struct tcp_sock *tsock, uint32_t acked)
{
	uint32_t add_up;

	tsock->snd_cwnd_uncommited += acked;

	/* update snd_cwnd only at rtt interval */
	if (worker->ts_us - tsock->snd_cwnd_ts_us < (tsock->srtt >> 3))
		return;

	/* meaning it's not cwnd limited */
	if (tsock->snd_cwnd_uncommited < tsock->snd_cwnd)
		goto out;

	if (tsock->snd_cwnd < tsock->snd_ssthresh) {
		/* TODO: add option to disable abc */
		tsock->snd_cwnd += tsock->snd_cwnd_uncommited;
	} else {
		/* basically increase cwnd by one mss each rtt */
		add_up = tsock->snd_cwnd_uncommited * tsock->snd_mss / tsock->snd_cwnd;
		tsock->snd_cwnd += RTE_MAX(1, add_up);
	}

	set_cwnd(tsock, tsock->snd_cwnd);

out:
	tsock->snd_cwnd_ts_us = worker->ts_us;
	tsock->snd_cwnd_uncommited = 0;
}

static void leave_fast_retrans(struct tcp_sock *tsock, uint32_t cwnd, int trace_type)
{
	set_cwnd(tsock, cwnd);
	tsock_trace_fast_retrans(tsock, trace_type);

	tsock->retrans_stage = NONE;
	tsock->nr_dupack = 0;
}

static inline void handle_fast_retransmit(struct tpa_worker *worker, struct tcp_sock *tsock,
					  struct packet *pkt, uint32_t acked)
{
	int retrans_budget = tsock->snd_mss;
	uint32_t sacked_bytes;
	uint32_t cwnd;

	if (likely(tsock->nr_dupack < 3 && tsock->retrans_stage != FAST_RETRANS))
		return;

	if (tsock->retrans_stage == NONE && seq_gt(TCP_SEG(pkt)->ack, tsock->snd_recover)) {
		tsock->snd_ssthresh = RTE_MAX(tsock->snd_cwnd / 2, (uint32_t)(2 * tsock->snd_mss));
		tsock->snd_recover = tsock->snd_nxt;
		tsock->snd_cwnd_orig = tsock->snd_cwnd;
		set_cwnd(tsock, tsock->snd_cwnd + tsock->nr_dupack * tsock->snd_mss);
		tsock->retrans_stage = FAST_RETRANS;

		tsock_trace_fast_retrans(tsock, FAST_RETRANS_ENTERING);
		tcp_reset_retrans(tsock, tsock->snd_una, tsock->txq.una);
		tcp_fast_retrans(worker, tsock, tsock->snd_mss);
		if (tsock->ts_ok)
			tsock->retrans.ts_val = us_to_tcp_ts(worker->ts_us);
	}

	if (tsock->retrans_stage != FAST_RETRANS)
		return;

	if (acked == 0) {
		if (tsock->sack_ok)
			sacked_bytes = tsock->sacked_bytes;
		else
			sacked_bytes = tsock->nr_dupack * tsock->snd_mss;
		sacked_bytes = RTE_MIN(sacked_bytes, tsock->snd_cwnd_orig);

		/* cwnd inflation */
		cwnd = tsock->snd_cwnd_orig + sacked_bytes;
		set_cwnd(tsock, cwnd);
		return;
	}

	/* partial ack */
	if (seq_lt(TCP_SEG(pkt)->ack, tsock->snd_recover)) {
		if (tsock->retrans.ts_val && seq_lt(TCP_SEG(pkt)->ts_ecr, tsock->retrans.ts_val)) {
			leave_fast_retrans(tsock, tsock->snd_cwnd_orig, FAST_RETRANS_FALSE);
			return;
		}
		/* make sure the false detection is made against the first ACK */
		tsock->retrans.ts_val = 0;

		/* cwnd deflation */
		cwnd = tsock->snd_cwnd - acked;
		set_cwnd(tsock, RTE_MAX(tsock->snd_cwnd_orig, cwnd));

		if (tsock->sack_ok)
			retrans_budget = RTE_MIN(tsock->sacked_bytes, tsock->snd_ssthresh);
		tcp_fast_retrans(worker, tsock, retrans_budget);
		timer_start(&tsock->timer_rto, worker->ts_us, tsock->rto);
	} else {
		leave_fast_retrans(tsock, tsock->snd_ssthresh, FAST_RETRANS_LEAVING);
	}
}

static int sack_block_cmp(const void *__a, const void *__b)
{
	const struct tcp_sack_block *a = __a;
	const struct tcp_sack_block *b = __b;

	return seq_gt(a->start, b->start);
}

static int sort_sack(int nr_sack, struct tcp_sack_block *blocks)
{
	uint32_t prev_end;
	int i;

	qsort(blocks, nr_sack, sizeof(struct tcp_sack_block), sack_block_cmp);

	prev_end = blocks[0].end;
	for (i = 1; i < nr_sack; i++) {
		if (seq_lt(blocks[i].start, prev_end))
			return -ERR_TCP_SACK_INTERSECT;
		prev_end = blocks[i].end;
	}

	return 0;
}

static void mark_desc_sacked(struct tpa_worker *worker, struct tcp_sock *tsock,
			     struct tx_desc *desc)
{
	if (desc->flags & TX_DESC_FLAG_SACKED)
		return;

	tsock->sacked_bytes += desc->len;
	desc->flags |= TX_DESC_FLAG_SACKED;
	trace_tcp_desc_sacked(tsock, desc->seq, desc->len,
			      worker->ts_us - desc->ts_us, desc->flags);
}

static __rte_noinline void tcp_rcv_sack(struct tpa_worker *worker,
					struct tcp_sock *tsock,
					struct tcp_opts *opts)
{
	struct tcp_txq *txq = &tsock->txq;
	int nr_sack = opts->nr_sack;
	struct tcp_sack_block blocks[TCP_MAX_NR_SACK_BLOCK];
	struct tcp_sack_block *blk;
	struct tx_desc *desc;
	uint16_t desc_off = 0;
	int ret;
	int i;

	memcpy(blocks, opts->sack_blocks, nr_sack * sizeof(struct tcp_sack_block));
	tsock_trace_sack(tsock, SACK_RCV, blocks, nr_sack);

	ret = sort_sack(nr_sack, blocks);
	if (ret < 0) {
		WORKER_TSOCK_STATS_INC(worker, tsock, -ret);
		return;
	}

	for (i = 0; i < nr_sack; i++) {
		blk = &blocks[i];

		/* XXX: we probably should count it */
		if (seq_gt(blk->end, tsock->snd_nxt))
			continue;

		while (1) {
			desc = tcp_txq_peek_for_write(txq, txq->una, desc_off++);
			if (!desc)
				break;

			if (seq_ge(desc->seq + desc->len, tsock->snd_nxt))
				break;

			if (seq_ge(desc->seq + desc->len, blk->end))
				break;

			if (seq_ge(desc->seq, blk->start))
				mark_desc_sacked(worker, tsock, desc);
		}
	}
}

static inline void tsock_established(struct tpa_worker *worker, struct tcp_sock *tsock, struct packet *pkt);
static inline int tcp_rcv_ack(struct tpa_worker *worker, struct tcp_sock *tsock,
			      struct packet *pkt, struct tcp_opts *opts)
{
	int acked_len;
	int err;

	if (!has_flag_ack(pkt))
		return -ERR_TCP_NO_ACK;

	if (TCP_SEG(pkt)->flags == TCP_FLAG_ACK && TCP_SEG(pkt)->len == 0)
		WORKER_TSOCK_STATS_INC(worker, tsock, PURE_ACK_IN);

	switch (tsock->state) {
	case TCP_STATE_SYN_RCVD:
	case TCP_STATE_ESTABLISHED:
	case TCP_STATE_FIN_WAIT_1:
	case TCP_STATE_FIN_WAIT_2:
	case TCP_STATE_CLOSE_WAIT:
	case TCP_STATE_CLOSING:
	case TCP_STATE_LAST_ACK:
	case TCP_STATE_TIME_WAIT:
		if (seq_lt(TCP_SEG(pkt)->ack, tsock->snd_una)) {
			WORKER_TSOCK_STATS_INC(worker, tsock, ERR_TCP_OLD_ACK);
			return 0;
		}

		if (seq_gt(TCP_SEG(pkt)->ack, tsock->snd_nxt)) {
			tsock_set_ack_flag(tsock, TSOCK_FLAG_ACK_NOW);
			return -ERR_TCP_INVALID_ACK;
		}

		if (tsock->state == TCP_STATE_SYN_RCVD) {
			tsock_established(worker, tsock, pkt);
			accept_tsock_enqueue(worker, tsock);
			return 0;
		}

		if (TCP_SEG(pkt)->ack == tsock->snd_una) {
			/* RFC 5681 on duplicate ack detection */
			if (TCP_SEG(pkt)->len == 0 &&
			    TCP_SEG(pkt)->wnd == (tsock->snd_wnd >> tsock->snd_wscale) &&
			    tsock->snd_nxt != tsock->snd_una) {
				tsock->nr_dupack += 1;
				trace_tcp_dupack(tsock, tsock->nr_dupack);
			}
		} else {
			tsock->nr_dupack = 0;
		}

		debug_assert(seq_ge(TCP_SEG(pkt)->ack, tsock->snd_una));
		acked_len = TCP_SEG(pkt)->ack - tsock->snd_una;

		/* don't count on SYN */
		if (unlikely(tsock->closed_at_syn_rcvd))
			acked_len -= 1;

		if (unlikely((tsock->flags & TSOCK_FLAG_FIN_SENT) != 0 &&
			     TCP_SEG(pkt)->ack == tsock->snd_nxt)) {
			tsock->flags &= ~TSOCK_FLAG_FIN_PENDING;
			acked_len -= 1;

			switch (tsock->state) {
			case TCP_STATE_FIN_WAIT_1:
				tsock_set_state(tsock, TCP_STATE_FIN_WAIT_2);
				break;

			case TCP_STATE_CLOSING:
				tsock_set_state(tsock, TCP_STATE_TIME_WAIT);
				break;

			case TCP_STATE_LAST_ACK:
				tsock->flags |= TSOCK_FLAG_PUT;
				tsock_set_state(tsock, TCP_STATE_CLOSED);
				break;
			}
		}

		if (acked_len > 0) {
			uint32_t rtt;

			err = ack_sent_data(worker, tsock, pkt, acked_len, &rtt);
			if (err)
				return err;

			if (rtt)
				rtt_update(worker, tsock, rtt);

			/* per RFC 6298 page 5, reset back off and timer once new data is acked */
			tsock->zero_wnd_probe_shift = 0;
			tsock->rto_shift = 0;
			tsock_rearm_timer_rto(tsock, worker->ts_us);

			update_cwnd(worker, tsock, acked_len);
		}

		if (opts->nr_sack)
			tcp_rcv_sack(worker, tsock, opts);

		handle_fast_retransmit(worker, tsock, pkt, acked_len);

		if (likely(tsock->retrans_stage == NONE)) {
			if (acked_len > 0)
				tsock->snd_recover = tsock->snd_una - 1;
		} else {
			/*
			 * all bytes before RTO retransmit are acked; finish the RTO
			 */
			if (seq_ge(TCP_SEG(pkt)->ack, tsock->snd_recover)) {
				uint32_t recover_time = worker->ts_us - tsock->rto_start_ts;

				tsock->retrans_stage = NONE;
				tsock_trace_archive(tsock->trace, "rto-%.3fms",
						    (double)recover_time / 1e3);
			} else if (tsock->retrans_stage == RTO) {
				tcp_retrans(worker, tsock);
			}
		}

		if (tsock->snd_una == tsock->snd_nxt)
			timer_stop(&tsock->timer_rto);

		if (seq_lt(tsock->snd_wl1, TCP_SEG(pkt)->seq) ||
		    (TCP_SEG(pkt)->seq == tsock->snd_wl1 &&
		     seq_le(tsock->snd_wl2, TCP_SEG(pkt)->ack))) {
			tsock->snd_wl1 = TCP_SEG(pkt)->seq;
			tsock->snd_wl2 = TCP_SEG(pkt)->ack;
			tsock->snd_wnd = TCP_SEG(pkt)->wnd << tsock->snd_wscale;
		}

		return 0;
	}

	return -ERR_NOT_IMPLEMENTED;
}

static inline void tcp_rcv_ack_fastpath(struct tpa_worker *worker,
					struct tcp_sock *tsock, struct packet *pkt)
{
	int acked_len;

	debug_assert(tsock->state == TCP_STATE_ESTABLISHED);
	debug_assert(seq_ge(TCP_SEG(pkt)->ack, tsock->snd_una) &&
		     seq_le(TCP_SEG(pkt)->ack, tsock->snd_nxt));

	acked_len = TCP_SEG(pkt)->ack - tsock->snd_una;
	if (acked_len > 0) {
		uint32_t rtt;

		ack_sent_data(worker, tsock, pkt, acked_len, &rtt);
		if (rtt)
			rtt_update(worker, tsock, rtt);

		tsock->snd_recover = tsock->snd_una - 1;
		tsock->nr_dupack = 0;

		if (tsock->snd_una == tsock->snd_nxt)
			timer_stop(&tsock->timer_rto);
		else
			tsock_rearm_timer_rto(tsock, worker->ts_us);

		update_cwnd(worker, tsock, acked_len);
	}

	/* the conditions to update snd_wl1/2 must have been met here */
	tsock->snd_wl1 = TCP_SEG(pkt)->seq;
	tsock->snd_wl2 = TCP_SEG(pkt)->ack;
	tsock->snd_wnd = TCP_SEG(pkt)->wnd << tsock->snd_wscale;
}

static inline void update_ts_recent(struct tpa_worker *worker, struct tcp_sock *tsock,
				    struct packet *pkt)
{
	tsock->ts_recent = TCP_SEG(pkt)->ts_val;
	tsock->ts_recent_in_sec = now_in_sec(worker);
}

/*
 * Returns 1 if the pkt is consumed by the fastpath */
static inline int tcp_rcv_fastpath(struct tpa_worker *worker,
				   struct tcp_sock *tsock, struct packet *pkt)
{
	int err;

	/* disable fastpath when seq, ack and flags are not expected */
	if (unlikely(TCP_SEG(pkt)->seq != tsock->rcv_nxt ||
		     seq_lt(TCP_SEG(pkt)->ack, tsock->snd_una) ||
		     seq_gt(TCP_SEG(pkt)->ack, tsock->snd_nxt) ||
		     (TCP_SEG(pkt)->flags & ~TCP_FLAG_PSH) != TCP_FLAG_ACK ||
		     (TCP_SEG(pkt)->len == 0 && TCP_SEG(pkt)->ack == tsock->snd_una) ||
		     tsock->retrans_stage != NONE ||
		     tsock->rcv_wnd == 0))
		return 0;

	/* we also assume ts opt is a must */
	if (unlikely(TCP_SEG(pkt)->opt_len != TCP_OPT_TS_SPACE ||
		     !(pkt->flags & PKT_FLAG_HAS_TS_OPT)))
		return 0;

	/* light PAWS check; ts wrap will be checked in slowpath */
	if (seq_lt(TCP_SEG(pkt)->ts_val, tsock->ts_recent))
		return 0;
	if (seq_le(TCP_SEG(pkt)->seq, tsock->last_ack_sent))
		update_ts_recent(worker, tsock, pkt);

	err = tcp_rcv_data(worker, tsock, pkt);
	if (unlikely(err))
		return err;

	trace_tcp_ts_opt(tsock, TCP_SEG(pkt)->ts_val, TCP_SEG(pkt)->ts_ecr,
			 tsock->ts_recent, tsock->last_ack_sent);
	tcp_rcv_ack_fastpath(worker, tsock, pkt);

	WORKER_TSOCK_STATS_ADD(worker, tsock, BYTE_RECV_FASTPATH, TCP_SEG(pkt)->len);

	return 1;
}

/* returns non-zero on validation failure */
static int validate_seq(struct tpa_worker *worker, struct tcp_sock *tsock,
			struct packet *pkt, struct tcp_opts *opts)
{
	uint32_t seq = TCP_SEG(pkt)->seq;
	uint32_t end = TCP_SEG(pkt)->seq + TCP_SEG(pkt)->len;

	if (TCP_SEG(pkt)->len == 0 && seq == tsock->rcv_nxt)
		return 0;

	if (seq_le(end, tsock->rcv_nxt) || seq_ge(seq, tsock->rcv_nxt + tsock->rcv_wnd))
		return -ERR_TCP_INVALID_SEQ;

	return 0;
}

static int process_incoming_seq(struct tpa_worker *worker, struct tcp_sock *tsock,
				struct packet *pkt, struct tcp_opts *opts)
{
	int err;

	err = validate_seq(worker, tsock, pkt, opts);
	if (err)
		return err;

	if (opts->has_ts) {
		trace_tcp_ts_opt(tsock, TCP_SEG(pkt)->ts_val, TCP_SEG(pkt)->ts_ecr,
				 tsock->ts_recent, tsock->last_ack_sent);

		/*
		 * besides the basic PAWS check we did at fastpath, we do
		 * 2 more check here:
		 * - ts wrap
		 * - RST pkt: per RFC 7323 5.2, RST seg must not be subjected
		 *   to the PAWS check
		 */
		if (seq_lt(opts->ts.val, tsock->ts_recent) &&
		    (now_in_sec(worker) - tsock->ts_recent_in_sec) < TCP_PAWS_IDLE_MAX &&
		    !has_flag_rst(pkt))
			return -ERR_TCP_INVALID_TS;

		if (seq_le(TCP_SEG(pkt)->seq, tsock->last_ack_sent) && !has_flag_rst(pkt))
			update_ts_recent(worker, tsock, pkt);
	}

	return 0;
}

static inline void process_tcp_opt_negotiation(struct tpa_worker *worker, struct tcp_sock *tsock,
					       struct packet *pkt)
{
	struct tcp_opts opts;
	int has_ts;
	int ret;

	ret = parse_tcp_opts(&opts, pkt);
	trace_tcp_ts_opt(tsock, TCP_SEG(pkt)->ts_val, TCP_SEG(pkt)->ts_ecr,
			 tsock->ts_recent, tsock->last_ack_sent);
	if (ret < 0)
		WORKER_TSOCK_STATS_INC(worker, tsock, -ret);

	has_ts = (tsock->ts_enabled && opts.has_ts) ? 1 : 0;
	tsock->snd_mss = calc_snd_mss(tsock, has_ts, 1, opts.mss);
	if (has_ts) {
		tsock->snd_mss -= TCP_OPT_TS_SPACE;
		update_ts_recent(worker, tsock, pkt);
		tsock->ts_ok = 1;
	}

	if (tsock->ws_enabled && opts.has_wscale) {
		tsock->snd_wscale = opts.wscale;
		tsock->rcv_wscale = TCP_WSCALE_DEFAULT;
		tsock->ws_ok = 1;
	} else {
		tsock->snd_wscale = 0;
		tsock->rcv_wscale = 0;
	}

	tsock->sack_ok = tsock->sack_enabled && opts.has_sack_perm;
}

static inline void tsock_established(struct tpa_worker *worker,
				     struct tcp_sock *tsock,
				     struct packet *pkt)
{
	/* XXX: it's not quite right to set snd_una to pkt.ack here */
	trace_tcp_snd_una(tsock, TCP_SEG(pkt)->ack);
	tsock->snd_una = TCP_SEG(pkt)->ack;

	if (tsock->state == TCP_STATE_SYN_SENT)
		tsock->snd_wnd = TCP_SEG(pkt)->wnd;
	else
		tsock->snd_wnd = TCP_SEG(pkt)->wnd << tsock->snd_wscale;

	tsock->snd_wl1 = TCP_SEG(pkt)->seq;
	tsock->snd_wl2 = TCP_SEG(pkt)->ack;
	tsock->snd_cwnd = tcp_cfg.cwnd_init;
	tsock->snd_cwnd_uncommited = 0;
	tsock->snd_cwnd_ts_us = worker->ts_us;
	tsock->snd_ssthresh = RTE_MIN((uint32_t)(1<<20), tsock->snd_wnd * 64);

	rtt_update(worker, tsock, worker->ts_us - tsock->init_ts_us);

	tsock->rto_shift = 0;
	timer_stop(&tsock->timer_rto);
	tsock_rearm_timer_keepalive(tsock, worker->ts_us);

	tsock_set_state(tsock, TCP_STATE_ESTABLISHED);
	tsock_trace_established(tsock);
	rte_smp_wmb();

	tsock_event_add(tsock, TPA_EVENT_OUT);
}

static int syn_sent_to_established(struct tpa_worker *worker,
				   struct tcp_sock *tsock,
				   struct packet *pkt)
{
	tsock->rcv_isn = TCP_SEG(pkt)->seq;
	tsock->rcv_nxt = TCP_SEG(pkt)->seq + 1;

	process_tcp_opt_negotiation(worker, tsock, pkt);
	tsock_established(worker, tsock, pkt);
	tsock_set_ack_flag(tsock, TSOCK_FLAG_ACK_NOW);

	return 0;
}

static __rte_noinline int tcp_rcv_rst(struct tpa_worker *worker,
				      struct tcp_sock *tsock,
				      struct packet *pkt)
{
	int ret = -WARN_RST_RECV;
	int to_close = 0;

	debug_assert(has_flag_rst(pkt));

	if (tsock->state == TCP_STATE_CLOSED)
		return ret;

	switch (tsock->state) {
	case TCP_STATE_SYN_SENT:
		tsock->err = ECONNREFUSED;
		ret = -ERR_CONN_REFUSED;
		break;

	case TCP_STATE_SYN_RCVD:
		if (tsock->passive_connection) {
			/* RFC 793 page 69: from LISTEN state */
			to_close = 1;
		} else {
			/* from SYN-SENT state */
			tsock->err = ECONNREFUSED;
			ret = -ERR_CONN_REFUSED;
		}
		break;

	case TCP_STATE_ESTABLISHED:
	case TCP_STATE_FIN_WAIT_1:
	case TCP_STATE_FIN_WAIT_2:
	case TCP_STATE_CLOSE_WAIT:
		tsock->err = ECONNRESET;
		break;

	case TCP_STATE_CLOSING:
	case TCP_STATE_LAST_ACK:
		tsock->flags |= TSOCK_FLAG_PUT;
		break;

	case TCP_STATE_TIME_WAIT:
		tsock->flags |= TSOCK_FLAG_PUT;
		ret = -WARN_GOT_RST_AT_TIME_WAIT;
		break;
	}

	if (tsock->close_issued || to_close)
		tsock->flags |= TSOCK_FLAG_PUT;
	else
		tsock_event_add(tsock, TPA_EVENT_ERR);

	tsock_set_state(tsock, TCP_STATE_CLOSED);

	return ret;
}

static inline void passive_tsock_init(struct tpa_worker *worker,
				      struct tcp_sock *tsock,
				      struct packet *pkt, void *data)
{
	struct sock_key key;
	tsock->net_hdr_len = init_net_hdr_from_pkt(&tsock->net_hdr, &tsock->local_ip,
						   &tsock->remote_ip, pkt);
	tsock->local_port  = pkt->dst_port;
	tsock->remote_port = pkt->src_port;

	tsock_trace_base_init(tsock);

	sock_key_init(&key, &tsock->remote_ip, ntohs(tsock->remote_port),
		      &tsock->local_ip, ntohs(tsock->local_port));
	sock_table_add(&worker->sock_table, &key, tsock);
	tsock_offload_create(tsock);

	/* refresh worker ts_us */
	worker->ts_us = TSC_TO_US(rte_rdtsc());
	tsock_trace_rcv_pkt(tsock, pkt, worker->ts_us);

	tsock->rcv_isn = TCP_SEG(pkt)->seq;
	tsock->rcv_nxt = TCP_SEG(pkt)->seq + 1;

	tsock->passive_connection = 1;
	tsock->opts.data = data;

	tsock->port_id = pkt->port_id;

	tsock->snd_isn = isn_gen(&tsock->local_ip, &tsock->remote_ip,
				 tsock->local_port, tsock->remote_port);

	process_tcp_opt_negotiation(worker, tsock, pkt);
	tsock_set_state(tsock, TCP_STATE_SYN_RCVD);
}

static inline int tsock_accept(struct tpa_worker *worker, struct tcp_sock *listen_tsock,
			       struct packet *pkt)
{
	struct tcp_sock *tsock;

	debug_assert(tsock_lookup_slowpath(worker, pkt, &tsock) != 0);

	tsock = sock_create(NULL, !!(pkt->flags & PKT_FLAG_IS_IPV6));
	if (!tsock)
		return -ERR_TOO_MANY_SOCKS;

	passive_tsock_init(worker, tsock, pkt, listen_tsock->opts.data);

	return xmit_syn(worker, tsock);
}

/*
 * XXX: we should protect the listen sock well; as in server mode, with the RSS
 * ability, there could be many workers could recv the syn request at the same
 * time.
 */
static inline int tcp_rcv_pkt_at_listen(struct tpa_worker *worker,
					struct tcp_sock *tsock, struct packet *pkt)
{
	int err;

	if (has_flag_rst(pkt))
		return -WARN_RST_RECV;

	if (has_flag_ack(pkt)) {
		err = xmit_rst_for_listen(worker, tsock, pkt);
		if (err)
			WORKER_TSOCK_STATS_INC(worker, tsock, -err);

		return -WARN_ACK_AT_LISTEN;
	}

	if (has_flag_syn(pkt))
		return tsock_accept(worker, tsock, pkt);

	return -WARN_INVLIAD_PKT_AT_LISTEN;
}

static int tcp_rcv_pkt_at_syn_sent(struct tpa_worker *worker, struct tcp_sock *tsock,
				   struct packet *pkt)
{
	if (has_flag_ack(pkt)) {
		if (seq_le(TCP_SEG(pkt)->ack, tsock->snd_isn) || seq_gt(TCP_SEG(pkt)->ack, tsock->snd_nxt)) {
			tsock->flags |= TSOCK_FLAG_RST_NEEDED;
			xmit_flag_packet_with_seq(worker, tsock, TCP_SEG(pkt)->ack);

			/* re-send syn */
			output_tsock_enqueue(worker, tsock);
			return -WARN_HALF_OPEN_DETECTED;
		}
	}

	if (has_flag_rst(pkt)) {
		if (has_flag_ack(pkt)) {
			return tcp_rcv_rst(worker, tsock, pkt);
		}

		return -ERR_RST_WITH_NO_ACK;
	}

	/*
	 * fifth, if neither of the SYN or RST bits is set then drop the
	 * segment and return
	 */
	if (!has_flag_syn(pkt))
		return -ERR_NO_SYN_AND_RST;

	/* XXX: handle simultaneous connect */
	if (!has_flag_ack(pkt))
		return -SIMULTANEOUS_CONNECT;

	if (seq_gt(TCP_SEG(pkt)->ack, tsock->snd_isn))
		return syn_sent_to_established(worker, tsock, pkt);

	return -ERR_INVALID_SYN_SENT_PROCESS;
}


static inline int tcp_rcv_fin(struct tpa_worker *worker, struct tcp_sock *tsock,
			      struct packet *pkt)
{
	if (likely(!has_flag_fin(pkt)))
		return 0;

	tsock->flags |= TSOCK_FLAG_EOF;

	if (tsock->state == TCP_STATE_CLOSED ||
	    tsock->state == TCP_STATE_LISTEN ||
	    tsock->state == TCP_STATE_SYN_SENT)
		return -ERR_INVALID_STATE_FOR_FIN;

	tsock_event_add(tsock, TPA_EVENT_IN);

	switch (tsock->state) {
	case TCP_STATE_SYN_RCVD:
	case TCP_STATE_ESTABLISHED:
		tsock_set_state(tsock, TCP_STATE_CLOSE_WAIT);
		break;

	case TCP_STATE_FIN_WAIT_1:
		tsock_set_state(tsock, TCP_STATE_CLOSING);
		break;

	case TCP_STATE_FIN_WAIT_2:
		tsock_set_state(tsock, TCP_STATE_TIME_WAIT);
		break;

	case TCP_STATE_CLOSE_WAIT:
	case TCP_STATE_CLOSING:
	case TCP_STATE_LAST_ACK:
		/* remain in the old state */
		break;
	}

	tsock_set_ack_flag(tsock, TSOCK_FLAG_ACK_NOW);

	return 0;
}

/*
 * The TCP state processing (RFC 793)
 */
static inline int tcp_rcv_pkt(struct tpa_worker *worker, struct tcp_sock *tsock,
			      struct packet *pkt)
{
	struct tcp_opts opts;
	int err = 0;

	tsock_trace_rcv_pkt(tsock, pkt, worker->ts_us);
	tsock_update_last_ts(tsock, LAST_TS_RCV_PKT);

	if (unlikely(pkt->wid != worker->id && tsock->state != TCP_STATE_LISTEN))
		return -WARN_STALE_PKT_WORKER_MISMATCH;

	if (likely(tsock->state == TCP_STATE_ESTABLISHED &&
		   tcp_rcv_fastpath(worker, tsock, pkt) == 1)) {
		tsock_rearm_timer_keepalive(tsock, worker->ts_us);
		return 0;
	}

	switch (tsock->state) {
	case TCP_STATE_CLOSED:
		err = -PKT_RECV_AFTER_CLOSE;
		goto send_rst;

	case TCP_STATE_SYN_SENT:
		return tcp_rcv_pkt_at_syn_sent(worker, tsock, pkt);

	case TCP_STATE_LISTEN:
		return tcp_rcv_pkt_at_listen(worker, tsock, pkt);
	}

	tsock_rearm_timer_keepalive(tsock, worker->ts_us);

	err = parse_tcp_opts(&opts, pkt);
	if (err < 0)
		WORKER_TSOCK_STATS_INC(worker, tsock, -err);

	/* first, check sequence number */
	err = process_incoming_seq(worker, tsock, pkt, &opts);
	if (err)
		goto send_ack;

	/* second, check the RST bit */
	if (has_flag_rst(pkt))
		return tcp_rcv_rst(worker, tsock, pkt);

	/* third, check security and precedence; outdated */

	/* fourth, check the SYN bit; RFC 5961 section 4, page 8 */
	if (has_flag_syn(pkt)) {
		err = -WARN_INVLIAD_SYN_RCVD;
		goto send_ack;
	}

	/* fifth, check the ACK field */
	err = tcp_rcv_ack(worker, tsock, pkt, &opts);
	if (err)
		return err;
	if (unlikely(tsock->state == TCP_STATE_CLOSED)) {
		/*
		 * let the caller to do the term action, as it
		 * may still have to reference the tsock
		 */
		return 0;
	}

	/* sixth, check the URG bit; skipped */

	/* seventh, process the segment text */
	if (tsock->state == TCP_STATE_ESTABLISHED ||
	    tsock->state == TCP_STATE_FIN_WAIT_1  ||
	    tsock->state == TCP_STATE_FIN_WAIT_2) {
		err = tcp_rcv_data(worker, tsock, pkt);
		if (err)
			return err;
	} else {
		if (TCP_SEG(pkt)->len != 0)
			return -ERR_TCP_RCV_INVALID_STATE;
	}

	/* eighth check the FIN bit */
	return tcp_rcv_fin(worker, tsock, pkt);

send_ack:
	if (!has_flag_rst(pkt)) {
		if (TCP_SEG(pkt)->len != 0 && seq_lt(TCP_SEG(pkt)->seq, tsock->rcv_nxt))
			tsock_reset_quickack(tsock);
		tsock_set_ack_flag(tsock, TSOCK_FLAG_ACK_NOW);
	}

	return err;

send_rst:
	if (!has_flag_rst(pkt)) {
		tsock->flags |= TSOCK_FLAG_RST_NEEDED;
		xmit_flag_packet(worker, tsock);
	}

	return err;
}

static inline void queue_input_tsock(struct tpa_worker *worker,
				     struct tcp_sock *tsock, uint32_t *nr_tsock)
{
	uint32_t i = *nr_tsock;

	if (i > 0 && tsock == worker->tsocks[i-1])
		return;

	worker->tsocks[i] = tsock;
	*nr_tsock += 1;
}

static inline void tcp_rcv_process(struct tpa_worker *worker, struct tcp_sock *tsock,
				   struct packet *pkt)
{
	int err;

	vstats_add(&tsock->rx_merge_size, pkt->nr_read_seg);
	/* here we do count only when merge happened; therefore > 1 here */
	if (pkt->nr_read_seg > 1)
		WORKER_TSOCK_STATS_ADD(worker, tsock, PKT_RECV_MERGE, pkt->nr_read_seg);

	/* done with MERGE stage; switch to READ stage */
	pkt->to_read = pkt;
	err = tcp_rcv_pkt(worker, tsock, pkt);

	/* free pkt carries no data as well (TCP_SEG.len == 0) */
	if (unlikely(err || TCP_SEG(pkt)->len == 0))
		free_err_pkt(worker, tsock, pkt, err);

	if (unlikely(tsock->flags & TSOCK_FLAG_ACK_NOW))
		xmit_flag_packet(worker, tsock);

	tsock->rx_merge_head = NULL;
}

static inline int has_ts_opt_only(struct packet *pkt)
{
	return TCP_SEG(pkt)->opt_len == TCP_OPT_TS_SPACE &&
	       (pkt->flags & PKT_FLAG_HAS_TS_OPT);
}

static inline int tcp_can_merge(struct packet *head, struct packet *pkt)
{
	/* XXX: need simplify this */
	return tcp_cfg.enable_rx_merge && has_ts_opt_only(pkt) &&
	       TCP_SEG(head)->len > 0 && TCP_SEG(pkt)->len > 0 &&
	       (TCP_SEG(pkt)->flags & ~TCP_FLAG_PSH) == TCP_FLAG_ACK &&
	       TCP_SEG(head)->ack == TCP_SEG(pkt)->ack &&
	       (TCP_SEG(head)->seq + TCP_SEG(head)->len == TCP_SEG(pkt)->seq) &&
	       TCP_SEG(head)->ts_raw == TCP_SEG(pkt)->ts_raw &&
	       TCP_SEG(head)->len + pkt->l5_len < TSOCK_MAX_MERGE_SIZE;
}

static inline void tcp_merge(struct tpa_worker *worker, struct tcp_sock *tsock,
			     struct packet *pkt)
{
	struct packet *head;

	head = tsock->rx_merge_head;
	if (head) {
		if (TCP_SEG(head)->seq == tsock->rcv_nxt && tcp_can_merge(head, pkt)) {
			packet_chain(head, pkt);

			/* we have recv-ed few pkts, return ACK timely */
			tsock_set_ack_flag(tsock, TSOCK_FLAG_ACK_NOW);
			return;
		}

		tcp_rcv_process(worker, tsock, head);
	}

	tsock->rx_merge_head = pkt;
}

int tcp_input(struct tpa_worker *worker, struct packet **pkts, int nr_pkt)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	uint32_t nr_tsock = 0;
	uint32_t i;
	int err;

	for (i = 0; i < nr_pkt; i++) {
		pkt = pkts[i];

		err = do_parse_tcp_packet(pkt);
		if (unlikely(err)) {
			free_err_pkt(worker, NULL, pkt, err);
			continue;
		}

		err = tsock_lookup(worker, worker->id, pkt, &tsock);
		if (unlikely(err)) {
			free_err_pkt(worker, NULL, pkt, err);
			continue;
		}
		pkt->tsock = tsock;
		TSOCK_STATS_INC(tsock, PKT_RECV);

		parse_ts_opt_fast(pkt);
		queue_input_tsock(worker, tsock, &nr_tsock);
		if (tsock->state == TCP_STATE_LISTEN)
			tcp_rcv_process(worker, tsock, pkt);
		else
			tcp_merge(worker, tsock, pkt);
	}

	for (i = 0; i < nr_tsock; i++) {
		tsock = worker->tsocks[i];

		if (tsock->rx_merge_head)
			tcp_rcv_process(worker, tsock, tsock->rx_merge_head);

		if (tsock->flags & TSOCK_FLAG_ACK_NEEDED) {
			if (tsock->flags & TSOCK_FLAG_ACK_NOW) {
				xmit_flag_packet(worker, tsock);
			} else {
				flex_fifo_push_if_not_exist(worker->delayed_ack,
							    &tsock->delayed_ack_node);
			}
		}

		if (unlikely(tsock->flags & TSOCK_FLAG_PUT)) {
			tsock->flags &= ~TSOCK_FLAG_PUT;
			tsock_free(tsock);
		}
	}

	return nr_pkt;
}
