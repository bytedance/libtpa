/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>

#include "tpa.h"
#include "tcp.h"
#include "sock.h"
#include "tcp_queue.h"
#include "trace.h"
#include "worker.h"
#include "neigh.h"
#include "tsock_trace.h"

/*
 * The DPDK API rte_ipv4/6_udptcp_cksum do not support calculating
 * checksum when there is a mbuf chain. And this function does
 * support that.
 */
uint16_t calc_udptcp_csum(struct packet *pkt, void *ip)
{
	struct rte_mbuf *m = &pkt->mbuf;
	int version = (*(uint8_t *)ip) >> 4;
	uint16_t mbuf_cusm = 0;
	uint32_t csum;
	uint16_t len;

	if (version == 4) {
		len = ntohs(((struct rte_ipv4_hdr *)ip)->total_length);
		csum = rte_ipv4_phdr_cksum(ip, 0);
	} else {
		len = ntohs(((struct rte_ipv6_hdr *)ip)->payload_len);
		csum = rte_ipv6_phdr_cksum(ip, 0);
	}

	rte_raw_cksum_mbuf(m, sizeof(struct rte_ether_hdr), len, &mbuf_cusm);
	csum = __rte_raw_cksum_reduce(csum + mbuf_cusm);

	return (~csum) & 0xffff;
}

static inline void mbuf_set_offload(struct packet *pkt, struct eth_ip_hdr *net_hdr,
				    struct rte_tcp_hdr *tcp, int is_ipv6,
				    uint16_t tcp_hdr_len, uint16_t payload_len,
				    uint16_t packet_id, uint16_t snd_mss)
{
	struct rte_mbuf *m = &pkt->mbuf;

	m->l2_len = sizeof(struct rte_ether_hdr);
	m->l4_len = tcp_hdr_len;
	m->ol_flags = 0;

	if (m->pkt_len - pkt->hdr_len > snd_mss) {
		m->ol_flags |= PKT_TX_TCP_SEG;
		m->tso_segsz = snd_mss;
	}

	if (!is_ipv6) {
		m->l3_len = sizeof(struct rte_ipv4_hdr);
		m->packet_type = RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_TCP;

		net_hdr->ip4.packet_id = htons(packet_id);
		net_hdr->ip4.total_length = htons(payload_len + sizeof(net_hdr->ip4) + tcp_hdr_len);
		net_hdr->ip4.hdr_checksum = 0;

		if (likely(dev.caps & TX_OFFLOAD_IPV4_CKSUM))
			m->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM;
		else
			net_hdr->ip4.hdr_checksum = rte_ipv4_cksum(&net_hdr->ip4);

		if (likely(dev.caps & TX_OFFLOAD_TCP_CKSUM)) {
			m->ol_flags |= PKT_TX_TCP_CKSUM;

			if (unlikely(!(dev.caps & TX_OFFLOAD_PSEUDO_HDR_CKSUM)))
				tcp->cksum = rte_ipv4_phdr_cksum(&net_hdr->ip4, m->ol_flags);
		} else {
			tcp->cksum = 0;
			tcp->cksum = calc_udptcp_csum(pkt, &net_hdr->ip4);
		}
	} else {
		m->l3_len = sizeof(struct rte_ipv6_hdr);
		m->packet_type = RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_TCP;

		net_hdr->ip6.payload_len = htons(payload_len + tcp_hdr_len);

		if (likely(dev.caps & TX_OFFLOAD_TCP_CKSUM)) {
			m->ol_flags |= PKT_TX_IPV6 | PKT_TX_TCP_CKSUM;

			if (unlikely(!(dev.caps & TX_OFFLOAD_PSEUDO_HDR_CKSUM)))
				tcp->cksum = rte_ipv6_phdr_cksum(&net_hdr->ip6, m->ol_flags);
		} else {
			tcp->cksum = 0;
			tcp->cksum = calc_udptcp_csum(pkt, &net_hdr->ip6);
		}
	}

	pkt->l2_off = pkt->mbuf.data_off;
	pkt->l3_off = pkt->l2_off + m->l2_len;
	pkt->l4_off = pkt->l3_off + m->l3_len;
}

static inline int calc_tcp_opt_len(struct tcp_sock *tsock, uint16_t flags,
				   uint32_t *enabled_opts)
{
	uint32_t opts = 0;
	uint16_t len = 0;

	if (tsock->state == TCP_STATE_SYN_SENT ? tsock->ts_enabled : tsock->ts_ok) {
		len += TCP_OPT_TS_SPACE;
		opts |= TCP_OPT_TS_BIT;
	}

	if (unlikely(flags & TCP_FLAG_SYN)) {
		len  += TCP_OPT_MSS_SPACE;
		opts |= TCP_OPT_MSS_BIT;

		if (tsock->ws_enabled) {
			len  += TCP_OPT_WSCALE_SPACE;
			opts |= TCP_OPT_WSCALE_BIT;
		}

		if (tsock->state == TCP_STATE_SYN_SENT ? tsock->sack_enabled : tsock->sack_ok) {
			len  += TCP_OPT_SACK_PERM_SPACE;
			opts |= TCP_OPT_SACK_PERM_BIT;
		}
	} else {
		if (tsock->nr_sack_block) {
			debug_assert(tsock->sack_ok);
			len  += TCP_OPT_SACK_SPACE(tsock->nr_sack_block);
			opts |= TCP_OPT_SACK_BIT;
		}
	}

	*enabled_opts = opts;
	debug_assert(len % 4 == 0);

	return len;
}

static __rte_noinline void fill_uncommon_opts(const struct tcp_sock *tsock,
					      uint32_t opts, uint8_t *addr)
{
	struct tcp_opt *opt;

	if (opts & TCP_OPT_MSS_BIT) {
		opt = (struct tcp_opt *)addr;
		opt->type = TCP_OPT_MSS_KIND;
		opt->len  = TCP_OPT_MSS_LEN;
		opt->u16[0] = htons(calc_snd_mss(tsock, opts & TCP_OPT_TS_BIT, 0, 0));

		addr += TCP_OPT_MSS_SPACE;
	}

	if (opts & TCP_OPT_WSCALE_BIT) {
		opt = (struct tcp_opt *)addr;
		opt->type  = TCP_OPT_WSCALE_KIND;
		opt->len   = TCP_OPT_WSCALE_LEN;
		opt->u8[0] = TCP_WSCALE_DEFAULT;
		opt->u8[1] = TCP_OPT_NOP_KIND;

		addr += TCP_OPT_WSCALE_SPACE;
	}

	if (opts & TCP_OPT_SACK_PERM_BIT) {
		opt = (struct tcp_opt *)addr;
		opt->type  = TCP_OPT_SACK_PERM_KIND;
		opt->len   = TCP_OPT_SACK_PERM_LEN;
		opt->u8[0] = TCP_OPT_NOP_KIND;
		opt->u8[1] = TCP_OPT_NOP_KIND;

		addr += TCP_OPT_SACK_PERM_SPACE;
	}

	if (opts & TCP_OPT_SACK_BIT) {
		struct tcp_sack_block *blk;
		int i;

		addr[0] = TCP_OPT_NOP_KIND;
		addr[1] = TCP_OPT_NOP_KIND;
		addr += 2;

		opt = (struct tcp_opt *)addr;
		opt->type  = TCP_OPT_SACK_KIND;
		opt->len   = TCP_OPT_SACK_LEN(tsock->nr_sack_block);

		blk = (struct tcp_sack_block *)opt->u8;
		for (i = 0; i < tsock->nr_sack_block; i++) {
			blk->start = htonl(tsock->sack_blocks[i].start);
			blk->end   = htonl(tsock->sack_blocks[i].end);

			blk += 1;
		}

		addr += opt->len;
	}
}

static inline void fill_opts(const struct tcp_sock *tsock, uint32_t opts, uint8_t *addr)
{
	if (likely(opts & TCP_OPT_TS_BIT)) {
		fill_opt_ts(addr, us_to_tcp_ts(tsock->worker->ts_us), 0);
		addr += TCP_OPT_TS_SPACE;
	}

	if (unlikely(opts & ~TCP_OPT_TS_BIT))
		fill_uncommon_opts(tsock, opts, addr);
}

static inline int prepend_tcp_hdr(struct tcp_sock *tsock, struct packet *pkt,
				  uint32_t seq, uint8_t tcp_flags)
{
	struct rte_mbuf *m = &pkt->mbuf;
	uint16_t payload_len = m->pkt_len;
	struct eth_ip_hdr *hdr;
	struct rte_tcp_hdr *tcp;
	uint32_t ack = tsock->rcv_nxt;
	uint16_t tcp_hdr_len;
	uint32_t wnd;
	uint32_t opts;
	uint16_t snd_mss;

	pkt->tsock = tsock;

	tcp_hdr_len = sizeof(*tcp) + calc_tcp_opt_len(tsock, tcp_flags, &opts);
	hdr = (struct eth_ip_hdr *)rte_pktmbuf_prepend(m, tsock->net_hdr_len + tcp_hdr_len);
	if (hdr == NULL)
		return -ERR_PKT_PREPEND_HDR;
	tcp = (struct rte_tcp_hdr *)((char *)hdr + tsock->net_hdr_len);

	fill_opts(tsock, opts, (uint8_t *)(tcp + 1));

	debug_assert(tsock->rcv_wnd < TCP_WINDOW_MAX);
	if (tsock->rcv_wnd >= TCP_WINDOW_MAX)
		tsock->rcv_wnd = 0;

	if (unlikely(tcp_flags & TCP_FLAG_SYN))
		wnd = tsock->rcv_wnd;
	else
		wnd = tsock->rcv_wnd >> tsock->rcv_wscale;
	wnd = RTE_MIN(wnd, UINT16_MAX);

	if (likely(tcp_flags & TCP_FLAG_ACK)) {
		tsock->flags &= ~TSOCK_FLAG_ACK_NOW;
	} else {
		ack = 0;
	}

	*hdr = tsock->net_hdr;
	tcp->src_port = tsock->local_port;
	tcp->dst_port = tsock->remote_port;
	tcp->sent_seq = htonl(seq);
	tcp->recv_ack = htonl(ack);
	tcp->data_off = (tcp_hdr_len >> 2) << 4;
	tcp->tcp_flags = tcp_flags;
	tcp->rx_win = htons(wnd);

	pkt->hdr_len = tsock->net_hdr_len + tcp_hdr_len;
	TCP_SEG(pkt)->seq = seq;
	TCP_SEG(pkt)->len = payload_len;
	TCP_SEG(pkt)->flags = tcp_flags;

	snd_mss = tsock->snd_mss;
	if (opts & TCP_OPT_SACK_BIT)
		snd_mss -= TCP_OPT_SACK_SPACE(tsock->nr_sack_block);

	mbuf_set_offload(pkt, hdr, tcp, tsock->is_ipv6, tcp_hdr_len, payload_len,
			 tsock->packet_id++, snd_mss);

	return 0;
}

static inline void update_tcp_csum_offload(struct packet *pkt, struct eth_ip_hdr *net_hdr,
					   struct rte_tcp_hdr *tcp, int is_ipv6, uint16_t snd_mss)
{
	struct rte_mbuf *m = &pkt->mbuf;

	if (m->pkt_len - pkt->hdr_len <= snd_mss) {
		m->ol_flags &= ~PKT_TX_TCP_SEG;
		m->tso_segsz = 0;
		return;
	}

	m->ol_flags |= PKT_TX_TCP_SEG;
	m->tso_segsz = snd_mss;

	if (!is_ipv6)
		tcp->cksum = rte_ipv4_phdr_cksum(&net_hdr->ip4, m->ol_flags);
	else
		tcp->cksum = rte_ipv6_phdr_cksum(&net_hdr->ip6, m->ol_flags);
}

int xmit_flag_packet_with_seq(struct tpa_worker *worker, struct tcp_sock *tsock, uint32_t seq)
{
	struct packet *pkt;
	uint8_t tcp_flags;
	int err;

	/*
	 * Below may happen when we get a packet before SYN is sent.
	 * We simply return here. This should be rare that we don't
	 * bother to introduce a counter for it.
	 *
	 * XXX: we probably should setup the hdr as soon as possible
	 * to avoid such hack?
	 */
	if (tsock->net_hdr_len == 0) {
		tsock->flags &= ~TSOCK_FLAG_TCP_FLAGS_MASK;
		return -1;
	}

	pkt = packet_alloc(&worker->hdr_pkt_pool);
	if (!pkt) {
		err = -ERR_PKT_ALLOC_FAIL;
		goto err;
	}

	tcp_flags = tsock_flags_to_tcp_flags(tsock->flags);
	err = prepend_tcp_hdr(tsock, pkt, seq, tcp_flags);
	if (err == 0) {
		if (tsock->flags & TSOCK_FLAG_MISSING_ARP) {
			tsock->flags &= ~TSOCK_FLAG_MISSING_ARP;
			err = neigh_wait_enqueue(pkt);
		} else {
			err = dev_port_txq_enqueue(tsock->port_id, worker->queue, pkt);
		}

		if (unlikely(err))
			goto err;
	}

	if (tcp_flags & TCP_FLAG_ACK) {
		tsock->last_ack_sent = tsock->rcv_nxt;
		tsock->last_ack_sent_ts = worker->ts_us;
		tsock->flags &= ~(TSOCK_FLAG_ACK_NEEDED | TSOCK_FLAG_ACK_NOW);
		WORKER_TSOCK_STATS_INC(worker, tsock, PURE_ACK_OUT);
	}

	if (tcp_flags & TCP_FLAG_SYN) {
		tsock->flags &= ~TSOCK_FLAG_SYN_NEEDED;
		WORKER_TSOCK_STATS_INC(worker, tsock, SYN_XMIT);
	}

	if (tcp_flags & TCP_FLAG_FIN) {
		tsock->flags &= ~TSOCK_FLAG_FIN_NEEDED;
		WORKER_TSOCK_STATS_INC(worker, tsock, FIN_XMIT);
	}

	if (tcp_flags & TCP_FLAG_RST) {
		tsock->flags &= ~TSOCK_FLAG_RST_NEEDED;
		WORKER_TSOCK_STATS_INC(worker, tsock, RST_XMIT);
	}

	tsock_update_last_ts(tsock, LAST_TS_SND_PKT);
	tsock_trace_xmit_pkt(tsock, pkt, 0);

	return 0;

err:
	WORKER_TSOCK_STATS_INC(worker, tsock, -err);
	if (pkt) {
		tsock_trace_xmit_pkt(tsock, pkt, -err);
		packet_free(pkt);
	}

	return err;
}

int xmit_flag_packet(struct tpa_worker *worker, struct tcp_sock *tsock)
{
	uint8_t tcp_flags;
	uint32_t seq = tsock->snd_nxt;

	tcp_flags = tsock_flags_to_tcp_flags(tsock->flags);
	if (tcp_flags & TCP_FLAG_SYN)
		seq = tsock->snd_isn;
	else if (tcp_flags & TCP_FLAG_FIN)
		seq = tsock->data_seq_nxt;

	return xmit_flag_packet_with_seq(worker, tsock, seq);
}

/*
 * The @tsock speicified here is a listen tsock, where the 5 tuples is
 * not complete (or, typically, it may only have local port speicified).
 * Therefore, we can't use the generic function xmit_flag_packet to
 * construct a *reply* pkt. Instead, we should construct it from the
 * incoming pkt.
 */
int xmit_rst_for_listen(struct tpa_worker *worker, struct tcp_sock *tsock, struct packet *pkt)
{
	struct eth_ip_hdr *net_hdr;
	struct rte_tcp_hdr *tcp;
	struct tpa_ip local_ip;
	struct tpa_ip remote_ip;
	struct packet *reply_pkt;
	int pkt_len;
	int ret;

	debug_assert(tsock->state == TCP_STATE_LISTEN);

	reply_pkt = packet_alloc(&worker->hdr_pkt_pool);
	if (!reply_pkt)
		return -ERR_PKT_ALLOC_FAIL;

	pkt_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_tcp_hdr);
	if (pkt->flags & PKT_FLAG_IS_IPV6)
		pkt_len += sizeof(struct rte_ipv6_hdr);
	else
		pkt_len += sizeof(struct rte_ipv4_hdr);

	net_hdr = (struct eth_ip_hdr *)rte_pktmbuf_prepend(&reply_pkt->mbuf, pkt_len);
	if (net_hdr == NULL) {
		ret = -ERR_PKT_PREPEND_HDR;
		goto err;
	}

	init_net_hdr_from_pkt(net_hdr, &local_ip, &remote_ip, pkt);
	tcp = (struct rte_tcp_hdr *)((char *)net_hdr + pkt_len - sizeof(struct rte_tcp_hdr));

	memset(tcp, 0, sizeof(*tcp));
	tcp->src_port = pkt->dst_port;
	tcp->dst_port = pkt->src_port;
	tcp->sent_seq = htonl(TCP_SEG(pkt)->ack);
	tcp->tcp_flags = TCP_FLAG_RST;
	tcp->data_off = (sizeof(struct rte_tcp_hdr) >> 2) << 4;

	reply_pkt->hdr_len = pkt_len;
	reply_pkt->tsock = tsock;
	TCP_SEG(reply_pkt)->flags = TCP_FLAG_RST;
	TCP_SEG(reply_pkt)->len = 0;

	mbuf_set_offload(reply_pkt, net_hdr, tcp, pkt->flags & PKT_FLAG_IS_IPV6,
			 sizeof(struct rte_tcp_hdr), 0, tsock->packet_id++, 0);

	ret = dev_port_txq_enqueue(tsock->port_id, worker->queue, reply_pkt);
	if (ret)
		goto err;

	tsock_update_last_ts(tsock, LAST_TS_SND_PKT);
	tsock_trace_xmit_pkt(tsock, reply_pkt, 0);

	return 0;

err:
	tsock_trace_xmit_pkt(tsock, reply_pkt, ret);
	packet_free(reply_pkt);
	return ret;
}

void flush_tcp_packet(struct packet *pkt, int err)
{
	struct tcp_sock *tsock = pkt->tsock;
	struct tpa_worker *worker;

	debug_assert(tsock != NULL);

	worker = tsock->worker;

	if (tsock_flags_to_tcp_flags(tsock->flags) & TCP_FLAG_SYN) {
		tsock->flags &= ~TSOCK_FLAG_SYN_NEEDED;
		WORKER_TSOCK_STATS_INC(worker, tsock, SYN_XMIT);
	}

	tsock_update_last_ts(tsock, LAST_TS_SND_PKT);
	tsock_trace_xmit_pkt(pkt->tsock, pkt, err);
}

uint32_t isn_gen(struct tpa_ip *local_ip, struct tpa_ip *remote_ip,
		 uint16_t local_port, uint16_t remote_port)
{
	uint32_t seq;

	/* we ignore local ip here as it does not change */
	seq = rte_crc32_u64(remote_ip->u64[0] | (uint64_t)local_port,
			    remote_ip->u64[1] | (uint64_t)remote_port);

	return seq + (rte_rdtsc() >> 10);
}

int tcp_connect(struct tcp_sock *tsock)
{
	if (tsock == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (tsock->state != TCP_STATE_CLOSED) {
		errno = EADDRINUSE;
		return -1;
	}
	tsock->state = TCP_STATE_SYN_SENT;

	tsock->snd_isn = isn_gen(&tsock->local_ip, &tsock->remote_ip,
				 tsock->local_port, tsock->remote_port);

	output_tsock_enqueue(tsock->worker, tsock);

	return 0;
}


/* be a bit conservative here */
#define MAX_HDR_LEN		100

static inline uint32_t tsock_snd_mss(struct tcp_sock *tsock)
{
	return tsock->tso_enabled ? (UINT16_MAX - MAX_HDR_LEN): tsock->snd_mss;
}

static void __rte_noinline tcp_zero_wnd_probe(struct tpa_worker *worker, struct tcp_sock *tsock)
{
	if (worker->ts_us - last_ts_in_us(tsock, LAST_TS_SND_PKT) < (tsock->rto << tsock->zero_wnd_probe_shift))
		return;

	tsock->flags |= TSOCK_FLAG_ACK_NEEDED;
	xmit_flag_packet_with_seq(worker, tsock, tsock->snd_una - 1);

	tsock->zero_wnd_probe_shift  = RTE_MIN(tsock->zero_wnd_probe_shift + 1, tcp_cfg.retries);
	WORKER_TSOCK_STATS_INC(worker, tsock, ZERO_WND_PROBE);
}

struct xmit_ctx {
	uint32_t seq;
	uint32_t seq_max;
	int      budget;
	uint16_t desc_off;
	uint16_t desc_base;
	uint64_t now;
};

/*
 * construct one packet with size no longer than the effective mss
 * from the txq and then xmit it.
 */
static inline int xmit_one_packet(struct tpa_worker *worker, struct tcp_sock *tsock,
				  struct xmit_ctx *ctx)
{
	struct packet *hdr_pkt;
	struct packet *pkt;
	struct packet *tail;
	struct tx_desc *desc;
	int budget;
	uint32_t size = 0;
	uint32_t off;
	int err = 0;
	int len;

	while (1) {
		desc = tcp_txq_peek_for_write(&tsock->txq, ctx->desc_base, ctx->desc_off);
		if (!desc)
			return 0;

		if (likely(desc->flags & TX_DESC_FLAG_SACKED) == 0)
			break;

		ctx->desc_off += 1;
		ctx->seq = desc->seq + desc->len;
	}

	hdr_pkt = packet_alloc(&worker->hdr_pkt_pool);
	if (!hdr_pkt)
		return -ERR_PKT_ALLOC_FAIL;

	tail = hdr_pkt;
	budget = RTE_MIN(ctx->budget, tsock_snd_mss(tsock));

	while (budget > 0) {
		if (unlikely(seq_lt(ctx->seq, tsock->snd_nxt))) {
			desc->flags |= TX_DESC_FLAG_RETRANS;
			hdr_pkt->flags |= PKT_FLAG_RETRANSMIT;
		}
		if (unlikely(desc->flags & TX_DESC_FLAG_SACKED))
			break;

		/* TODO: bulk allocate */
		pkt = packet_alloc(&worker->zwrite_pkt_pool);
		if (!pkt) {
			err = -ERR_PKT_ALLOC_FAIL;
			break;
		}

		off = ctx->seq - desc->seq;
		len = RTE_MIN(desc->len - off, budget);

		/* make sure we do not go beyond snd_nxt for retrans */
		if (seq_gt((ctx->seq + len), ctx->seq_max)) {
			len = ctx->seq_max - ctx->seq;
			budget = len;
		}

		trace_tcp_xmit_data(tsock, ctx->seq, budget, off, len, desc->flags);
		debug_assert(off < desc->len);

		packet_attach_extbuf(pkt, desc->addr + off, desc->phys_addr + off, len);
		TCP_SEG(pkt)->seq = ctx->seq;
		TCP_SEG(pkt)->len = len;

		budget -= len;
		ctx->seq += len;
		size += len;
		if (off + len == desc->len) {
			desc->ts_us = worker->ts_us;
			if (likely(!(desc->flags & TX_DESC_FLAG_RETRANS))) {
				if (unlikely(desc->flags & TX_DESC_FLAG_MEASURE_LATENCY)) {
					if (!ctx->now)
						ctx->now = rte_rdtsc();

					desc->tsc_xmit = ctx->now;
				}
			}

			ctx->desc_off += 1;
			desc = tcp_txq_peek_for_write(&tsock->txq, ctx->desc_base, ctx->desc_off);
		}

		tail->mbuf.next = &pkt->mbuf;
		tail = pkt;
		hdr_pkt->mbuf.nb_segs += 1;
		hdr_pkt->mbuf.pkt_len += len;

		if (hdr_pkt->mbuf.nb_segs >= tcp_cfg.pkt_max_chain)
			break;

		if (unlikely(!desc))
			break;
	}

	if (unlikely(size == 0))
		goto error;

	err = prepend_tcp_hdr(tsock, hdr_pkt, ctx->seq - size, TCP_FLAG_ACK);
	if (unlikely(err))
		goto error;

	err = dev_port_txq_enqueue(tsock->port_id, worker->queue, hdr_pkt);
	if (unlikely(err))
		goto error;

	ctx->budget -= size;
	tsock->flags &= ~TSOCK_FLAG_TCP_FLAGS_MASK;
	tsock_trace_xmit_pkt(tsock, hdr_pkt, 0);

	return size;

error:
	tsock_trace_xmit_pkt(tsock, hdr_pkt, err);
	packet_free(hdr_pkt);
	return err;
}

static inline int do_tcp_xmit_data(struct tpa_worker *worker, struct tcp_sock *tsock,
				   struct xmit_ctx *ctx)
{
	uint32_t nr_to_xmit;
	int size = 0;
	int ret;
	int i;

	nr_to_xmit = RTE_MIN(dev_port_txq_free_count(tsock->port_id, worker->queue), BATCH_SIZE);
	for (i = 0; i < nr_to_xmit && ctx->budget > 0; i++) {
		ret = xmit_one_packet(worker, tsock, ctx);
		if (unlikely(ret <= 0)) {
			if (ret < 0)
				WORKER_TSOCK_STATS_INC(worker, tsock, -ret);
			break;
		}

		size += ret;
	}

	if (likely(size > 0)) {
		/*
		 * Per RFC 6298 5.1: only rearm rto timer if it's not running
		 */
		if (timer_is_stopped(&tsock->timer_rto))
			tsock_rearm_timer_rto(tsock, worker->ts_us);

		tsock->last_ack_sent = tsock->rcv_nxt;
		tsock->last_ack_sent_ts = worker->ts_us;
		tsock->snd_ts = us_to_tcp_ts(worker->ts_us);
		tsock_update_last_ts(tsock, LAST_TS_SND_DATA);
		tsock_update_last_ts(tsock, LAST_TS_SND_PKT);
	}

	return size;
}

/*
 * Try to xmit the data queued in the tcp txq.
 */
static uint32_t tcp_xmit_data(struct tpa_worker *worker, struct tcp_sock *tsock)
{
	struct xmit_ctx ctx;
	uint32_t wnd;

	wnd = RTE_MIN(tsock->snd_wnd, tsock->snd_cwnd);
	if (unlikely(wnd == 0)) {
		tcp_zero_wnd_probe(worker, tsock);
		return 0;
	}

	ctx.seq = tsock->snd_nxt;
	ctx.seq_max = tsock->data_seq_nxt;
	ctx.budget = wnd - (ctx.seq - tsock->snd_una);
	ctx.desc_base = tsock->txq.nxt;
	ctx.desc_off = 0;
	ctx.now = 0;

	do_tcp_xmit_data(worker, tsock, &ctx);
	if (ctx.seq == tsock->snd_nxt)
		return 0;

	tsock->snd_nxt = ctx.seq;
	tcp_txq_update_nxt(&tsock->txq, ctx.desc_off);
	trace_tcp_update_txq(tsock, tcp_txq_inflight_pkts(&tsock->txq), tcp_txq_to_send_pkts(&tsock->txq));

	return 0;
}

static int do_tcp_retrans(struct tpa_worker *worker, struct tcp_sock *tsock, int budget)
{
	struct xmit_ctx ctx;
	int size;

	ctx.seq = tsock->retrans.seq;
	ctx.seq_max = tsock->snd_nxt;
	ctx.budget = budget;
	ctx.desc_base = tsock->retrans.desc_base;
	ctx.desc_off = 0;
	ctx.now = 0;

	size = do_tcp_xmit_data(worker, tsock, &ctx);
	tsock->retrans.seq = ctx.seq;
	tsock->retrans.desc_base = ctx.desc_base + ctx.desc_off;

	WORKER_TSOCK_STATS_ADD(tsock->worker, tsock, BYTE_RE_XMIT, size);

	return size;
}

void tcp_retrans(struct tpa_worker *worker, struct tcp_sock *tsock)
{
	uint32_t budget;
	uint32_t wnd;

	/* regulate retrans pointers */
	if (seq_lt(tsock->retrans.seq, tsock->snd_una))
		tcp_reset_retrans(tsock, tsock->snd_una, tsock->txq.una);

	wnd = RTE_MIN(tsock->snd_wnd, tsock->snd_cwnd);
	budget = wnd - (tsock->retrans.seq - tsock->snd_una);

	do_tcp_retrans(worker, tsock, budget);
}

void tcp_fast_retrans(struct tpa_worker *worker, struct tcp_sock *tsock, int budget)
{
	int size;

	/* regulate retrans pointers */
	if (seq_lt(tsock->retrans.seq, tsock->snd_una))
		tcp_reset_retrans(tsock, tsock->snd_una, tsock->txq.una);

	budget = budget - (tsock->retrans.seq - tsock->snd_una);
	if (budget < tsock->snd_mss)
		budget = tsock->snd_mss;

	size = do_tcp_retrans(worker, tsock, budget);
	if (size == 0)
		WORKER_TSOCK_STATS_INC(tsock->worker, tsock, PKT_FAST_RE_XMIT_ERR);
	else
		WORKER_TSOCK_STATS_ADD(tsock->worker, tsock, BYTE_FAST_RE_XMIT, size);
}

/*
 * Assume an user just triggers a write for a socket the first time and
 * it fails (say, due to running out of mbufs). The app then watches the
 * OUT event, with the hope it will be waken up later to continue the
 * write. Since it's the first write, no one would do the wake up then.
 * Therefore, the socket may get forgotten, if no more active write
 * request made.
 *
 * Here is a quick fix to re-file the OUT event at write when:
 * - EAGAIN is returned, AND
 * - the send queue is empty
 *
 * The caller of this function should make sure it satisfies condition
 * 1. Therefore, here we only need check condition 2.
 *
 * XXX: a better fix might be put it to a list and then file the OUT
 * event when some mbufs are available. Well, we don't really know that,
 * as some mbuf are freed by NIC.
 */
static inline void refire_out_event_if_needed(struct tcp_sock *tsock)
{
	if (unlikely(tcp_txq_unfinished_pkts(&tsock->txq) == 0))
		tsock_event_add(tsock, TPA_EVENT_OUT);
}

struct write_ctx {
	int nr_desc_free;
	int nr_desc;
	uint32_t size;

	int nr_fallback;
	uint64_t start_tsc;
};

static inline void write_commit(struct tcp_sock *tsock, struct write_ctx *ctx)
{
	struct tcp_txq *txq = &tsock->txq;

	txq->write += ctx->nr_desc;
	debug_assert((uint16_t)(txq->write - txq->una) <= txq->size);

	vstats_add(&tsock->write_size, ctx->size);

	WORKER_TSOCK_STATS_ADD(tsock->worker, tsock, BYTE_XMIT, ctx->size);
	WORKER_TSOCK_STATS_ADD(tsock->worker, tsock, PKT_XMIT,  ctx->nr_desc);

	tsock->data_seq_nxt += ctx->size;
	output_tsock_enqueue(tsock->worker, tsock);
}

static void write_revoke(struct tcp_sock *tsock, struct write_ctx *ctx)
{
	struct tcp_txq *txq = &tsock->txq;
	struct tx_desc *desc;
	int i;

	for (i = 0; i < ctx->nr_desc; i++) {
		desc = txq->descs[(txq->write + i) & txq->mask];
		if (desc->flags & TX_DESC_FLAG_MEM_FROM_MBUF)
			packet_free(desc->pkt);

		tx_desc_free(tsock->worker->tx_desc_pool, desc);
	}
}

static int write_one_iov(struct tcp_sock *tsock, const struct tpa_iovec *iov,
			 struct write_ctx *ctx)
{
	struct tx_desc_pool *pool = tsock->worker->tx_desc_pool;
	struct tcp_txq *txq = &tsock->txq;
	struct tx_desc *desc = NULL;
	uint32_t off = 0;
	struct packet *pkt;
	void *addr;
	uint64_t phys_addr;
	uint32_t flags;
	uint32_t len;

	if (iov->iov_len == 0)
		return 0;

	do {
		if (unlikely(ctx->nr_desc + 1 > ctx->nr_desc_free))
			return -1;

		desc = tx_desc_alloc(pool);
		if (!desc)
			return -1;

		len = RTE_MIN(iov->iov_len - off, tcp_cfg.write_chunk_size);
		if (likely(iov->iov_phys != 0)) {
			addr      = iov->iov_base + off;
			phys_addr = iov->iov_phys + off;
			flags = 0;
		} else {
			if (unlikely(too_many_used_mbufs(tsock->worker))) {
				tx_desc_free(pool, desc);
				return -1;
			}

			/*
			 * No phys_addr provided; fallback to
			 * none zero copy version.
			 */
			pkt = packet_alloc(generic_pkt_pool);
			if (!pkt) {
				tx_desc_free(pool, desc);
				return -1;
			}

			addr      = rte_pktmbuf_mtod(&pkt->mbuf, char *);
			phys_addr = rte_pktmbuf_iova(&pkt->mbuf);
			flags = TX_DESC_FLAG_MEM_FROM_MBUF;

			len = RTE_MIN(len, rte_pktmbuf_tailroom(&pkt->mbuf));
			memcpy(addr, (const char *)iov->iov_base + off, len);
			pkt->mbuf.data_len = len;
			pkt->mbuf.pkt_len = len;

			desc->pkt = pkt;
			ctx->nr_fallback += 1;
		}

		desc->addr       = addr;
		desc->phys_addr  = phys_addr;
		desc->len        = len;
		desc->write_done = NULL;
		desc->base       = NULL;
		desc->param      = NULL;
		desc->flags      = flags;
		desc->seq        = tsock->data_seq_nxt + ctx->size;

		off += len;
		ctx->size += len;
		txq->descs[(txq->write + ctx->nr_desc) & txq->mask] = desc;
		ctx->nr_desc += 1;
	} while (off < iov->iov_len);

	/* we can only free it when last seg is acked */
	desc->write_done = iov->iov_write_done;
	desc->base  = iov->iov_base;
	desc->param = iov->iov_param;

	if (unlikely(iov->iov_phys == 0)) {
		WORKER_TSOCK_STATS_INC(tsock->worker, tsock, ZWRITE_FALLBACK_PKTS);
		WORKER_TSOCK_STATS_ADD(tsock->worker, tsock, ZWRITE_FALLBACK_BYTES, iov->iov_len);
	}

	return 0;
}

static inline void init_write_lat_tsc(struct tcp_sock *tsock, struct write_ctx *ctx)
{
	struct tcp_txq *txq;
	struct tx_desc *desc;

	if (unlikely(tcp_cfg.measure_latency)) {
		txq = &tsock->txq;
		desc = txq->descs[(txq->write + ctx->nr_desc - 1) & txq->mask];

		desc->tsc_start  = ctx->start_tsc;
		desc->tsc_submit = rte_rdtsc();
		desc->flags |= TX_DESC_FLAG_MEASURE_LATENCY;
	}
}

static __rte_noinline ssize_t tsock_zwritev_slowpath(struct tcp_sock *tsock,
						     const struct tpa_iovec *iov,
						     int nr_iov, struct write_ctx *ctx)
{
	int i;

	ctx->nr_fallback = 0;
	for (i = ctx->nr_desc; i < nr_iov; i++) {
		if (write_one_iov(tsock, &iov[i], ctx) < 0)
			return -1;
	}

	if (unlikely(trace_cfg.more_trace))
		tsock_trace_zwritev(tsock, nr_iov, nr_iov, ctx->size, ctx->nr_fallback);

	tsock->worker->nr_write_mbuf += ctx->nr_fallback;

	init_write_lat_tsc(tsock, ctx);
	write_commit(tsock, ctx);

	return ctx->size;
}

/* Note that this macro has return statement */
#define TSOCK_WRITE_CHECK(tsock)		do {			\
	if (unlikely(tsock->close_issued)) {				\
		errno = EBADF;						\
		return -1;						\
	}								\
									\
	if (unlikely(tsock->err != 0)) {				\
		errno = tsock->err;					\
		return -1;						\
	}								\
									\
	if (unlikely(tsock->state != TCP_STATE_ESTABLISHED)) {		\
		switch (tsock->state) {					\
		case TCP_STATE_CLOSE_WAIT:				\
			break;						\
		case TCP_STATE_SYN_SENT:				\
		case TCP_STATE_SYN_RCVD:				\
			errno = ENOTCONN;				\
			return -1;					\
		default:						\
			errno = EPIPE;					\
			return -1;					\
		}							\
	}								\
} while (0)

ssize_t tsock_zwritev(struct tcp_sock *tsock, const struct tpa_iovec *iov, int nr_iov)
{
	struct tcp_txq *txq = &tsock->txq;
	struct write_ctx ctx;
	struct tx_desc *desc;
	int i;

	if (unlikely(tcp_cfg.measure_latency))
		ctx.start_tsc = rte_rdtsc();

	TSOCK_WRITE_CHECK(tsock);

	ctx.nr_desc_free = tcp_txq_free_count(&tsock->txq);
	ctx.nr_desc = 0;
	ctx.size = 0;

	for (i = 0; i < nr_iov; i++) {
		if (unlikely(iov[i].iov_phys == 0 || iov[i].iov_len == 0 || iov[i].iov_len > tcp_cfg.write_chunk_size))
			goto slowpath;

		if (unlikely(ctx.nr_desc + 1 > ctx.nr_desc_free))
			goto fail;

		desc = tx_desc_alloc(tsock->worker->tx_desc_pool);
		if (unlikely(!desc))
			goto fail;

		desc->addr       = iov[i].iov_base;
		desc->phys_addr  = iov[i].iov_phys;
		desc->len        = iov[i].iov_len;
		desc->write_done = iov[i].iov_write_done;
		desc->base       = iov[i].iov_base;
		desc->param      = iov[i].iov_param;
		desc->flags      = 0;
		desc->seq        = tsock->data_seq_nxt + ctx.size;

		txq->descs[(txq->write + ctx.nr_desc) & txq->mask] = desc;
		ctx.nr_desc += 1;

		ctx.size += iov[i].iov_len;
	}
	debug_assert(ctx.nr_desc == nr_iov);

	if (unlikely(trace_cfg.more_trace))
		tsock_trace_zwritev(tsock, nr_iov, nr_iov, ctx.size, 0);

	init_write_lat_tsc(tsock, &ctx);
	write_commit(tsock, &ctx);

	return ctx.size;

slowpath:
	if (tsock_zwritev_slowpath(tsock, iov, nr_iov, &ctx) >= 0)
		return ctx.size;
fail:
	write_revoke(tsock, &ctx);
	refire_out_event_if_needed(tsock);
	errno = EAGAIN;

	return -1;
}

int tsock_write(struct tcp_sock *tsock, const void *buf, size_t size)
{
	struct tpa_iovec iov;

	iov.iov_base = (void *)(uintptr_t)buf;
	iov.iov_len = size;
	iov.iov_phys = 0;
	iov.iov_write_done = NULL;
	iov.iov_param = NULL;

	return tsock_zwritev(tsock, &iov, 1);
}

static inline void tsock_init_net_hdr(struct tpa_worker *worker, struct tcp_sock *tsock)
{
	struct rte_ether_hdr eth;

	if (eth_lookup(worker, &tsock->remote_ip, &eth) < 0)
		tsock->flags |= TSOCK_FLAG_MISSING_ARP;

	tsock->net_hdr_len = init_net_hdr(&tsock->net_hdr, &eth, &tsock->local_ip, &tsock->remote_ip);
}

uint16_t calc_snd_mss(const struct tcp_sock *tsock, int has_ts, int passive, uint16_t nego_mss)
{
	int ip_hdr_len;
	int snd_mss;

	if (tcp_cfg.usr_snd_mss > 0) {
		snd_mss = tcp_cfg.usr_snd_mss + (has_ts ? TCP_OPT_TS_SPACE : 0);
	} else {
		ip_hdr_len = tsock->is_ipv6 ? sizeof(struct rte_ipv6_hdr) : sizeof(struct rte_ipv4_hdr);
		snd_mss = DEFAULT_MTU - ip_hdr_len - sizeof(struct rte_tcp_hdr);
		if (snd_mss < 0)
			snd_mss = TCP_MSS_DEFAULT;
	}

	if (passive == 0)
		return snd_mss;

	return RTE_MIN(snd_mss, nego_mss ? nego_mss : TCP_MSS_DEFAULT);
}

int xmit_syn(struct tpa_worker *worker, struct tcp_sock *tsock)
{
	uint32_t seq;
	int ret;

	seq = tsock->snd_isn;
	tsock->snd_recover = seq;
	tsock->snd_una = seq;
	tsock->snd_nxt = seq + 1;
	tsock->snd_ts = us_to_tcp_ts(worker->ts_us);
	tsock->init_ts_us = worker->ts_us;
	tsock->rto = TCP_RTO_DEFAULT;
	tsock->data_seq_nxt = tsock->snd_nxt;

	tsock_init_net_hdr(worker, tsock);

	tsock->flags |= TSOCK_FLAG_SYN_NEEDED;
	if (tsock->state == TCP_STATE_SYN_RCVD)
		tsock->flags |= TSOCK_FLAG_ACK_NEEDED;

	tsock_trace_xmit_syn(tsock);
	ret = xmit_flag_packet(worker, tsock);
	/*
	 * If we failed to xmit syn (due to dev txq is full),
	 * retry the syn xmit soon instead of waitting for the RTO
	 * timeout.
	 */
	if (ret == -ERR_DEV_TXQ_FULL)
		output_tsock_enqueue(worker, tsock);

	if (tsock->rto_shift == 0)
		timer_start(&tsock->timer_rto, worker->ts_us, tsock->rto);

	return 0;
}

void tsock_set_state(struct tcp_sock *tsock, int state)
{
	tsock->state = state;
	trace_tcp_set_state(tsock, state, tcp_rxq_readable_count(&tsock->rxq));

	if (state == TCP_STATE_TIME_WAIT || state == TCP_STATE_FIN_WAIT_2)
		timer_start(&tsock->timer_wait, tsock->worker->ts_us, tcp_cfg.time_wait);
}

static __rte_noinline int tcp_close(struct tpa_worker *worker, struct tcp_sock *tsock)
{
	if (tsock->flags & TSOCK_FLAG_CLOSE_PROCESSED)
		return tsock->state;
	tsock->flags |= TSOCK_FLAG_CLOSE_PROCESSED;

	if (tcp_rxq_readable_count(&tsock->rxq)) {
		tsock_set_state(tsock, TCP_STATE_CLOSED);
		tsock->flags |= TSOCK_FLAG_RST_NEEDED | TSOCK_FLAG_ACK_NEEDED;
		xmit_flag_packet(worker, tsock);
		goto out;
	}

	switch (tsock->state) {
	case TCP_STATE_LISTEN:
	case TCP_STATE_SYN_SENT:
		tsock_set_state(tsock, TCP_STATE_CLOSED);
		break;

	case TCP_STATE_SYN_RCVD:
		tsock->closed_at_syn_rcvd = 1;
		/* fallthrough */

	case TCP_STATE_ESTABLISHED:
		tsock->flags |= TSOCK_FLAG_FIN_PENDING;
		tsock_set_state(tsock, TCP_STATE_FIN_WAIT_1);
		break;

	case TCP_STATE_CLOSE_WAIT:
		tsock->flags |= TSOCK_FLAG_FIN_PENDING;
		tsock_set_state(tsock, TCP_STATE_LAST_ACK);
		break;
	}

out:
	if (tsock->state == TCP_STATE_CLOSED) {
		tsock_free(tsock);
		return TCP_STATE_CLOSED;
	}

	return tsock->state;
}

static inline int tcp_output_one(struct tpa_worker *worker, struct tcp_sock *tsock)
{
	int state;
	int ret;

	/* XXX: count it */
	if (unlikely(tsock->sid < 0))
		return 0;

	state = tsock->state;
	if (unlikely(tsock->close_issued))
		state = tcp_close(worker, tsock);

	switch (state) {
	case TCP_STATE_CLOSED:
		return 0;

	case TCP_STATE_SYN_SENT:
	case TCP_STATE_SYN_RCVD:
		return xmit_syn(worker, tsock);

	default:
		ret = tcp_xmit_data(worker, tsock);
		if (ret)
			return ret;
		break;
	}

	if (tcp_txq_to_send_pkts(&tsock->txq) > 0) {
		output_tsock_enqueue(tsock->worker, tsock);
	} else if (tsock->flags & TSOCK_FLAG_FIN_PENDING) {
		tsock->snd_nxt = tsock->data_seq_nxt + 1;
		tsock->flags |= TSOCK_FLAG_FIN_NEEDED | TSOCK_FLAG_ACK_NEEDED |
				TSOCK_FLAG_FIN_SENT;
		if (tsock->rto_shift == 0) {
			timer_start(&tsock->timer_rto, tsock->worker->ts_us, tsock->rto);
		}
	}

	if (tsock_flags_to_tcp_flags(tsock->flags))
		xmit_flag_packet(worker, tsock);

	return ret;
}

static inline void tcp_flush_delayed_ack(struct tpa_worker *worker)
{
	struct tcp_sock *tsock;
	int i;

	for (i = 0; i < BATCH_SIZE; i++) {
		tsock = FLEX_FIFO_PEEK_ENTRY(worker->delayed_ack, struct tcp_sock, delayed_ack_node);
		if (!tsock)
			break;

		/* XXX: should warn on this */
		if (tsock->sid < 0) {
			flex_fifo_pop(worker->delayed_ack);
			continue;
		}

		if ((uint32_t)worker->ts_us - tsock->last_ack_sent_ts < tcp_cfg.delayed_ack)
			break;

		if (tsock->flags & TSOCK_FLAG_ACK_NEEDED)
			xmit_flag_packet(worker, tsock);
		flex_fifo_pop(worker->delayed_ack);
	}
}

int tcp_output(struct tpa_worker *worker)
{
	struct tcp_sock *tsock;
	uint32_t nr_tsock;
	uint32_t i;
	int err;

	nr_tsock = output_tsock_dequeue(worker);

	for (i = 0; i < nr_tsock; i++) {
		tsock = worker->tsocks[i];

		err = tcp_output_one(worker, tsock);
		if (unlikely(err))
			WORKER_TSOCK_STATS_INC(worker, tsock, -err);
	}

	tcp_flush_delayed_ack(worker);

	return nr_tsock;
}
