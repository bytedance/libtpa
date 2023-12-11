/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <unistd.h>

#include <rte_cycles.h>

#include "pktfuzz.h"
#include "worker.h"
#include "trace/tcp.h"

static inline int get_cut_size(struct fuzz_cut_cfg *cut, uint16_t payload_len)
{
	if (cut->size.random)
		return (rte_rdtsc() % payload_len) / (cut->head + cut->tail);

	return RTE_MIN(cut->size.num, (int)payload_len);
}

static inline struct rte_mbuf *mbuf_cut_head(struct rte_mbuf *m, uint32_t size)
{
	struct rte_mbuf *next;
	uint32_t pkt_len = m->pkt_len;
	uint32_t nr_seg = m->nb_segs;
	uint32_t left = size;

	assert(m->pkt_len >= size);

	/*
	 * do not use >= here; we always would return one mbuf seg
	 * at least: even though all pkts are being cut, we still
	 * have a tcp hdr could be sent.
	 */
	while (left > m->data_len) {
		left -= m->data_len;
		nr_seg -= 1;

		next = m->next;
		rte_pktmbuf_free_seg(m);
		m = next;
	}

	/* see rte_pktmbuf_adj for details on the cast */
	m->data_len -= left;
	m->data_off += left;
	m->pkt_len  = pkt_len - size;
	m->nb_segs  = nr_seg;

	return m;
}

#define relative_snd_seq(seq, pkt)		\
	seq - pkt->tsock->snd_isn

/*
 * instead of moving the whole payload to do head cut, here we simply
 * move the net hdr.
 */
static struct packet *cut_head(struct packet *pkt, int size)
{
	struct rte_ether_hdr *eth = rte_pktmbuf_mtod(&pkt->mbuf, struct rte_ether_hdr *);
	struct rte_tcp_hdr *tcp;

	/* update the hdr before real cut: we do hdr move only after all */
	if (eth->ether_type == htons(RTE_ETHER_TYPE_IPV4)) {
		struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);

		ip->total_length = htons(ntohs(ip->total_length) - size);
		tcp = (struct rte_tcp_hdr *)((char *)eth + sizeof(*eth) + sizeof(*ip));
	} else {
		struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)(eth + 1);

		ip6->payload_len = htons(ntohs(ip6->payload_len) - size);
		tcp = (struct rte_tcp_hdr *)((char *)eth + sizeof(*eth) + sizeof(*ip6));
	}
	tcp->sent_seq = htonl(ntohl(tcp->sent_seq) + size);
	trace_pktfuzz_cut(pkt->tsock, ntohl(tcp->sent_seq), size);

	if (size < pkt->mbuf.data_len - pkt->hdr_len) {
		pkt->mbuf.data_off += size;
		pkt->mbuf.pkt_len  -= size;
		pkt->mbuf.data_len -= size;

		memmove((char *)eth + size, eth, pkt->hdr_len);

		return pkt;
	} else {
		int hdr_len = pkt->hdr_len;
		char hdr_snapshot[hdr_len];
		struct rte_mbuf *m = &pkt->mbuf;
		int tso_segsz = m->tso_segsz;
		void *hdr;

		memcpy(hdr_snapshot, eth, pkt->hdr_len);

		/* remove the hdr before cut; we cut payload only after all */
		rte_pktmbuf_adj(m, pkt->hdr_len);
		m = mbuf_cut_head(m, size);
		m->tso_segsz = tso_segsz;

		hdr = rte_pktmbuf_prepend(m, hdr_len);
		assert(hdr != NULL);

		memcpy(hdr, hdr_snapshot, hdr_len);

		pkt = (struct packet *)m;
		pkt->hdr_len = hdr_len;
		return pkt;
	}
}

static void cut_tail(struct packet *pkt, int size)
{
	struct rte_ether_hdr *eth = rte_pktmbuf_mtod(&pkt->mbuf, struct rte_ether_hdr *);
	struct rte_mbuf *m = &pkt->mbuf;
	struct rte_tcp_hdr *tcp;
	uint32_t seq;

	if (eth->ether_type == htons(RTE_ETHER_TYPE_IPV4)) {
		struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);

		ip->total_length = htons(ntohs(ip->total_length) - size);
		tcp = (struct rte_tcp_hdr *)((char *)eth + sizeof(*eth) + sizeof(*ip));
	} else {
		struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)(eth + 1);

		ip6->payload_len = htons(ntohs(ip6->payload_len) - size);
		tcp = (struct rte_tcp_hdr *)((char *)eth + sizeof(*eth) + sizeof(*ip6));
	}

	pkt->mbuf.pkt_len -= size;
	seq = ntohl(tcp->sent_seq) + pkt->mbuf.pkt_len - pkt->hdr_len,
	trace_pktfuzz_cut(pkt->tsock, seq, size);

	/* hide hdr */
	rte_pktmbuf_adj(m, pkt->hdr_len);

	size = pkt->mbuf.pkt_len;
	pkt->mbuf.nb_segs = 0;

	while (size >= m->data_len) {
		size -= m->data_len;
		pkt->mbuf.nb_segs += 1;

		m = m->next;
	};

	m->data_len = size;
	pkt->mbuf.nb_segs += 1;

	if (m->next) {
		packet_free((struct packet *)m->next);
		m->next = NULL;
	}

	/* restore hdr */
	rte_pktmbuf_prepend(&pkt->mbuf, pkt->hdr_len);
}

static inline void do_cut(struct dev_txq *txq, struct fuzz_cut_cfg *cut, int payload_len)
{
	struct packet *pkt = pktfuzz_packet_copy(txq->pkts[txq->nr_pkt - 1]);
	int size;

	if (!pkt)
		return;

	size = get_cut_size(cut, payload_len);
	if (size) {
		if (cut->head)
			pkt = cut_head(pkt, size);
		if (cut->tail)
			cut_tail(pkt, size);
	}

	pktfuzz_update_csum_offload(pkt);

	packet_free(txq->pkts[txq->nr_pkt - 1]);
	txq->pkts[txq->nr_pkt - 1] = pkt;
	cut->stats.total += 1;
}

static void cut_fuzz(struct dev_txq *txq)
{
	struct fuzz_cut_cfg *cut = &fuzz_cfg.cut;
	struct packet *pkt;
	int payload_len;
	int nr_seg;	/* in unit of mss */
	int mss;

	if (!cut->enabled || txq->nr_pkt == 0)
		return;

	pkt = txq->pkts[txq->nr_pkt - 1];
	payload_len =  pkt->mbuf.pkt_len - pkt->hdr_len;
	if (payload_len == 0)
		return;

	if (pkt->tsock == NULL || pkt->tsock->snd_mss == 0)
		return;

	mss = pkt->tsock->snd_mss;
	nr_seg = (payload_len + mss - 1) / mss;
	if (meet_rate_n(&cut->rate, nr_seg))
		do_cut(txq, cut, payload_len);
}

static void cut_stats(struct shell_buf *reply, struct fuzz_cfg *fuzz_cfg)
{
	struct fuzz_cut_cfg *cut = &fuzz_cfg->cut;

	shell_append_reply(reply,
			   "cut:\n"
			   "\tenabled: %d\n"
			   RATE_FMT
			   "\tstats.total: %lu\n",
			   cut->enabled,
			   RATE_ARGS(&cut->rate),
			   cut->stats.total);
}

static void cut_help(struct shell_buf *reply, struct fuzz_cfg *fuzz_cfg)
{
	shell_append_reply(reply,
			  "cut           cut few bytes of the packet payload\n"
			  "  -r rate     specify the cut rate\n"
			  "  -n num      specify the cut size in bytes\n"
			  "  -h          cut payload from head\n"
			  "  -t          cut payload from tail (default)\n");
}

static int cut_parse(struct fuzz_opt *opts)
{
	struct fuzz_cut_cfg *cut = &opts->fuzz_cfg->cut;
	int enabled = 0;
	int opt;

	memset(cut, 0, sizeof(*cut));

	while ((opt = getopt(opts->argc, opts->argv, "r:n:ht")) != -1) {
		switch (opt) {
		case 'r':
			parse_rate(&cut->rate, optarg);
			enabled = 1;
			break;

		case 'n':
			if (parse_num(&cut->size, optarg, NUM_TYPE_SIZE) < 0) {
				shell_append_reply(opts->reply, "invalid cut size: %c\n", opt);
				return -1;
			}
			break;

		case 'h':
			cut->head = 1;
			break;
		case 't':
			cut->tail = 1;
			break;

		default:
			shell_append_reply(opts->reply, "invalid arg: %c\n", opt);
			return -1;
		}
	}

	/* default to cutting tail */
	if (cut->head == 0 && cut->tail == 0)
		cut->tail = 1;

	if (!num_given(&cut->size))
		cut->size.num = 1;

	cut->enabled = enabled;

	return 0;
}

const struct fuzzer fuzzer_cut = {
	.name   = "cut",
	.fuzz   = cut_fuzz,
	.parse  = cut_parse,
	.stats  = cut_stats,
	.help   = cut_help,
};
