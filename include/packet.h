/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _PACKET_H_
#define _PACKET_H_

#include <sys/queue.h>

#include <rte_mbuf.h>

#include "lib/utils.h"
#include "tcp.h"
#include "cfg.h"
#include "flex_fifo.h"
#include "dpdk_compat.h"

/*
 * 64k/1448 ~= 45
 *
 * TODO: we should obey nb_seg_max/nb_mtu_seg_max
 */
#define PKT_MAX_CHAIN			45

#define PKT_FLAG_RETRANSMIT		(1u<<0)
#define PKT_FLAG_HAS_TS_OPT		(1u<<1)
#define PKT_FLAG_MEASURE_READ_LATENCY	(1u<<2)
#define PKT_FLAG_IS_IPV6		(1u<<3)
#define PKT_FLAG_VERIFY_CUT		(1u<<4)
#define PKT_FLAG_STALE_NEIGH		(1u<<5)

struct packet {
	struct rte_mbuf mbuf;

	uint16_t src_port;
	uint16_t dst_port;

	uint16_t flags;
	uint8_t  wid;
	uint8_t l2_off;
	uint8_t l3_off;
	uint8_t l4_off;

	/*
	 * The tcp payload offset; unlike other offsets, it's not fixed.
	 * It may vary as we do packet cut.
	 */
	uint16_t l5_off;
	uint16_t l5_len;
	uint16_t ip_payload_len;
	uint8_t hdr_len;
	int8_t nr_read_seg;

	/*
	 * If there is a pkt chain,
	 * - TCP_SEG(head)->seq points to the first valid seq, which may
	 *   point to a seq in next pkt in the chain (after HEAD cut).
	 *
	 * - TCP_SEG(head)->len represents the TCP payload len of the
	 *   whole packet chain, where TCP_SEG(pkt)->l5_len represents
	 *   the acutal TCP payload for each TCP segment.
	 */
	struct {
		uint32_t seq;
		uint32_t ack;
		union {
			struct {
				uint32_t ts_val;
				uint32_t ts_ecr;
			};
			uint64_t ts_raw;
		};
		uint16_t wnd;
		uint16_t len;
		uint8_t  opt_len;
		uint8_t  flags;
	} __attribute__((packed)) tcp;

	uint16_t port_id;

	union {
		struct packet *tail;	/* for merge stage */
		struct packet *to_read; /* for read stage */
	};
	uint64_t ts_us;

	struct tcp_sock *tsock;
	union {
		TAILQ_ENTRY(packet) node; /* for ooo only so far */
		struct flex_fifo_node neigh_node;
	};

	struct {
		uint64_t start;
		uint64_t submit;
		uint64_t drain;
	} read_tsc;
} __rte_cache_aligned;

TAILQ_HEAD(packet_list, packet);

/* XXX: we support 2 NUMA at most */
#define TPA_MAX_NUMA			2
#define preferred_mempool(p)		((p)->pool[tpa_cfg.preferred_numa])
#define backup_mempool(p)		((p)->pool[!tpa_cfg.preferred_numa])

struct packet_pool {
	struct rte_mempool *pool[TPA_MAX_NUMA];
};

#define TCP_SEG(pkt)		(&((pkt)->tcp))
#define has_flag_syn(pkt)	((TCP_SEG(pkt)->flags & TCP_FLAG_SYN) != 0)
#define has_flag_rst(pkt)	((TCP_SEG(pkt)->flags & TCP_FLAG_RST) != 0)
#define has_flag_ack(pkt)	((TCP_SEG(pkt)->flags & TCP_FLAG_ACK) != 0)
#define has_flag_psh(pkt)	((TCP_SEG(pkt)->flags & TCP_FLAG_PSH) != 0)
#define has_flag_fin(pkt)	((TCP_SEG(pkt)->flags & TCP_FLAG_FIN) != 0)

/*
 * note that it points to mbuf->mbuf_addr directly, instead of the addr with
 * mbuf->data_off.
 */
static inline uint8_t *packet_data(struct packet *pkt)
{
	return pkt->mbuf.buf_addr;
}

static inline struct rte_ether_hdr *packet_eth_hdr(struct packet *pkt)
{
	return (struct rte_ether_hdr *)(packet_data(pkt) + pkt->l2_off);
}

static inline struct rte_ipv4_hdr *packet_ip_hdr(struct packet *pkt)
{
	return (struct rte_ipv4_hdr *)(packet_data(pkt) + pkt->l3_off);
}

static inline struct rte_ipv6_hdr *packet_ip6_hdr(struct packet *pkt)
{
	return (struct rte_ipv6_hdr *)(packet_data(pkt) + pkt->l3_off);
}

static inline int ip_is_frag(uint32_t frag_off)
{
	return (frag_off & htons(RTE_IPV4_HDR_MF_FLAG | RTE_IPV4_HDR_OFFSET_MASK)) != 0;
}

static inline struct rte_tcp_hdr *packet_tcp_hdr(struct packet *pkt)
{
	return (struct rte_tcp_hdr *)(packet_data(pkt) + pkt->l4_off);
}

static inline void *tcp_payload_addr(struct packet *pkt)
{
	return packet_data(pkt) + pkt->l5_off;
}

static inline uint64_t tcp_payload_phys_addr(struct packet *pkt)
{
	return pkt->mbuf.buf_iova + pkt->l5_off;
}

/*
 * A more lightweight external buf attach for zero copy write implementation.
 */
static inline void packet_attach_extbuf(struct packet *pkt, void *virt_addr,
					uint64_t phys_addr, uint16_t data_len)
{
	pkt->mbuf.buf_addr = virt_addr;
	pkt->mbuf.buf_iova = phys_addr;
	pkt->mbuf.pkt_len  = data_len;
	pkt->mbuf.data_len = data_len;
	pkt->mbuf.data_off = 0;
}

static inline void packet_init(struct packet *pkt)
{
	pkt->flags = 0;
	pkt->hdr_len = 0;

	TCP_SEG(pkt)->flags = 0;
	TCP_SEG(pkt)->len = 0;

	FLEX_FIFO_NODE_INIT(&pkt->neigh_node);
}

static inline struct rte_mempool *packet_pool_get_mempool(struct packet_pool *pool)
{
	return preferred_mempool(pool) ? preferred_mempool(pool) : backup_mempool(pool);
}

static inline struct packet *do_packet_alloc(struct rte_mempool *mempool)
{
	struct packet *pkt;

	if (unlikely(mempool == NULL))
		return NULL;

	pkt = (struct packet *)rte_pktmbuf_alloc(mempool);
	if (likely(pkt != NULL))
		packet_init(pkt);

	return pkt;
}

static inline struct packet *packet_alloc(struct packet_pool *pool)
{
	struct packet *pkt;

	pkt = do_packet_alloc(preferred_mempool(pool));
	if (unlikely(pkt == NULL))
		pkt = do_packet_alloc(backup_mempool(pool));

	return pkt;
}

static inline void packet_free(struct packet *pkt)
{
	rte_pktmbuf_free(&pkt->mbuf);
}

static inline void packet_free_batch(struct packet **pkts, int nr_pkt)
{
	int i;

	for (i = 0; i < nr_pkt; i++)
		packet_free(pkts[i]);
}

#define CUT_HEAD	1
#define CUT_TAIL	0

static inline void tcp_packet_cut_head(struct packet *head, int size)
{
	struct packet *pkt = head->to_read;

	TCP_SEG(head)->seq += size;

	while (pkt && size >= pkt->l5_len) {
		size -= pkt->l5_len;
		pkt = (struct packet *)(pkt->mbuf.next);
		head->nr_read_seg -= 1;
	}

	if (size) {
		pkt->l5_len -= size;
		pkt->l5_off += size;
	}

	head->to_read = pkt;
}

static inline void tcp_packet_cut_tail(struct packet *head, int size)
{
	struct packet *pkt = head->to_read;
	uint16_t nr_read_seg = 0;

	size = TCP_SEG(head)->len - size;
	while (pkt && size >= pkt->l5_len) {
		size -= pkt->l5_len;
		pkt = (struct packet *)(pkt->mbuf.next);
		nr_read_seg += 1;
	}

	if (size) {
		pkt->l5_len = size;
		nr_read_seg += 1;
	}

	head->nr_read_seg = nr_read_seg;
}

static inline void tcp_packet_cut_verify(struct packet *pkt)
{
	uint16_t size = TCP_SEG(pkt)->len;
	uint16_t nr_seg = pkt->nr_read_seg;

	pkt = pkt->to_read;
	while (size) {
		size -= pkt->l5_len;
		pkt = (struct packet *)(pkt->mbuf.next);
		nr_seg -= 1;
	}

	assert(nr_seg == 0);
}

static inline void tcp_packet_cut(struct packet *pkt, uint32_t size, int dir)
{
	debug_assert(TCP_SEG(pkt)->len >= size);

	if (dir == CUT_HEAD)
		tcp_packet_cut_head(pkt, size);
	else
		tcp_packet_cut_tail(pkt, size);

	TCP_SEG(pkt)->len -= size;


	/*
	 * XXX: normally, we should introduce a debug macro and only
	 * enable it when such macro is defined. However, it's not
	 * friendly for unit purpose: we wish to always do strict
	 * verification on unit test. Therefore, a hack is made here.
	 */
	if (unlikely(pkt->flags & PKT_FLAG_VERIFY_CUT))
		tcp_packet_cut_verify(pkt);
}

static inline void packet_chain(struct packet *head, struct packet *pkt)
{
	head->mbuf.nb_segs += 1;
	head->mbuf.pkt_len += pkt->mbuf.pkt_len;
	head->tail->mbuf.next = &pkt->mbuf;

	TCP_SEG(head)->len += pkt->l5_len;
	head->nr_read_seg += 1;
	head->tail = pkt;
}

#define IP4_HDR_LEN(ip)		((ip->version_ihl & 0xf) << 2)

int parse_tcp_packet(struct packet *pkt);
int parse_tcp_opts(struct tcp_opts *opts, struct packet *pkt);
uint16_t calc_udptcp_csum(struct packet *pkt, void *ip);

extern struct packet_pool *generic_pkt_pool;
int packet_pool_create(struct packet_pool *pool, double percent,
		       uint32_t mbuf_size, const char *fmt, ...);

#endif
