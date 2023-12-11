/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _TCP_QUEUE_H_
#define _TCP_QUEUE_H_

#include "tx_desc.h"

/*
 * TCP txq enqueue operation is atomic: either all objs will be enqueued,
 * or nothing will. This makes the write/writev/send operation be atomic.
 *
 * And it has following layout:
 *
 *   +----------------------+-------------+----------------------+
 *   |                      |             |      f r e e         |
 *   +----------------------+-------------+----------------------+
 *   ^                      ^             ^
 *  una                    nxt           write
 */
struct tcp_txq {
	uint16_t una;
	uint16_t nxt;
	uint16_t write;
	uint16_t size;
	uint16_t mask;

	void **descs;
};

static inline void tcp_txq_init(struct tcp_txq *txq, uint16_t size)
{
	assert((size & (size - 1)) == 0);

	txq->una = 0;
	txq->nxt = 0;
	txq->write = 0;
	txq->size = size;
	txq->mask = size - 1;
}

static inline uint16_t tcp_txq_inflight_pkts(struct tcp_txq *txq)
{
	return txq->nxt - txq->una;
}

static inline uint16_t tcp_txq_to_send_pkts(struct tcp_txq *txq)
{
	return txq->write - txq->nxt;
}

static inline int tcp_txq_unfinished_pkts(struct tcp_txq *txq)
{
	return tcp_txq_inflight_pkts(txq) + tcp_txq_to_send_pkts(txq);
}

static inline uint16_t tcp_txq_free_count(struct tcp_txq *txq)
{
	return txq->size - tcp_txq_unfinished_pkts(txq);
}

/*
 * returns 0 if all descs are enqueued, otherwise returns -1.
 */
static inline int tcp_txq_enqueue_bulk(struct tcp_txq *txq, void **descs, uint16_t nr_desc)
{
	uint16_t i;

	if ((uint16_t)(txq->write + nr_desc - txq->una) > txq->size)
		return -1;

	for (i = 0; i < nr_desc; i++)
		txq->descs[(txq->write + i) & txq->mask] = descs[i];

	txq->write += nr_desc;

	return 0;
}

static inline void *tcp_txq_peek_una_before_nxt(struct tcp_txq *txq, uint16_t off)
{
	if (off >= (uint16_t)(txq->nxt - txq->una))
		return NULL;

	return txq->descs[(txq->una + off) & txq->mask];
}

/* @base could be any value between @una and @write */
static inline void *tcp_txq_peek_for_write(struct tcp_txq *txq, uint16_t base, uint16_t off)
{
	if (off >= (uint16_t)(txq->write - base))
		return NULL;

	return txq->descs[(base + off) & txq->mask];
}

#define TCP_TXQ_PEEK(type, end)							\
static inline void *tcp_txq_peek_##type(struct tcp_txq *txq, uint16_t off)	\
{										\
	if (off >= (uint16_t)(txq->end - txq->type))				\
		return NULL;							\
	return txq->descs[(txq->type + off) & txq->mask];			\
}
#define TCP_TXQ_UPDATE(type, end)						\
static inline void tcp_txq_update_##type(struct tcp_txq *txq, uint16_t count)	\
{										\
	debug_assert(count <= (uint16_t)(txq->end - txq->type));		\
	txq->type += count;							\
}

TCP_TXQ_PEEK(una, write)
TCP_TXQ_UPDATE(una, write)

TCP_TXQ_PEEK(nxt, write)
TCP_TXQ_UPDATE(nxt, write)


struct tcp_rxq {
	uint16_t unread; /* tail */
	uint16_t max;    /* head */

	uint16_t size;
	uint16_t mask;

	/* it could be a pkt or a sock (for listen socket) */
	void **objs;
};

static inline void tcp_rxq_init(struct tcp_rxq *rxq, uint16_t size)
{
	assert((size & (size - 1)) == 0);

	rxq->unread = 0;
	rxq->max = 0;
	rxq->size = size;
	rxq->mask = size - 1;
}

static inline uint16_t tcp_rxq_readable_count(struct tcp_rxq *rxq)
{
	return rxq->max - rxq->unread;
}

static inline uint16_t tcp_rxq_free_count(struct tcp_rxq *rxq)
{
	return rxq->size - tcp_rxq_readable_count(rxq);
}

/* enqueue as many as we can */
static inline uint16_t tcp_rxq_enqueue_burst(struct tcp_rxq *rxq, void **objs, uint16_t nr_obj)
{
	uint16_t i;

	nr_obj = RTE_MIN(tcp_rxq_free_count(rxq), nr_obj);
	for (i = 0; i < nr_obj; i++)
		rxq->objs[(rxq->max + i) & rxq->mask] = objs[i];

	rte_smp_wmb();
	rxq->max += nr_obj;

	return nr_obj;
}

static inline uint16_t tcp_rxq_dequeue_burst(struct tcp_rxq *rxq, void **objs, uint16_t nr_obj)
{
	uint16_t i;

	nr_obj = RTE_MIN(tcp_rxq_readable_count(rxq), nr_obj);
	for (i = 0; i < nr_obj; i++)
		objs[i] = rxq->objs[(rxq->unread + i) & rxq->mask];

	rte_smp_wmb();
	rxq->unread += nr_obj;

	return nr_obj;

}

static inline void *tcp_rxq_peek_unread(struct tcp_rxq *rxq, uint16_t off)
{
	if (off >= (uint16_t)(rxq->max - rxq->unread))
		return NULL;

	return rxq->objs[(rxq->unread + off) & rxq->mask];
}

static inline void tcp_rxq_update_unread(struct tcp_rxq *rxq, uint16_t count)
{
	debug_assert(count <= (uint16_t)(rxq->max - rxq->unread));
	rxq->unread += count;
}

#endif /* _TCP_QUEUE_ */
