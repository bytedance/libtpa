/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _TX_DESC_H_
#define _TX_DESC_H_

#include <stdint.h>

#include <rte_malloc.h>

#include "lib/utils.h"

#define TX_DESC_FLAG_MEM_FROM_MBUF		(1<<0)
#define TX_DESC_FLAG_MEASURE_LATENCY		(1<<1)
#define TX_DESC_FLAG_RETRANS			(1<<2)
#define TX_DESC_FLAG_SACKED			(1<<3)

struct tx_desc {
	void *addr;
	uint64_t phys_addr;
	uint32_t len;
	uint32_t flags;
	void (*write_done)(void *base, void *param);
	void *base;
	void *param;

	uint32_t seq;
	uint32_t reserved;
	uint64_t ts_us;

	/* cacheline 2 */
	uint64_t tsc_start;
	uint64_t tsc_submit;
	uint64_t tsc_xmit;

	/* for none zero copy write */
	void *pkt;
} __attribute__((__aligned__(64)));

#define tx_desc_done(desc, pool)		do {		\
	if ((desc)->flags & TX_DESC_FLAG_MEM_FROM_MBUF)		\
		packet_free(desc->pkt);				\
	if ((desc)->write_done)					\
		desc->write_done(desc->base, desc->param);	\
	tx_desc_free(pool, desc);				\
} while (0)



/* a stack-based allocator */
struct tx_desc_pool {
	uint32_t nr_desc;
	uint32_t off;

	struct tx_desc *descs[0];
};

static inline struct tx_desc *tx_desc_alloc(struct tx_desc_pool *pool)
{
	if (pool->off == 0)
		return NULL;

	return pool->descs[--pool->off];
}

static inline void tx_desc_free(struct tx_desc_pool *pool, struct tx_desc *desc)
{
	debug_assert(pool->off < pool->nr_desc);

	pool->descs[pool->off++] = desc;
}

static inline uint32_t tx_desc_pool_free_count(struct tx_desc_pool *pool)
{
	return pool->off;
}

static inline struct tx_desc_pool *tx_desc_pool_create(int nr_desc)
{
	struct tx_desc_pool *pool;
	struct tx_desc *descs;
	size_t pool_size;
	int i;

	pool_size = sizeof(struct tx_desc_pool) + nr_desc * sizeof(struct tx_desc *);
	pool = rte_malloc(NULL, pool_size, 64);
	if (!pool)
		return NULL;

	pool->nr_desc = nr_desc;
	pool->off = 0;

	descs = rte_malloc(NULL, nr_desc * sizeof(struct tx_desc), 64);
	if (!descs) {
		rte_free(pool);
		return NULL;
	}

	for (i = 0; i < nr_desc; i++)
		tx_desc_free(pool, &descs[i]);

	return pool;
}

#endif
