/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _MBUF_H_
#define _MBUF_H_

#define MBUF_SIZE		(4096)
#define MBUF_POOL_SIZE		(512 << 20)


/* note that it's not thread safe */
struct mbuf {
	int refcnt;

	struct mbuf_pool *pool;
	void *data;

	void *private;
};

/* a stack-based allocator */
struct mbuf_pool {
	uint32_t nr_mbuf;
	uint32_t off;
	uint32_t mbuf_size;

	struct mbuf *bufs[0];
};

static inline struct mbuf *mbuf_alloc(struct mbuf_pool *pool)
{
	struct mbuf *mbuf;

	if (pool->off == 0)
		return NULL;

	mbuf = pool->bufs[--pool->off];

	assert(mbuf->refcnt == 0);
	mbuf->refcnt += 1;

	return mbuf;
}


static inline void mbuf_free(struct mbuf *mbuf)
{
	struct mbuf_pool *pool = mbuf->pool;

	assert(mbuf->refcnt == 0);
	assert(pool->off < pool->nr_mbuf);

	pool->bufs[pool->off++] = mbuf;
}

static inline struct mbuf *mbuf_get(struct mbuf *mbuf)
{
	mbuf->refcnt += 1;
	return mbuf;
}

static inline void mbuf_put(struct mbuf *mbuf)
{
	assert(mbuf->refcnt > 0);

	mbuf->refcnt -= 1;
	if (mbuf->refcnt == 0)
		mbuf_free(mbuf);
}

static inline uint32_t mbuf_pool_free_count(struct mbuf_pool *pool)
{
	return pool->off;
}

struct mbuf_pool *mbuf_pool_create(void);
void mbuf_fill(struct connection *conn);

#endif
