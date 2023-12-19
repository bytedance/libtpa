/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <sys/mman.h>

#include "tperf.h"

struct mbuf_pool *mbuf_pool_create(void)
{
	struct mbuf_pool *pool;
	struct mbuf *mbufs;
	size_t nr_mbuf;
	void *addr;
	int i;

	addr = mmap(NULL, MBUF_POOL_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	assert(addr != MAP_FAILED);

	nr_mbuf = MBUF_POOL_SIZE / MBUF_SIZE;
	pool = zmalloc_assert(sizeof(struct mbuf_pool) + sizeof(void *) * nr_mbuf);
	pool->nr_mbuf = nr_mbuf;

	mbufs = zmalloc_assert(sizeof(struct mbuf) * nr_mbuf);
	for (i = 0; i < nr_mbuf; i++) {
		mbufs[i].refcnt = 0;
		mbufs[i].pool = pool;
		mbufs[i].data = addr + i * MBUF_SIZE;

		mbuf_free(&mbufs[i]);
	}

	if (tpa_extmem_register(addr, MBUF_POOL_SIZE, NULL,
				   MBUF_POOL_SIZE / MBUF_SIZE, MBUF_SIZE) != 0) {
		fprintf(stderr, "warn: external mem registration failed: %s\n", strerror(errno));
		fprintf(stderr, "disabling zero copy write by force\n");
		ctx.enable_zwrite = 0;
	}

	return pool;
}
