/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _FLEX_FIFO_H_
#define _FLEX_FIFO_H_

#include <stdint.h>
#include <sys/queue.h>

#include <rte_malloc.h>

#include "lib/utils.h"

/*
 * A flex_fifo is a hybrid fifo built on top of ring and list.
 * The ring serves as a fastpath with a limited entries while the
 * list serves as the slowpath, with unlimited entries. Therefore,
 * we could support unlimited entries overall.
 *
 * Thus, the performance should sit between ring and list.
 *
 * Besides that, we leverage the tqe_prev field of the node as a sign
 * of whether a node is in the ring or list of a flex fifo.
 *
 * - if it's in ring, we store the ring idx there and the idx is
 *   bound by [1, max_size + 1], where max_size is bound by 64k.
 *
 * - if it's in list, then tqe_prev is a valid pointer, therefore,
 *   it should be bigger than max_size + 1.
 *
 * - otherwise, it should be NULL, meaning it's neither in ring nor
 *   in the list.
 */

#define NODE_SET_IDX(_node, idx)		(_node)->node.tqe_prev = ((void *)(uintptr_t)(idx))
#define NODE_GET_IDX(_node)			((uint64_t)(uintptr_t)((_node)->node.tqe_prev))

#define RING_MAX_SIZE				(1<<16)

#define FLEX_FIFO_NODE_INIT(_node)		(NODE_SET_IDX(_node, 0))
#define FLEX_FIFO_ENTRY(ptr, type, member)	container_of(ptr, type, member)

struct flex_fifo_node {
	TAILQ_ENTRY(flex_fifo_node) node;
};

TAILQ_HEAD(flex_fifo_list, flex_fifo_node);

/* on early dev stage */
#define FLEX_FIFO_STATS

struct flex_fifo {
	rte_spinlock_t lock;

	uint32_t list_size;
	struct flex_fifo_list list;

	uint64_t ring_total;
	uint64_t list_total;

	uint32_t write;
	uint32_t read;
	uint32_t mask;
	uint32_t size;
	struct flex_fifo_node *ring[0];
} __attribute__((__aligned__(64)));

static inline int node_in_ring(struct flex_fifo_node *node)
{
	uint64_t idx = NODE_GET_IDX(node);

	return idx > 0 && idx < RING_MAX_SIZE + 1;
}

static inline int node_in_list(struct flex_fifo_node *node)
{
	uint64_t idx = NODE_GET_IDX(node);

	return idx > RING_MAX_SIZE + 1;
}

static inline int node_in_fifo(struct flex_fifo_node *node)
{
	return node->node.tqe_prev != NULL;
}


/*
 * Ring related code
 *
 * Note that the prefix _ff_ shows it's an internal function.
 */
static inline uint32_t flex_fifo_ring_count(struct flex_fifo *ff)
{
	return ff->write - ff->read;
}

static inline int flex_fifo_ring_free_size(struct flex_fifo *ff)
{
	return ff->size - flex_fifo_ring_count(ff);
}

static inline void _ff_do_ring_push(struct flex_fifo *ff, struct flex_fifo_node *node)
{
	ff->ring[ff->write & ff->mask] = node;
	NODE_SET_IDX(node, (ff->write & ff->mask) + 1);

	ff->write += 1;
}

static inline int _ff_ring_push(struct flex_fifo *ff, struct flex_fifo_node *node)
{
	if (unlikely(!TAILQ_EMPTY(&ff->list) || flex_fifo_ring_free_size(ff) == 0))
		return -1;

	_ff_do_ring_push(ff, node);

#ifdef FLEX_FIFO_STATS
	ff->ring_total += 1;
#endif

	return 0;
}

static inline struct flex_fifo_node *_ff_ring_pop(struct flex_fifo *ff)
{
	struct flex_fifo_node *node;

	if (unlikely(ff->read == ff->write))
		return NULL;

	node = ff->ring[ff->read++ & ff->mask];
	debug_assert(node_in_ring(node));
	NODE_SET_IDX(node, 0);

	return node;
}

static inline struct flex_fifo_node *_ff_ring_peek(struct flex_fifo *ff)
{
	if (unlikely(ff->read == ff->write))
		return NULL;

	return ff->ring[ff->read & ff->mask];
}

/*
 * Remove a node in a ring by popping and pushing all elements (except the
 * one to be removed) back to the ring.
 *
 * Note that it's not high performance by design as we think it's a rare
 * operation to remove a node.
 */
static inline int _ff_ring_remove(struct flex_fifo *ff, struct flex_fifo_node *node)
{
	struct flex_fifo_node *curr;
	uint32_t count;
	uint32_t i;

	if (!node_in_ring(node))
		return -1;

	debug_assert(ff->read != ff->write);
	debug_assert(ff->ring[NODE_GET_IDX(node) - 1] == node);

	count = flex_fifo_ring_count(ff);
	for (i = 0; i < count; i++) {
		curr = _ff_ring_pop(ff);
		if (curr == node)
			continue;

		_ff_do_ring_push(ff, curr);
	}

	debug_assert(flex_fifo_ring_count(ff) == count - 1);

	return 0;
}

/*
 * List related code
 */
static inline void _ff_list_push(struct flex_fifo *ff, struct flex_fifo_node *node)
{
	TAILQ_INSERT_TAIL(&ff->list, node, node);
	ff->list_size += 1;

#ifdef FLEX_FIFO_STATS
	ff->list_total += 1;
#endif
}

static inline void _ff_do_list_remove(struct flex_fifo *ff, struct flex_fifo_node *node)
{
	/*
	 * The first assert catches the case when the head node is
	 * not deleted properly by either the POP or REMOVE API,
	 * but instead by doing an INIT(memset) operation.
	 *
	 * The second assert catches something similar, but for the
	 * middle nodes. One thing worth noting is that if that happens,
	 * the list would be chopped, silently (without any explicit
	 * errors), that all nodes after this one will not be accessable
	 * any more (since node->tqe_next is set to NULL). We probably
	 * could get a hint from ff->list_size though.
	 */
	debug_assert(node_in_list(node));
	debug_assert(node->node.tqe_next == NULL || node_in_list(node->node.tqe_next));

	TAILQ_REMOVE(&ff->list, node, node);
	NODE_SET_IDX(node, 0);

	ff->list_size -= 1;
}

static inline struct flex_fifo_node *_ff_list_pop(struct flex_fifo *ff)
{
	struct flex_fifo_node *node;

	node = TAILQ_FIRST(&ff->list);
	if (node)
		_ff_do_list_remove(ff, node);

	return node;
}

static inline struct flex_fifo_node *_ff_list_peek(struct flex_fifo *ff)
{
	return TAILQ_FIRST(&ff->list);
}

static inline int _ff_list_remove(struct flex_fifo *ff, struct flex_fifo_node *node)
{
	if (!node_in_list(node))
		return -1;

	_ff_do_list_remove(ff, node);
	return 0;
}

static inline uint32_t flex_fifo_list_count(struct flex_fifo *ff)
{
	return ff->list_size;
}


/*
 * Generic APIs
 */
static inline void flex_fifo_push(struct flex_fifo *ff, struct flex_fifo_node *node)
{
	debug_assert(!node_in_fifo(node));

	if (likely(_ff_ring_push(ff, node) == 0))
		return;

	_ff_list_push(ff, node);
}

static inline void flex_fifo_push_if_not_exist(struct flex_fifo *ff, struct flex_fifo_node *node)
{
	if (node_in_fifo(node))
		return;

	if (likely(_ff_ring_push(ff, node) == 0))
		return;

	_ff_list_push(ff, node);
}

static inline struct flex_fifo_node *flex_fifo_pop(struct flex_fifo *ff)
{
	struct flex_fifo_node *node;

	node = _ff_ring_pop(ff);
	if (likely(node))
		return node;

	return _ff_list_pop(ff);
}

static inline void *flex_fifo_pop_entry(struct flex_fifo *ff, size_t offset)
{
	struct flex_fifo_node *node;

	node = flex_fifo_pop(ff);
	if (likely(node))
		return (void *)((char *)node - offset);

	return NULL;
}

#define FLEX_FIFO_POP_ENTRY(ff, type, member)	\
	(type *)flex_fifo_pop_entry(ff, offsetof(type, member))

static inline struct flex_fifo_node *flex_fifo_peek(struct flex_fifo *ff)
{
	struct flex_fifo_node *node;

	node = _ff_ring_peek(ff);
	if (likely(node))
		return node;

	return _ff_list_peek(ff);
}

static inline void *flex_fifo_peek_entry(struct flex_fifo *ff, size_t offset)
{
	struct flex_fifo_node *node;

	node = flex_fifo_peek(ff);
	if (likely(node))
		return (void *)((char *)node - offset);

	return NULL;
}

#define FLEX_FIFO_PEEK_ENTRY(ff, type, member)	\
	(type *)flex_fifo_peek_entry(ff, offsetof(type, member))

static inline int flex_fifo_remove(struct flex_fifo *ff, struct flex_fifo_node *node)
{
	if (_ff_ring_remove(ff, node) == 0)
		return 0;

	return _ff_list_remove(ff, node);
}

static inline uint32_t flex_fifo_count(struct flex_fifo *ff)
{
	return flex_fifo_ring_count(ff) + flex_fifo_list_count(ff);
}

static inline struct flex_fifo *flex_fifo_create(uint32_t size)
{
	struct flex_fifo *ff;

	if ((size & (size - 1)) || size > RING_MAX_SIZE)
		return NULL;

	ff = rte_malloc(NULL, sizeof(struct flex_fifo) + size * sizeof(void *), 64);
	if (!ff)
		return NULL;

	memset(ff, 0, sizeof(*ff));

	ff->size = size;
	ff->mask = size - 1;
	TAILQ_INIT(&ff->list);
	rte_spinlock_init(&ff->lock);

	return ff;
}


/*
 * Here starts the lock version, normally used in scenes do not
 * care a lot about performance.
 */
#define _FF_LOCK(ff, op)		do {	\
	rte_spinlock_lock(&(ff)->lock);		\
	op;					\
	rte_spinlock_unlock(&(ff)->lock);	\
} while (0)

static inline void flex_fifo_push_lock(struct flex_fifo *ff, struct flex_fifo_node *node)
{
	_FF_LOCK(ff, flex_fifo_push(ff, node));
}

static inline void flex_fifo_push_if_not_exist_lock(struct flex_fifo *ff, struct flex_fifo_node *node)
{
	_FF_LOCK(ff, flex_fifo_push_if_not_exist(ff, node));
}

static inline struct flex_fifo_node *flex_fifo_pop_lock(struct flex_fifo *ff)
{
	struct flex_fifo_node *node;

	_FF_LOCK(ff, node = flex_fifo_pop(ff));

	return node;
}

static inline void *flex_fifo_pop_entry_lock(struct flex_fifo *ff, size_t offset)
{
	void *obj;

	_FF_LOCK(ff, obj = flex_fifo_pop_entry(ff, offset));

	return obj;
}

#define FLEX_FIFO_POP_ENTRY_LOCK(ff, type, member)	\
	(type *)flex_fifo_pop_entry_lock(ff, offsetof(type, member))

static inline struct flex_fifo_node *flex_fifo_peek_lock(struct flex_fifo *ff)
{
	struct flex_fifo_node *node;

	_FF_LOCK(ff, node = flex_fifo_peek(ff));

	return node;
}

static inline void *flex_fifo_peek_entry_lock(struct flex_fifo *ff, size_t offset)
{
	void *obj;

	_FF_LOCK(ff, obj = flex_fifo_peek_entry(ff, offset));

	return obj;
}

#define FLEX_FIFO_PEEK_ENTRY_LOCK(ff, type, member)	\
	(type *)flex_fifo_peek_entry_lock(ff, offsetof(type, member))

static inline int flex_fifo_remove_lock(struct flex_fifo *ff, struct flex_fifo_node *node)
{
	int ret;

	_FF_LOCK(ff, ret = flex_fifo_remove(ff, node));

	return ret;
}

#endif
