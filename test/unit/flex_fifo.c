/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include "test_utils.h"

#include "flex_fifo.h"

struct test_struct {
	uint64_t a;
	struct flex_fifo_node node;
	uint64_t b;
};

static uint64_t next_id;

static void test_flex_fifo_basic(int ring_size)
{
	struct flex_fifo *ff = flex_fifo_create(ring_size);
	struct flex_fifo_node *node;
	struct test_struct ts[3];

	printf("testing %s ring_size=%d ...\n", __func__, ring_size);

	memset(ts, 0, sizeof(ts));

	/* enqueue 3 */
	FLEX_FIFO_NODE_INIT(&ts[0].node); flex_fifo_push(ff, &ts[0].node);
	FLEX_FIFO_NODE_INIT(&ts[1].node); flex_fifo_push(ff, &ts[1].node);
	FLEX_FIFO_NODE_INIT(&ts[2].node); flex_fifo_push(ff, &ts[2].node);

	/* remove the middle one */
	assert(flex_fifo_remove(ff, &ts[1].node) == 0); {
		assert(FLEX_FIFO_PEEK_ENTRY(ff, struct test_struct, node) == &ts[0]);
		node = flex_fifo_pop(ff);
		assert(node == &ts[0].node);
		assert(FLEX_FIFO_ENTRY(node, struct test_struct, node) == &ts[0]);

		assert(FLEX_FIFO_PEEK_ENTRY(ff, struct test_struct, node) == &ts[2]);
		node = flex_fifo_pop(ff);
		assert(node == &ts[2].node);
		assert(FLEX_FIFO_ENTRY(node, struct test_struct, node) == &ts[2]);

		assert(flex_fifo_count(ff) == 0);
		assert(flex_fifo_pop(ff) == NULL);
		assert(FLEX_FIFO_PEEK_ENTRY(ff, struct test_struct, node) == NULL);
	}
}

static struct test_struct *push_ts(struct flex_fifo *ff)
{
	struct test_struct *ts;

	ts = malloc(sizeof(*ts));

	FLEX_FIFO_NODE_INIT(&ts->node);
	ts->a = next_id++;
	ts->b = UINT64_MAX - ts->a;

	flex_fifo_push(ff, &ts->node);

	return ts;
}

static int pop_and_verify_ts(struct flex_fifo *ff, uint64_t *id, int strict)
{
	struct test_struct *ts;

	ts = FLEX_FIFO_POP_ENTRY(ff, struct test_struct, node);
	if (!ts)
		return -1;

	if (strict)
		assert(ts->a == *id);
	else
		assert(ts->a - *id <= 1);
	assert(ts->a + ts->b == UINT64_MAX);

	*id = ts->a + 1;
	free(ts);

	return 0;
}

static void test_flex_fifo_stress(int ring_size)
{
	struct flex_fifo *ff = flex_fifo_create(ring_size);
	uint32_t loop = 0;
	uint64_t id = 0;
	int nr_to_push;
	int nr_to_pop;
	int i;

	printf("testing %s ring_size=%d ...\n", __func__, ring_size);

	next_id = 0;
	WHILE_NOT_TIME_UP() {
		nr_to_push = rand() % 128;
		nr_to_pop = rand() % 150;

		/* simulate burst */
		if (rand() % 1000 == 1)
			nr_to_push = rand() % 4096;

		for (i = 0; i < nr_to_push; i++)
			push_ts(ff);

		for (i = 0; i < nr_to_pop; i++) {
			if (pop_and_verify_ts(ff, &id, 1) < 0)
				break;
		}

		ON_INTERVAL(1000 * 1000) {
			printf("%-4u curr : total=%-8u ring=%-4u list=%-8u   "
			       "total: ring=%-12lu list=%-12lu ring_ratio=%.3f\n",
			       loop++, flex_fifo_count(ff), flex_fifo_ring_count(ff),
			       flex_fifo_list_count(ff),
			       ff->ring_total, ff->list_total,
			       (double)ff->ring_total * 100.0 / (ff->ring_total + ff->list_total));
		}
	}

	while (pop_and_verify_ts(ff, &id, 1) == 0)
		;

	assert(flex_fifo_count(ff) == 0);
}

static void test_flex_fifo_stress_with_remove(int ring_size)
{
	struct flex_fifo *ff = flex_fifo_create(ring_size);
	struct test_struct *to_remove = NULL;
	uint32_t loop = 0;
	uint64_t id = 0;
	int nr_to_push;
	int nr_to_pop;
	int i;

	printf("testing %s ring_size=%d ...\n", __func__, ring_size);

	next_id = 0;
	WHILE_NOT_TIME_UP() {
		/*
		 * push 2 entries at least, so that the max ID gap would
		 * be 1 caused by remove
		 */
		nr_to_push = (rand() % 128) + 2;
		nr_to_pop = rand() % 150;

		/* we remove one entry every time we push a batch of them */
		for (i = 0; i < nr_to_push; i++)
			to_remove = push_ts(ff);

		flex_fifo_remove(ff, &to_remove->node);
		free(to_remove);

		for (i = 0; i < nr_to_pop; i++) {
			if (pop_and_verify_ts(ff, &id, 0) < 0)
				break;
		}

		ON_INTERVAL(1000 * 1000) {
			printf("%-4u curr : total=%-8u ring=%-4u list=%-8u   "
			       "total: ring=%-12lu list=%-12lu ring_ratio=%.3f\n",
			       loop++, flex_fifo_count(ff), flex_fifo_ring_count(ff),
			       flex_fifo_list_count(ff),
			       ff->ring_total, ff->list_total,
			       (double)ff->ring_total * 100.0 / (ff->ring_total + ff->list_total));
		}
	}

	while (pop_and_verify_ts(ff, &id, 0) == 0)
		;

	assert(flex_fifo_count(ff) == 0);
}

int main(int argc, char **argv)
{
	ut_init(argc, argv);

	srand(rte_rdtsc());

	test_flex_fifo_basic(0);
	test_flex_fifo_basic(1);
	test_flex_fifo_basic(2);
	test_flex_fifo_basic(32);

	test_flex_fifo_stress(0);
	test_flex_fifo_stress(32);

	test_flex_fifo_stress_with_remove(0);
	test_flex_fifo_stress_with_remove(32);

	return 0;
}
