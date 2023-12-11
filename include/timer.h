/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _TIMER_H_
#define _TIMER_H_

#include <stdint.h>
#include <string.h>
#include <sys/queue.h>

#include "lib/utils.h"

/*
 * A simple timer implementation with one timer wheel. It has granularity
 * of 100 ms and 2048 slots. That means the max timeout we support is 204.8s.
 * It should be pretty enough for the TCP case.
 *
 * TODO: make it multiple wheel.
 */
#define NR_SLOT			2048
#define SLOT_MASK		(NR_SLOT - 1)
#define GRAGNULARITY		(100 * 1000)	/* us */

struct timer {
	TAILQ_ENTRY(timer) node;
	struct timer_ctrl *timer_ctrl;

	uint32_t slot_idx;
	uint16_t active;
	uint16_t closed;

	void (*cb)(struct timer *timer);
	void *arg;
};

TAILQ_HEAD(timer_slot, timer);

struct timer_ctrl {
	uint64_t next_run;
	uint64_t last_run;
	uint32_t curr_slot_idx;
	struct timer_slot slots[NR_SLOT];
};

#define timer_is_stopped(timer)		((timer)->active == 0)

static inline void timer_stop(struct timer *timer)
{
	if (timer_is_stopped(timer))
		return;

	TAILQ_REMOVE(&timer->timer_ctrl->slots[timer->slot_idx], timer, node);
	timer->active = 0;
}

static inline void timer_close(struct timer *timer, uint64_t now)
{
	timer_stop(timer);
	timer->closed = 1;
}

static inline void timer_start(struct timer *timer, uint64_t now, uint64_t expire)
{
	struct timer_ctrl *timer_ctrl = timer->timer_ctrl;
	int slot_off;
	int slot_idx;

	if (expire == 0)
		expire = 1;

	slot_off = (now + expire - timer_ctrl->last_run + GRAGNULARITY - 1) / GRAGNULARITY;
	if (slot_off > NR_SLOT)
		slot_off = NR_SLOT;
	slot_idx = slot_off + timer_ctrl->curr_slot_idx;

	if (!timer_is_stopped(timer) && (slot_idx & SLOT_MASK) == timer->slot_idx)
		return;

	timer_stop(timer);

	TAILQ_INSERT_TAIL(&timer_ctrl->slots[slot_idx & SLOT_MASK], timer, node);
	timer->slot_idx = slot_idx & SLOT_MASK;
	timer->active = 1;
}

static inline void timer_init(struct timer *timer, struct timer_ctrl *timer_ctrl,
			      void (*cb)(struct timer *timer), void *arg, uint64_t now)
{
	memset(timer, 0, sizeof(*timer));

	timer->timer_ctrl = timer_ctrl;
	timer->cb = cb;
	timer->arg = arg;
}

static inline int timer_process(struct timer_ctrl *timer_ctrl, uint64_t now)
{
	struct timer *timer;
	int nr_timeout = 0;

	while (now >= timer_ctrl->next_run) {
		timer_ctrl->last_run += GRAGNULARITY;
		timer_ctrl->next_run += GRAGNULARITY;
		timer_ctrl->curr_slot_idx += 1;

		while (1) {
			timer = TAILQ_FIRST(&timer_ctrl->slots[timer_ctrl->curr_slot_idx & SLOT_MASK]);
			if (!timer)
				break;

			debug_assert(timer->active == 1);
			debug_assert(timer->closed == 0);
			debug_assert(timer->slot_idx < NR_SLOT);

			timer_stop(timer);
			timer->cb(timer);

			nr_timeout += 1;
		}
	}

	return nr_timeout;
}

static inline void timer_ctrl_init(struct timer_ctrl *timer_ctrl, uint64_t now)
{
	int i;

	memset(timer_ctrl, 0, sizeof(*timer_ctrl));

	for (i = 0; i < NR_SLOT; i++)
		TAILQ_INIT(&timer_ctrl->slots[i]);

	timer_ctrl->last_run = now;
	timer_ctrl->next_run = now + GRAGNULARITY;
}

#endif
