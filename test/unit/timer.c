/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <unistd.h>

#include "test_utils.h"

#define FAKE_NOW		1

static void ut_timeout(struct timer *timer)
{
	uint32_t *alarmed = timer->arg;

	*alarmed = 1;
}

static void test_timer_basic(void)
{
	struct timer_ctrl timer_ctrl;
	struct timer timer;
	uint64_t now = FAKE_NOW;
	uint32_t alarmed = 0;

	printf("testing %s ...\n", __func__);

	timer_ctrl_init(&timer_ctrl, now);
	timer_init(&timer, &timer_ctrl, ut_timeout, &alarmed, FAKE_NOW);
	timer_start(&timer, FAKE_NOW, 200 * 1000);

	/* timer now as 100ms granularity */
	timer_process(&timer_ctrl, now + (200 + 100)* 1000); {
		assert(alarmed == 1);
	}
}

static void ut_timeout_stop(struct timer *timer)
{
	uint32_t *alarmed = timer->arg;

	*alarmed = 1;

	timer_stop(timer);
}

static void test_timer_stop_again_in_timeout(void)
{
	struct timer_ctrl timer_ctrl;
	struct timer timer;
	uint64_t now = FAKE_NOW;
	uint32_t alarmed = 0;

	printf("testing %s ...\n", __func__);

	timer_ctrl_init(&timer_ctrl, now);
	timer_init(&timer, &timer_ctrl, ut_timeout_stop, &alarmed, FAKE_NOW);
	timer_start(&timer, FAKE_NOW, 200 * 1000);

	/* timer now as 100ms granularity */
	timer_process(&timer_ctrl, now + (200 + 100)* 1000); {
		assert(alarmed == 1);
	}
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_timer_basic();
	test_timer_stop_again_in_timeout();

	return 0;
}
