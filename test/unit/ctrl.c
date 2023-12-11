/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022, ByteDance Ltd. and/or its Affiliates
 * Author: Wenlong Luo <luowenlong.linl@bytedance.com>
 */
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <sys/eventfd.h>

#include "test_utils.h"
#include "ctrl.h"

static int ctrl_done = 0;

static void *ctrl_event_done(struct ctrl_event *event)
{
	uint64_t val;
	int fd = *(int *)event->arg;

	ctrl_done += 1;
	read(fd, &val, sizeof(val));

	return NULL;
}

static void test_ctrl_event(void)
{
	int fd;
	uint64_t val = 1;

	printf("testing ctrl event ...\n");

	ctrl_done = 0;
	fd = eventfd(0, 0);
	ctrl_event_create(fd, ctrl_event_done, &fd, "test-ctrl-event");

	write(fd, &val, sizeof(val)); {
		sleep(1);
		assert(ctrl_done == 1);
	}

	write(fd, &val, sizeof(val)); {
		sleep(1);
		assert(ctrl_done == 2);
	}
}

static int ctrl_timeout_done = 0;

static void *ctrl_timeout_event_done(struct ctrl_event *event)
{
	ctrl_timeout_done += 1;
	return NULL;
}

static void test_ctrl_timeout_event(void)
{
	printf("testing ctrl timeout event ...\n");

	ctrl_timeout_event_create(1, ctrl_timeout_event_done, NULL, "test-ctrl-timeout-event");

	sleep(2);
	assert(ctrl_timeout_done >= 1);
}

static void *test_shell_exec(void *arg)
{
	WHILE_NOT_TIME_UP() {
		/* make sure we function well with an invalid cmd */
		system("tpa cfg hello > /dev/null 2>&1");

		system("tpa mem       > /dev/null 2>&1");
		system("tpa worker    > /dev/null 2>&1");
	}

	return NULL;
}

static void *test_stack_overwrite(struct ctrl_event *event)
{
	uint64_t stack[131072];		// 131072 * 8 = 1MB
	uint64_t i;

	for (i = 0; i < 131072; i++)
		stack[i] = 0xfff1fff1fff1fff1;

	/* avoid being optimized by gcc */
	for (i = 0; i < 131072; i++)
		assert(stack[i] == 0xfff1fff1fff1fff1);

	return NULL;
}

static void test_ctrl_multi_event_stress(void)
{
	pthread_t tid;

	printf("testing ctrl multi event stress ...\n");

	ut_spawn_thread(&tid, test_shell_exec, NULL);
	ctrl_timeout_event_create(1, test_stack_overwrite, NULL, "test-stack-overwrite");

	pthread_join(tid, NULL);
}

int main(int argc, char **argv)
{
	ut_init(argc, argv);

	test_ctrl_event();
	test_ctrl_timeout_event();
	test_ctrl_multi_event_stress();
}
