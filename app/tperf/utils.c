/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sched.h>

#include "tperf.h"

static int spawn_thread(void *(*func)(void *), void *arg, int cpu)
{
	pthread_t tid;

	if (pthread_create(&tid, NULL, func, arg) < 0) {
		fprintf(stderr, "err_spawn_thread: %s\n", strerror(errno));
		exit(1);
	}

	if (cpu >= 0) {
		cpu_set_t cpuset;

		CPU_ZERO(&cpuset);
		CPU_SET(cpu, &cpuset);
		if (pthread_setaffinity_np(tid, sizeof(cpu_set_t), &cpuset)) {
			fprintf(stderr, "warn: failed to bind to cpu %d: %s\n",
				cpu, strerror(cpu));
		}
	}

	return 0;
}

int spawn_test_threads(void *(*func)(void *))
{
	struct test_thread *thread;
	int i;

	if (tpa_init(ctx.nr_thread) < 0) {
		fprintf(stderr, "err_tpa_init: failed to init tcp stack: %s\n", strerror(errno));
		exit(1);
	}

	ctx.threads = zmalloc_assert(ctx.nr_thread * sizeof(struct test_thread));
	ctx.stats = zmalloc_assert(ctx.nr_thread * sizeof(struct thread_stats));

	for (i = 0; i < ctx.nr_thread; i++) {
		thread = &ctx.threads[i];

		thread->id = i;
		thread->mbuf_pool = mbuf_pool_create();
		thread->stats = &ctx.stats[i];

		/* 10m is the max sock count tpa supports so far */
		thread->sid_mappings = zmalloc_assert(10 * 1024 * 1024 * sizeof(struct connection *));

		TAILQ_INIT(&thread->event_queue);
		TAILQ_INIT(&thread->conn_list);

		spawn_thread(func, thread, ctx.start_cpu + i);
	}

	return 0;
}

void *zmalloc_assert(int size)
{
	void *addr;

	addr = malloc(size);
	assert(addr != NULL);

	memset(addr, 0, size);

	return addr;
}
