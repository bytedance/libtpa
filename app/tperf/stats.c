/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <time.h>

#include "tperf.h"

#define NR_TEST		(int)(sizeof(tperf_tests) / sizeof(tperf_tests[0]))

static const char *tperf_tests[] = {
	[TEST_READ]  = "read",
	[TEST_WRITE] = "write",
	[TEST_RW]    = "rw",
	[TEST_CRR]   = "crr",
	[TEST_RR]    = "rr",
};

static const char *tperf_tests_short[] = {
	[TEST_READ]  = "R",
	[TEST_WRITE] = "W",
	[TEST_RW]    = "RW",
	[TEST_CRR]   = "CR",
	[TEST_RR]    = "RR",
};

static inline const char *test_to_str(int test)
{
	if (test < 0 || test >= NR_TEST)
		return "unknown";

	return tperf_tests[test];
}

static const char *test_to_str_short(int test)
{
	if (test < 0 || test >= NR_TEST)
		return "NA";

	return tperf_tests_short[test];
}

int str_to_test(const char *str)
{
	int i;

	for (i = 0; i < NR_TEST; i++) {
		if (strcmp(tperf_tests[i], str) == 0)
			return i;
	}

	return -1;
}

#define to_Gbs(x)		((double)(x) * 8 / 1e9)
#define to_us(x)		((double)(x) / 1000)

uint64_t get_time_in_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);

	return ts.tv_sec * 1e9 + ts.tv_nsec;
}

void update_latency(struct connection *conn)
{
	struct latency *latency = &conn->thread->stats->latency;
	uint64_t now = get_time_in_ns();
	uint64_t delta = now - conn->last_ns;

	if (delta < latency->min || latency->min == 0)
		latency->min = delta;
	if (delta > latency->max)
		latency->max = delta;

	latency->count += 1;
	latency->sum += delta;

	conn->last_ns = now;
}

static void show_rr_stats(int loop, struct thread_stats *last_stats)
{
	uint64_t count;
	uint64_t sum;
	int i;

	for (i = 0; i < ctx.nr_thread; i++) {
		count = ctx.stats[i].latency.count - last_stats[i].latency.count;
		sum   = ctx.stats[i].latency.sum   - last_stats[i].latency.sum;

		printf("%5d %-2s .%d min=%.2fus avg=%.2fus max=%.2fus count=%lu\n",
		       loop, test_to_str_short(ctx.test), i,
		       to_us(ctx.stats[i].latency.min),
		       to_us(sum / (count ? : -1ull)),
		       to_us(ctx.stats[i].latency.max),
		       count);

		/* reset here; though we may have race condition issue */
		ctx.stats[i].latency.min = 0;
		ctx.stats[i].latency.max = 0;
	}
}

static void show_rw_stats(int loop, struct thread_stats *last_stats)
{
	struct rw_stats stats[ctx.nr_thread];
	struct rw_stats total;
	int i;

	memset(&total, 0, sizeof(total));
	for (i = 0; i < ctx.nr_thread; i++) {
		stats[i].bytes_read  = ctx.stats[i].rw_stats.bytes_read  - last_stats[i].rw_stats.bytes_read;
		stats[i].bytes_write = ctx.stats[i].rw_stats.bytes_write - last_stats[i].rw_stats.bytes_write;
		total.bytes_read  += stats[i].bytes_read;
		total.bytes_write += stats[i].bytes_write;
	}

	for (i = 0; i < ctx.nr_thread && ctx.nr_thread > 1; i++) {
		printf("%7d %-2s %3d. %.3f read Gbits/sec  %.3f write Gbits/sec\n",
		       loop, test_to_str_short(ctx.test), i,
		       to_Gbs(stats[i].bytes_read), to_Gbs(stats[i].bytes_write));
	}

	printf("%7d %-7s %.3f read Gbits/sec  %.3f write Gbits/sec\n",
		loop, test_to_str_short(ctx.test),
		to_Gbs(total.bytes_read),
		to_Gbs(total.bytes_write));
}

static void do_show_stats(int loop, struct thread_stats *last_stats)
{
	if (ctx.test == TEST_RR || ctx.test == TEST_CRR)
		show_rr_stats(loop, last_stats);
	else
		show_rw_stats(loop, last_stats);

	if (ctx.nr_thread > 1)
		printf("\n");
}

void show_stats(void)
{
	struct thread_stats last_stats[ctx.nr_thread];
	int loop = 0;
	int i;

	memset(last_stats, 0, sizeof(last_stats));
	do {
		sleep(1);

		if (!ctx.quiet) {
			do_show_stats(loop++, last_stats);
			memcpy(&last_stats, ctx.stats, sizeof(last_stats));
		}
	} while (--ctx.duration);

	printf("\n---\n");
	for (i = 0; i < ctx.nr_thread; i++) {
		printf("%2d nr_conn=%lu nr_zero_io_conn=%lu\n",
			i, ctx.stats[i].nr_conn_total, ctx.stats[i].nr_zero_io_conn);
	}
}
