/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _TPERF_H_
#define _TPERF_H_

#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <sys/queue.h>

#include <tpa.h>

#include "conn.h"
#include "mbuf.h"

#define MIN(a, b)		((a) < (b) ? (a) : (b))

#define TPERF_PORT			4096
#define BATCH_SIZE			64

enum {
	TEST_READ,
	TEST_WRITE,
	TEST_RR,
	TEST_CRR,
	TEST_RW,
};

struct thread_stats {
	struct rw_stats rw_stats;
	struct latency latency;

	uint64_t nr_conn_total;
	uint64_t nr_zero_io_conn;
};

struct test_thread {
	int id;
	struct tpa_worker *worker;

	struct thread_stats *stats;

	uint64_t nr_conn;
	struct conn_list conn_list;

	struct mbuf_pool *mbuf_pool;
	struct fifo *stats_fifo;
	struct connection **sid_mappings;

	uint32_t nr_event;
	struct event_queue event_queue;
} __attribute__((__aligned__(64)));

struct ctx {
	char *local;
	char *server;
	int is_client;
	int test;
	int duration;
	int message_size;
	int nr_thread;
	int nr_conn_per_thread;
	int start_cpu;
	int integrity_enabled;
	int enable_tso;
	int enable_zwrite;
	int port;
	int quiet;

	struct test_thread *threads;
	struct thread_stats *stats;
};

extern struct ctx ctx;

static inline void event_queue_add(struct connection *conn, uint32_t events)
{
	struct test_thread *thread = conn->thread;

	conn->events |= events;

	if (conn->in_event_queue == 0) {
		conn->in_event_queue = 1;
		thread->nr_event += 1;
		TAILQ_INSERT_TAIL(&thread->event_queue, conn, node);
	}
}

static inline struct connection *event_queue_pop(struct test_thread *thread)
{
	struct connection *conn;

	conn = TAILQ_FIRST(&thread->event_queue);

	if (conn) {
		TAILQ_REMOVE(&thread->event_queue, conn, node);
		conn->in_event_queue = 0;
		thread->nr_event -= 1;
	}

	return conn;
}

#define UPDATE_STATS(conn, field, val)		do {	\
	(conn)->stats.field += val;			\
	(conn)->thread->stats->rw_stats.field += val;	\
} while (0)

int tperf_client(void);
int tperf_server(void);
void init_server_conn(struct connection *conn);

/* stats.c */
uint64_t get_time_in_ns(void);
void update_latency(struct connection *conn);
int str_to_test(const char *str);
void show_stats(void);

/* event.c */
int poll_and_process(struct test_thread *thread);

/* options.c */
int parse_options(int argc, char **argv);

/* integrity.c */
void integrity_init(void);
void integrity_fill(char *buf, size_t size, uint64_t base);
int integrity_verify(char *buf, size_t size, uint64_t base);

/* utils.c */
void *zmalloc_assert(int size);
int spawn_test_threads(void *(*func)(void *));

#endif
