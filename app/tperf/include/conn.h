/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _CONN_H_
#define _CONN_H_

/*
 * 1000 is really handy for tcp debugging; note that the default message
 * is 1 byte for rr and crr test.
 */
#define DEFAULT_MESSAGE_SIZE		1000
#define DEFAULT_DURATION		10
#define DEFAULT_NR_THREAD		1

struct test_info {
	uint32_t test;
	uint32_t message_size;
	uint32_t integrity_enabled:1;
	uint32_t enable_zwrite:1;
	uint32_t integrity_off;
} __attribute__((__aligned__(64)));

struct latency {
	uint64_t count;
	uint64_t min;
	uint64_t max;
	uint64_t sum;

	uint64_t last_ns;
};

struct rw_stats {
	uint64_t bytes_read;
	uint64_t bytes_write;
} __attribute__((__aligned__(64)));

struct connection {
	struct test_thread *thread;

	int sid;
	int refcnt;
	int to_close;
	int is_client;

	int test;
	int message_size;
	int enable_zwrite;
	int integrity_enabled;
	uint32_t integrity_off;

	struct {
		size_t off;
		size_t budget;
	} read;

	/*
	 * Here we use the write.budget to control how much we should
	 * write each time.
	 *
	 * For example, for RR/CRR test, we set write.budget to the
	 * message size at the beginning. We then set it to 0 once we
	 * have done the write to disable the futher write.
	 *
	 * Note that the read.budget doesn't really do any control job;
	 * it's just for telling us whether we have read the full request
	 * or not.
	 */
	struct {
		size_t off;
		size_t budget;
	} write;

	uint64_t last_ns;
	struct rw_stats stats;

	int in_event_queue;
	uint32_t events;
	TAILQ_ENTRY(connection) node;

	uint32_t info_off;
	union {
		struct test_info info;
		char info_raw[sizeof(struct test_info)];
	};

	TAILQ_ENTRY(connection) thread_node;
};

TAILQ_HEAD(event_queue, connection);
TAILQ_HEAD(conn_list, connection);

static inline struct connection *conn_get(struct connection *conn)
{
	conn->refcnt += 1;
	return conn;
}

static inline void conn_put(struct connection *conn)
{
	assert(conn->refcnt >= 1);

	conn->refcnt -= 1;
	if (conn->refcnt == 0)
		free(conn);
}

struct connection *conn_create(struct test_thread *thread, int sid);
void conn_close(struct connection *conn);

int conn_on_read(struct connection *conn);
int conn_on_write(struct connection *conn);

#endif
