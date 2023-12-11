/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>

#include "tperf.h"

struct connection *conn_create(struct test_thread *thread, int sid)
{
	struct connection *conn = zmalloc_assert(sizeof(struct connection));
	struct tpa_event event;

	event.events = TPA_EVENT_IN | TPA_EVENT_OUT;
	event.data = conn;
	tpa_event_ctrl(sid, TPA_EVENT_CTRL_ADD, &event);

	conn->sid = sid;
	conn->thread = thread;

	TAILQ_INSERT_TAIL(&thread->conn_list, conn, thread_node);
	thread->sid_mappings[sid] = conn;
	thread->nr_conn += 1;
	thread->stats->nr_conn_total += 1;

	return conn_get(conn);
}

void conn_close(struct connection *conn)
{
	struct test_thread *thread = conn->thread;

	if (conn->stats.bytes_read == 0 && conn->stats.bytes_write == 0)
		thread->stats->nr_zero_io_conn += 1;

	TAILQ_REMOVE(&thread->conn_list, conn, thread_node);
	thread->sid_mappings[conn->sid] = NULL;
	thread->nr_conn -= 1;

	tpa_event_ctrl(conn->sid, TPA_EVENT_CTRL_DEL, NULL);
	tpa_close(conn->sid);

	conn_put(conn);
}
