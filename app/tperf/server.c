/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>

#include "tperf.h"

void init_server_conn(struct connection *conn)
{
	int message_size = conn->info.message_size;

	conn->test = conn->info.test;
	conn->integrity_enabled = conn->info.integrity_enabled;
	conn->integrity_off = conn->info.integrity_off;;
	conn->enable_zwrite = conn->info.enable_zwrite;
	conn->message_size = message_size;

	switch (conn->test) {
	case TEST_READ:
		conn->read.budget  = 0;
		conn->write.budget = message_size;
		event_queue_add(conn, TPA_EVENT_OUT);
		break;

	case TEST_WRITE:
		conn->read.budget  = message_size;
		conn->write.budget = 0;
		break;

	case TEST_RW:
		event_queue_add(conn, TPA_EVENT_OUT);
		conn->write.budget = message_size;
		conn->read.budget  = message_size;
		break;

	case TEST_RR:
	case TEST_CRR:
		conn->read.budget  = message_size;
		conn->write.budget = 0; /* write only after we got the req */
		break;
	}
}

static void start_server(void)
{
	struct tpa_sock_opts opts;
	int sid;

	memset(&opts, 0, sizeof(opts));
	opts.listen_scaling = 1;

	sid = tpa_listen_on(ctx.local, ctx.port, &opts);
	if (sid < 0) {
		fprintf(stderr, "failed to listen on port %hu\n", ctx.port);
		exit(1);
	}
}

static void accept_socks(struct test_thread *thread)
{
	int sid[BATCH_SIZE];
	int nr_sock;
	int i;

	nr_sock = tpa_accept_burst(thread->worker, sid, BATCH_SIZE);
	for (i = 0; i < nr_sock; i++)
		conn_create(thread, sid[i]);
}

static void *server_thread_loop(void *arg)
{
	struct test_thread *thread = arg;
	struct tpa_worker *worker;

	worker = tpa_worker_init();
	if (!worker) {
		fprintf(stderr, "failed to init worker: %s\n", strerror(errno));
		return NULL;
	}
	thread->worker = worker;

	if (thread->id == 0)
		start_server();

	while (1) {
		tpa_worker_run(thread->worker);

		accept_socks(thread);

		poll_and_process(thread);
	}

	return NULL;
}

int tperf_server(void)
{
	spawn_test_threads(server_thread_loop);

	while (1)
		sleep(1);

	return 0;
}
