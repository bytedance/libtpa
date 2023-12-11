/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <sys/mman.h>

#include "test_utils.h"

static int quit;

static void test_tsock_trace_basic(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	int i;

	printf("testing tsock_trace [basic] ...\n");

	tsock = ut_tcp_connect();

	for (i = 0; i < 10; i++) {
		pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt + i, 1);

		parse_tcp_packet(pkt);
		tsock_trace_rcv_pkt(tsock, pkt, worker->ts_us);

		packet_free(pkt);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tsock_trace_after_close(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	int sid;

	printf("testing tsock_trace [after close] ...\n");

	tsock = ut_tcp_connect();
	sid = tsock->sid;

	ut_close(tsock, CLOSE_TYPE_4WAY);

	pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt, 10); {
		pkt->mbuf.ol_flags |= PKT_RX_FDIR_ID;
		pkt->mbuf.hash.fdir.hi = make_flow_mark(0, sid);

		ut_tcp_input_one(tsock, pkt);
	}
}

static void test_tsock_trace_wrap(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	int i;

	printf("testing tsock_trace [trace buffer wrap] ...\n");

	tsock = ut_tcp_connect();

	for (i = 0; i < 10; i++) {
		pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt + i, 1);

		if (i & 1)
			cycles_update_begin(worker);
		parse_tcp_packet(pkt);
		tsock_trace_rcv_pkt(tsock, pkt, worker->ts_us);

		packet_free(pkt);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tsock_trace_mem_consumption(void)
{
	struct tcp_sock *tsock;
	char cmd[PATH_MAX];
	int size = 1<<30;
	FILE *file;
	int i;

	printf("testing tsock_trace [mem consumption] ...\n");


	for (i = 0; i < tcp_cfg.nr_max_sock; i++) {
		tsock = ut_tcp_connect();
		ut_close(tsock, CLOSE_TYPE_4WAY);
	}

	tpa_snprintf(cmd, sizeof(cmd), "du -sh -BM %s/trace", tpa_root_get());
	file = popen(cmd, "r");
	fscanf(file, "%dM", &size);
	pclose(file);

	assert(size <= 30);
}


#define NR_THREAD		4

#define TRACE_GET_COUNT		1000

static void *do_trace_create(void *sid)
{
	struct tcp_sock tsock;
	int i;
	int count = TRACE_GET_COUNT + *(int *)sid;

	tsock.trace = NULL;
	while (!quit) {
		for (i = *(int *)sid; i < count; ++i) {
			tsock.sid = i;
			tsock_trace_init(&tsock, i);
			assert(tsock.trace != NULL);
			tsock_trace_uninit(&tsock);
			assert(tsock.trace == NULL);
		}
	}

	return NULL;
}

static void test_tsock_trace_multi_thread(void)
{
	pthread_t tids[NR_THREAD];
	int arg[NR_THREAD];
	int i;

	printf("testing tsock_trace [multi-thread] ...\n");

	for (i = 0; i < NR_THREAD; i++) {
		arg[i] = TRACE_GET_COUNT * i;
		ut_spawn_thread(&tids[i], do_trace_create, &arg[i]);
	}

	sleep(5);

	quit = 1;
	for (i = 0; i < NR_THREAD; i++)
		pthread_join(tids[i], NULL);
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	ut_test_opts.silent = 1;
	test_tsock_trace_mem_consumption();
	test_tsock_trace_multi_thread();
	ut_test_opts.silent = 0;

	test_tsock_trace_basic();
	test_tsock_trace_after_close();
	test_tsock_trace_wrap();

	return 0;
}
