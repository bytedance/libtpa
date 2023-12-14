/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <sched.h>
#include <sys/syscall.h>

#include <rte_malloc.h>

#include "tpa.h"
#include "worker.h"
#include "neigh.h"
#include "cfg.h"
#include "sock.h"
#include "log.h"
#include "shell.h"
#include "tcp.h"

struct tpa_worker *workers;
__thread struct tpa_worker *tls_worker;
static uint32_t next_worker;

static const struct shell_cmd worker_cmd;

static int init_one_worker(struct tpa_worker *worker, uint8_t id)
{
	uint64_t now;

	worker->id = id;
	worker->queue = id;

	worker->output      = flex_fifo_create(BATCH_SIZE * 2);
	worker->delayed_ack = flex_fifo_create(BATCH_SIZE * 2);
	worker->event_queue = flex_fifo_create(BATCH_SIZE * 2);
	worker->accept      = flex_fifo_create(BATCH_SIZE * 2);
	worker->neigh_flush_queue = flex_fifo_create(BATCH_SIZE * 2);
	PANIC_ON(worker->output == NULL || worker->delayed_ack == NULL ||
		 worker->event_queue == NULL || worker->accept == NULL ||
		 worker->neigh_flush_queue == NULL,
		 "failed to create worker %d output/event/accept/neigh fifo", id);

	worker->tx_desc_pool = tx_desc_pool_create(TX_DESC_COUNT_PER_WORKER);
	if (!worker->tx_desc_pool)
		return -1;

	now = rte_rdtsc();
	worker->cycles.start = now;
	worker->cycles.end   = now;
	worker->ts_us = TSC_TO_US(now);
	timer_ctrl_init(&worker->timer_ctrl, worker->ts_us);

	sock_table_init(&worker->sock_table);

	if (packet_pool_create(&worker->zwrite_pkt_pool, 25.0 / tpa_cfg.nr_worker,
			       0, "zwrite-mbuf-mp-%d", worker->id) < 0)
		return -1;

	return packet_pool_create(&worker->hdr_pkt_pool, 12.5 / tpa_cfg.nr_worker,
				  RTE_PKTMBUF_HEADROOM, "hdr-mbuf-mp-%d", worker->id);
}

int worker_init(uint32_t nr_worker)
{
	size_t size;
	uint8_t i;

	tpa_cfg.hz = rte_get_tsc_hz();

	size = sizeof(struct tpa_worker) * nr_worker;
	workers = rte_malloc(NULL, size, 64);
	PANIC_ON(workers == NULL, "failed to allocate %u workers", nr_worker);

	tpa_cfg.nr_worker = nr_worker;
	tpa_cfg.nr_worker_shift = log2_ceil(nr_worker);
	tpa_cfg.nr_worker_mask = (1 << tpa_cfg.nr_worker_shift) - 1;


	memset(workers, 0, size);
	for (i = 0; i < nr_worker; i++) {
		if (init_one_worker(&workers[i], i) < 0)
			return -1;
	}

	shell_register_cmd(&worker_cmd);

	return 0;
}

static int flush_neigh_queue(struct tpa_worker *worker)
{
	if (likely(flex_fifo_count(worker->neigh_flush_queue) == 0))
		return 0;

	return neigh_flush(worker);
}

static inline int tcp_input_process(struct tpa_worker *worker)
{
	uint32_t nr_pkt = 0;
	uint32_t i;

	for (i = 0; i < dev.nr_port; i++) {
		dev_port_rxq_recv(i, worker->queue);
		nr_pkt += tcp_input(worker, i);
	}

	return nr_pkt;
}

static inline int tcp_output_process(struct tpa_worker *worker)
{
	uint32_t nr_tsock;
	int i;

	nr_tsock = tcp_output(worker);

	for (i = 0; i < dev.nr_port; i++) {
		pktfuzz_run(dev_port_txq(i, worker->queue));
	}

	dev_txq_flush(worker->queue);

	return nr_tsock;
}

struct tpa_worker *tpa_worker_init(void)
{
	struct tpa_worker *worker;
	uint32_t id;

	if (tls_worker) {
		LOG_ERR("worker %d has already been initialized", tls_worker->id);
		return NULL;
	}

	id = __sync_fetch_and_add_4(&next_worker, 1);
	if (id >= tpa_cfg.nr_worker) {
		LOG_ERR("too many worker initialization");
		return NULL;
	}

	/*
	 * The typical usage of libtpa doesn't involve DPDK threads.
	 * Therefore, the per thread lcore_id is not set. However we
	 * need set it correct to enable mbuf cache: that's what
	 * the following dirty hack for.
	 */
	RTE_PER_LCORE(_lcore_id) = id;

	worker = &workers[id];
	worker->tid = syscall(SYS_gettid);

	tls_worker = worker;

	return worker;
}

static __rte_noinline void do_drop_ooo_mbufs(struct tpa_worker *worker)
{
	struct sock_entry_list *list;
	struct sock_entry *entry;
	int i;

	for (i = 0; i < SOCK_TABLE_SIZE; i++) {
		list = &worker->sock_table.lists[i];

		TAILQ_FOREACH(entry, list, node) {
			tsock_drop_ooo_mbufs(entry->tsock);
		}
	}
}

static inline void drop_ooo_mbufs(struct tpa_worker *worker)
{
	if (unlikely(too_many_used_mbufs(worker)))
		do_drop_ooo_mbufs(worker);
}

void tpa_worker_run(struct tpa_worker *worker)
{
	int busy = 0;

	cycles_update_begin(worker);

	busy += flush_neigh_queue(worker);

	busy += timer_process(&worker->timer_ctrl, worker->ts_us);
	busy += tcp_input_process(worker);
	busy += tcp_output_process(worker);

	drop_ooo_mbufs(worker);

	cycles_update_end(worker, busy);
}

static void print_stats(struct shell_buf *reply, uint64_t *stats)
{
	int i;

	for (i = 0; i < STATS_MAX; i++) {
		if (stats[i])
			shell_append_reply(reply, "\t%-32s: %lu\n", stats_name(i), stats[i]);
	}
}

#define _US(cycles)                     ((double)(cycles) / (tpa_cfg.hz / 1e6))

static void dump_worker(struct tpa_worker *worker, struct shell_buf *reply, int reset_starvation)
{
	int i;
	char buf[128];

	shell_append_reply(reply, "worker %d (%p)\n", worker->id, worker);

	shell_append_reply(reply, "\t%-32s: %u\n"
				  "\t%-32s: %lu\n"
				  "\t%-32s: %lu\n"
				  "\t%-32s: %lu\n"
				  "\t%-32s: %.6fs ago\n"
				  "\t%-32s: %.6fs ago\n"
				  "\t%-32s: %.1fus\n"
				  "\t%-32s: %.1fus\n"
				  "\t%-32s: %.3fms\n"
				  "\t%-32s: %.3fms\n"
				  "\t%-32s: %u\n"
				  "\t%-32s: %lu\n"
				  "\t%-32s: %hu\n"
				  "\t%-32s: %u\n"
				  "\t%-32s: %u\n"
				  "\t%-32s: %u\n",
			   "tid", worker->tid,
			   "cycles.busy", worker->cycles.busy,
			   "cycles.outside_worker", worker->cycles.outside_worker,
			   "cycles.total", worker->cycles.total,
			   "last_run",  (double)TSC_TO_US(TS_DIFF(rte_rdtsc(), worker->cycles.end)) / 1e6,
			   "last_poll", (double)TSC_TO_US(TS_DIFF(rte_rdtsc(), worker->cycles.start)) / 1e6,
			   "avg_runtime", _US(vstats_avg(&worker->runtime)),
			   "avg_starvation", _US(vstats_avg(&worker->starvation)),
			   "max_runtime", _US(worker->runtime.max) / 1e3,
			   "max_starvation", _US(worker->starvation.max) / 1e3,
			   "nr_tsock", worker->nr_tsock,
			   "nr_tsock_total", worker->nr_tsock_total,
			   "dev_txq.size", TXQ_BUF_SIZE,
			   "nr_ooo_mbuf", worker->nr_ooo_mbuf,
			   "nr_in_process_mbuf", worker->nr_in_process_mbuf,
			   "nr_write_mbuf", worker->nr_write_mbuf);

	for (i = 0; i < dev.nr_port; i++) {
		tpa_snprintf(buf, sizeof(buf), "dev_txq[%d].nr_pkt", i);
		shell_append_reply(reply, "\t%-32s: %hu\n", buf, dev_port_txq(i, worker->queue)->nr_pkt);
	}

	for (i = 0; i < dev.nr_port; i++) {
		tpa_snprintf(buf, sizeof(buf), "dev_rxq[%d].nr_pkt", i);
		shell_append_reply(reply, "\t%-32s: %u\n", buf,
				   dev_port_rxq(i, worker->queue)->write - dev_port_rxq(i, worker->queue)->read);
	}

	if (reset_starvation)
		worker->starvation.max = 0;

	print_stats(reply, worker->stats_base);
}

static int cmd_worker(struct shell_cmd_info *cmd)
{
	struct tpa_worker *worker;
	int i;
	int reset_starvation = 0;

	if (cmd->argc == 1 && strcmp(cmd->argv[0], "--reset-starvation") == 0)
		reset_starvation = 1;

	for (i = 0; i < tpa_cfg.nr_worker; i++) {
		worker = &workers[i];
		if (!worker)
			continue;

		dump_worker(worker, cmd->reply, reset_starvation);
	}

	return 0;
}

static const struct shell_cmd worker_cmd = {
	.name    = "worker",
	.handler = cmd_worker,
};
