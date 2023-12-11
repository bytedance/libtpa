/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _WORKER_H_
#define _WORKER_H_

#include <stdint.h>

#include "cfg.h"
#include "sock.h"
#include "stats.h"
#include "timer.h"
#include "pktfuzz.h"
#include "dev.h"
#include "port_alloc.h"
#include "tx_desc.h"

struct cycles {
	uint64_t start;
	uint64_t end;
	uint64_t total;
	uint64_t busy;
	uint64_t outside_worker;
	uint64_t last_poll;
};

#define TX_DESC_COUNT_PER_WORKER		(128 * 1024)

struct tpa_worker {
	uint8_t id;

	uint16_t queue;
	uint32_t nr_ooo_mbuf;
	uint32_t nr_in_process_mbuf;
	uint32_t nr_write_mbuf;
	uint32_t nr_tsock;
	uint64_t nr_tsock_total;

	uint64_t ts_us;
	struct cycles cycles;
	struct vstats starvation;
	struct vstats runtime;

	struct tx_desc_pool *tx_desc_pool;

	struct packet_pool zwrite_pkt_pool;
	struct packet_pool hdr_pkt_pool;
	struct flex_fifo *event_queue;

	struct tcp_sock *tsocks[BATCH_SIZE];

	struct timer_ctrl timer_ctrl;

	struct flex_fifo *output;
	struct flex_fifo *delayed_ack;
	struct flex_fifo *accept;

	struct flex_fifo *neigh_flush_queue;

	int nr_port_block;
	struct port_block *port_blocks[MAX_PORT_BLOCK_PER_WORKER];
	struct sock_table sock_table;

	uint64_t stats_base[STATS_MAX];

	pid_t tid;
} __rte_cache_aligned;

static inline void tsock_update_last_ts(struct tcp_sock *tsock, int type)
{
	tsock->last_ts[type] = tsock->worker->cycles.start;
}

static inline uint64_t last_ts_in_us(struct tcp_sock *tsock, int type)
{
	return TSC_TO_US(tsock->last_ts[type]);
}

static inline void tsock_event_add(struct tcp_sock *tsock, uint32_t events)
{
	struct tpa_event *event = &tsock->event;

	tsock->last_events = events;
	event->events |= events;
	if (tsock->event.events & tsock->interested_events)
		flex_fifo_push_if_not_exist(tsock->worker->event_queue, &tsock->event_node);
}

static inline void output_tsock_enqueue(struct tpa_worker *worker,
					struct tcp_sock *tsock)
{
	flex_fifo_push_if_not_exist(worker->output, &tsock->output_node);
}

static inline uint32_t output_tsock_dequeue(struct tpa_worker *worker)
{
	struct tcp_sock *tsock;
	uint32_t i;

	for (i = 0; i < BATCH_SIZE; i++) {
		tsock = FLEX_FIFO_POP_ENTRY(worker->output, struct tcp_sock, output_node);
		if (!tsock)
			break;

		worker->tsocks[i] = tsock;
	}

	return i;
}

static inline void accept_tsock_enqueue(struct tpa_worker *worker, struct tcp_sock *tsock)
{
	flex_fifo_push(worker->accept, &tsock->accept_node);
}

static inline void cycles_update_begin(struct tpa_worker *worker)
{
	uint64_t now = rte_rdtsc();
	uint64_t starvation = now - worker->cycles.end;

	worker->cycles.outside_worker += starvation;
	worker->cycles.total          += now - worker->cycles.start;
	vstats_add(&worker->starvation, starvation);

	worker->cycles.start = rte_rdtsc();
	worker->ts_us = TSC_TO_US(worker->cycles.start);
}

static inline void cycles_update_end(struct tpa_worker *worker, int busy)
{
	worker->cycles.end = rte_rdtsc();
	if (busy) {
		worker->cycles.busy += worker->cycles.end - worker->cycles.start;
		vstats_add(&worker->runtime, worker->cycles.end - worker->cycles.start);
	}
}

static inline uint32_t now_in_sec(struct tpa_worker *worker)
{
	return worker->ts_us / 1000000;
}

static inline int too_many_used_mbufs(struct tpa_worker *worker)
{
	uint32_t nr_used_mbuf;

	nr_used_mbuf = worker->nr_ooo_mbuf + worker->nr_in_process_mbuf + worker->nr_write_mbuf;
	return nr_used_mbuf > tcp_cfg.drop_ooo_threshold;
}

extern struct tpa_worker *workers;
extern __thread struct tpa_worker *tls_worker;

int worker_init(uint32_t nr_worker);
struct tpa_worker *tpa_worker_init(void);
void tpa_worker_run(struct tpa_worker *worker);

#endif
