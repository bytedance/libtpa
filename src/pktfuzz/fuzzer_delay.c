/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <unistd.h>

#include <rte_cycles.h>

#include "pktfuzz.h"
#include "worker.h"

/*
 * XXX: re-use tcp.ts_raw as we have no more space for storing the
 * tx timpstamp
 */
#define _tx_at			tcp.ts_raw
#define MAX_DELAY		(1e6 * 10)	/* 10s */

TAILQ_HEAD(delayed_packet_list, packet);
static struct delayed_packet_list delayed_pkts = TAILQ_HEAD_INITIALIZER(delayed_pkts);

static inline int get_delay_usec(struct fuzz_num *usec, int max)
{
	if (usec->random)
		return (rte_rdtsc() / 3) % max;

	return RTE_MIN(usec->num, max);
}

static inline void do_delay(struct port_txq *txq, struct fuzz_delay_cfg *delay)
{
	/*
	 * need do copy here as we chain delayed pkts, which could not
	 * handle pkt retrans well.
	 */
	struct packet *pkt = pktfuzz_packet_copy(txq->pkts[txq->nr_pkt - 1]);
	int delay_usec;

	if (!pkt)
		return;

	delay_usec = get_delay_usec(&delay->usec, MAX_DELAY);
	pkt->_tx_at = TSC_TO_US(rte_rdtsc()) + delay_usec;
	TAILQ_INSERT_TAIL(&delayed_pkts, pkt, node);

	packet_free(txq->pkts[--txq->nr_pkt]);
	delay->stats.total += 1;
}

static void delay_fuzz(struct port_txq *txq)
{
	struct fuzz_delay_cfg *delay = &fuzz_cfg.delay;

	if (!delay->enabled)
		return;

	if (meet_rate(&delay->rate))
		do_delay(txq, delay);
}

static void delay_run(struct port_txq *txq)
{
	struct packet *pkt;
	uint64_t now = TSC_TO_US(rte_rdtsc());

	while (1) {
		pkt = TAILQ_FIRST(&delayed_pkts);
		if (!pkt)
			break;

		if (now < pkt->_tx_at)
			break;

		if (txq->nr_pkt >= TXQ_BUF_SIZE)
			break;

		TAILQ_REMOVE(&delayed_pkts, pkt, node);
		txq->pkts[txq->nr_pkt++] = pkt;
	}
}

static void delay_stats(struct shell_buf *reply, struct fuzz_cfg *fuzz_cfg)
{
	struct fuzz_delay_cfg *delay = &fuzz_cfg->delay;

	shell_append_reply(reply,
			   "delay:\n"
			   "\tenabled: %d\n"
			   RATE_FMT
			   "\tdelay: %s\n"
			   "\tstats.total: %lu\n",
			   delay->enabled,
			   RATE_ARGS(&delay->rate),
			   num_to_str(&delay->usec),
			   delay->stats.total);
}

static void delay_help(struct shell_buf *reply, struct fuzz_cfg *fuzz_cfg)
{
	shell_append_reply(reply,
			  "delay         put some delays to packets\n"
			  "  -r rate     specify the delay rate\n"
			  "  -n num      specify the delay duration in usec\n");
}

static int delay_parse(struct fuzz_opt *opts)
{
	struct fuzz_delay_cfg *delay = &opts->fuzz_cfg->delay;
	int enabled = 0;
	int opt;

	memset(delay, 0, sizeof(*delay));

	while ((opt = getopt(opts->argc, opts->argv, "r:n:")) != -1) {
		switch (opt) {
		case 'r':
			parse_rate(&delay->rate, optarg);
			enabled = 1;
			break;

		case 'n':
			if (parse_num(&delay->usec, optarg, NUM_TYPE_TIME_US) < 0) {
				shell_append_reply(opts->reply, "invalid num: %s\n", optarg);
				return -1;
			}
			break;

		default:
			shell_append_reply(opts->reply, "invalid arg: %c\n", opt);
			return -1;
		}
	}

	if (!num_given(&delay->usec))
		delay->usec.num = 1;

	delay->enabled = enabled;

	return 0;
}

const struct fuzzer fuzzer_delay = {
	.name   = "delay",
	.fuzz   = delay_fuzz,
	.run    = delay_run,
	.parse  = delay_parse,
	.stats  = delay_stats,
	.help   = delay_help,
};
