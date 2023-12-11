/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <unistd.h>

#include "pktfuzz.h"
#include "worker.h"

static inline void swap_packet(struct packet **a, struct packet **b)
{
	struct packet *tmp;

	tmp = *a;
	*a = *b;
	*b = tmp;
}

static inline void do_reorder(struct dev_txq *txq, struct fuzz_reorder_cfg *reorder)
{
	if (txq->nr_pkt < 2)
		return;

	swap_packet(&txq->pkts[0], &txq->pkts[txq->nr_pkt - 1]);
	reorder->stats.reordered += 1;
}

static void reorder_fuzz(struct dev_txq *txq)
{
	struct fuzz_reorder_cfg *reorder = &fuzz_cfg.reorder;

	if (!reorder->enabled)
		return;

	if (meet_rate(&reorder->rate))
		do_reorder(txq, reorder);
}

static void reorder_stats(struct shell_buf *reply, struct fuzz_cfg *fuzz_cfg)
{
	struct fuzz_reorder_cfg *reorder = &fuzz_cfg->reorder;

	shell_append_reply(reply,
			   "reorder:\n"
			   "\tenabled: %d\n"
			   RATE_FMT
			   "\treordered: %lu\n",
			   reorder->enabled,
			   RATE_ARGS(&reorder->rate),
			   reorder->stats.reordered);
}

static void reorder_help(struct shell_buf *reply, struct fuzz_cfg *fuzz_cfg)
{
	shell_append_reply(reply,
			  "reorder       reorder packets\n"
			  "  -r rate     specify the reordering rate\n"
			  "  -m mode     specify the reordering mode (not supported yet)\n");
}

static int reorder_parse(struct fuzz_opt *opts)
{
	struct fuzz_reorder_cfg *reorder = &opts->fuzz_cfg->reorder;
	int opt;
	int enabled = 0;

	while ((opt = getopt(opts->argc, opts->argv, "r:m")) != -1) {
		switch (opt) {
		case 'r':
			parse_rate(&reorder->rate, optarg);
			enabled = 1;
			break;

		case 'm':
			break;

		default:
			shell_append_reply(opts->reply, "invalid arg: %c\n", opt);
			return -1;
		}
	}

	memset(&reorder->stats, 0, sizeof(reorder->stats));

	reorder->enabled = enabled;

	return 0;
}

const struct fuzzer fuzzer_reorder = {
	.name   = "reorder",
	.fuzz   = reorder_fuzz,
	.parse  = reorder_parse,
	.stats  = reorder_stats,
	.help   = reorder_help,
};
