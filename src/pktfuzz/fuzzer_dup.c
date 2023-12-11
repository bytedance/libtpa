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

static inline int get_dup_count(struct fuzz_num *nr_pkt, int max)
{
	if (nr_pkt->random)
		return (rte_rdtsc() / 3) % max;

	return RTE_MIN(nr_pkt->num, max);
}

static inline void do_dup(struct dev_txq *txq, struct fuzz_dup_cfg *dup)
{
	struct packet *pkt = txq->pkts[txq->nr_pkt - 1];
	struct rte_tcp_hdr *tcp = packet_tcp_hdr(pkt);
	int dup_count;
	int i;

	if (dup->syn && (tcp->tcp_flags & RTE_TCP_SYN_FLAG) == 0)
		return;

	dup_count = get_dup_count(&dup->nr_pkt, TXQ_BUF_SIZE - txq->nr_pkt);
	for (i = 0; i < dup_count; i++)
		txq->pkts[txq->nr_pkt++] = pktfuzz_packet_copy(pkt);

	dup->stats.total += dup_count;
}

static void dup_fuzz(struct dev_txq *txq)
{
	struct fuzz_dup_cfg *dup = &fuzz_cfg.dup;

	if (!dup->enabled)
		return;

	if (meet_rate(&dup->rate))
		do_dup(txq, dup);
}

static void dup_stats(struct shell_buf *reply, struct fuzz_cfg *fuzz_cfg)
{
	struct fuzz_dup_cfg *dup = &fuzz_cfg->dup;

	shell_append_reply(reply,
			   "dup:\n"
			   "\tenabled: %d\n"
			   RATE_FMT
			   "\tnr_pkt: %s\n"
			   "\tsyn: %d\n"
			   "\tstats.total: %lu\n",
			   dup->enabled,
			   RATE_ARGS(&dup->rate),
			   num_to_str(&dup->nr_pkt),
			   dup->syn,
			   dup->stats.total);
}

static void dup_help(struct shell_buf *reply, struct fuzz_cfg *fuzz_cfg)
{
	shell_append_reply(reply,
			  "dup           duplicate a packet\n"
			  "  -r rate     specify the duplication rate\n"
			  "  -n num      specify the duplication count\n"
			  "  -s          duplicate syn packets only\n");
}

static int dup_parse(struct fuzz_opt *opts)
{
	struct fuzz_dup_cfg *dup = &opts->fuzz_cfg->dup;
	int enabled = 0;
	int opt;

	memset(dup, 0, sizeof(*dup));

	while ((opt = getopt(opts->argc, opts->argv, "r:n:s")) != -1) {
		switch (opt) {
		case 'r':
			parse_rate(&dup->rate, optarg);
			enabled = 1;
			break;

		case 'n':
			if (parse_num(&dup->nr_pkt, optarg, NUM_TYPE_NONE) < 0) {
				shell_append_reply(opts->reply, "invalid num: %s\n", optarg);
				return -1;
			}
			break;

		case 's':
			dup->syn = 1;
			break;

		default:
			shell_append_reply(opts->reply, "invalid arg: %c\n", opt);
			return -1;
		}
	}

	if (!num_given(&dup->nr_pkt))
		dup->nr_pkt.num = 1;

	dup->enabled = enabled;

	return 0;
}

const struct fuzzer fuzzer_dup = {
	.name   = "dup",
	.fuzz   = dup_fuzz,
	.parse  = dup_parse,
	.stats  = dup_stats,
	.help   = dup_help,
};
