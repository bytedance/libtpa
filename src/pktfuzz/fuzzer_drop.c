/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "pktfuzz.h"
#include "worker.h"

static inline int get_drop_count(struct fuzz_num *nr_pkt, int max)
{
	if (nr_pkt->random)
		return (rte_rdtsc() / 3) % max;

	return RTE_MIN(nr_pkt->num, max);
}

static inline int drop_pkts_match_port(struct port_txq *txq, int port)
{
	struct packet *pkt;
	struct rte_tcp_hdr *tcp;
	struct packet **pkts_to_keep = txq->pkts;
	int nr_kept = 0;
	int nr_drop;
	int i;

	for (i = 0; i < txq->nr_pkt; i++) {
		pkt = txq->pkts[i];
		tcp = packet_tcp_hdr(pkt);

		if (ntohs(tcp->src_port) != port && ntohs(tcp->dst_port) != port)
			pkts_to_keep[nr_kept++] = pkt;
		else
			packet_free(pkt);
	}

	nr_drop = txq->nr_pkt - nr_kept;
	txq->nr_pkt = nr_kept;

	return nr_drop;
}

static inline void do_drop(struct port_txq *txq, struct fuzz_drop_cfg *drop)
{
	int nr_to_drop;

	if (drop->port) {
		drop->stats.dropped += drop_pkts_match_port(txq, drop->port);
		return;
	}

	nr_to_drop = get_drop_count(&drop->count, txq->nr_pkt);
	if (drop->head) {
		packet_free_batch(&txq->pkts[0], nr_to_drop);
		txq->nr_pkt -= nr_to_drop;
		memmove(&txq->pkts[0], &txq->pkts[nr_to_drop], txq->nr_pkt * sizeof(struct packet *));
	} else {
		txq->nr_pkt -= nr_to_drop;
		packet_free_batch(&txq->pkts[txq->nr_pkt], nr_to_drop);
	}

	drop->stats.dropped += nr_to_drop;
}

static void drop_fuzz(struct port_txq *txq)
{
	struct fuzz_drop_cfg *drop = &fuzz_cfg.drop;

	if (!drop->enabled)
		return;

	if (meet_rate(&drop->rate))
		do_drop(txq, drop);
}

static void drop_stats(struct shell_buf *reply, struct fuzz_cfg *fuzz_cfg)
{
	struct fuzz_drop_cfg *drop = &fuzz_cfg->drop;

	shell_append_reply(reply,
			   "drop:\n"
			   "\tenabled: %d\n"
			   RATE_FMT
			   "\tcount: %s\n"
			   "\tport: %d\n"
			   "\tdrop_from_head: %d\n"
			   "\tdropped: %lu\n",
			   drop->enabled,
			   RATE_ARGS(&drop->rate),
			   num_to_str(&drop->count),
			   drop->port,
			   drop->head,
			   drop->stats.dropped);
}

static void drop_help(struct shell_buf *reply, struct fuzz_cfg *fuzz_cfg)
{
	shell_append_reply(reply,
			  "drop          drop packets\n"
			  "  -r rate     specify the drop rate\n"
			  "  -n num      specify the nubmer of packet to drop in a row\n"
			  "  -p port     drop pkts match the given port only; it ignores <num> option\n"
			  "  -h          drop head packets from the tx queue(default to tail)\n");
}

static int drop_parse(struct fuzz_opt *opts)
{
	struct fuzz_drop_cfg *drop = &opts->fuzz_cfg->drop;
	int opt;
	int enabled = 0;

	memset(drop, 0, sizeof(*drop));

	while ((opt = getopt(opts->argc, opts->argv, "r:n:p:h")) != -1) {
		switch (opt) {
		case 'r':
			parse_rate(&drop->rate, optarg);
			enabled = 1;
			break;

		case 'n':
			if (parse_num(&drop->count, optarg, NUM_TYPE_NONE) < 0) {
				shell_append_reply(opts->reply, "invalid num: %s\n", optarg);
				return -1;
			}

			enabled = 1;
			break;

		case 'p':
			drop->port = atoi(optarg);
			if (drop->port <= 0 || drop->port >= 65535) {
				shell_append_reply(opts->reply, "invalid port: %s\n", optarg);
				return -1;
			}
			break;

		case 'h':
			drop->head = 1;
			break;

		default:
			shell_append_reply(opts->reply, "invalid arg: %c\n", opt);
			return -1;
		}
	}

	if (!num_given(&drop->count))
		drop->count.num = 1;

	/*
	 * XXX: note that there are races between parsing and the running worker
	 *      that may be referencing us. The same to other fuzzer cfg parsers.
	 */
	drop->enabled = enabled;

	return 0;
}

const struct fuzzer fuzzer_drop = {
	.name   = "drop",
	.fuzz   = drop_fuzz,
	.parse  = drop_parse,
	.stats  = drop_stats,
	.help   = drop_help,
};
