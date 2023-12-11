/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <unistd.h>

#include "pktfuzz.h"
#include "worker.h"
#include "tpa.h"
#include "log.h"

static const struct fuzzer *fuzzers[] = {
	&fuzzer_reorder,
	&fuzzer_cut,
	&fuzzer_dup,

	/*
	 * both delay and drop fuzzer might reduce txq->nr_pkt to zero; put
	 * them at end.
	 */
	&fuzzer_delay,
	&fuzzer_drop,
};

struct fuzz_cfg fuzz_cfg;
int pktfuzz_enabled = 0;

static const struct fuzzer *fuzzer_find(const char *name)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(fuzzers); i++) {
		if (strcmp(fuzzers[i]->name, name) == 0)
			return fuzzers[i];
	}

	return NULL;
}

void fuzz(struct dev_txq *txq)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(fuzzers); i++) {
		if (txq->nr_pkt)
			fuzzers[i]->fuzz(txq);
	}
}

void fuzz_run(struct dev_txq *txq)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(fuzzers); i++) {
		if (fuzzers[i]->run)
			fuzzers[i]->run(txq);
	}
}

static void usage(struct shell_buf *reply)
{
	shell_append_reply(reply, "usage: pktfuzz egress fuzzer [options]\n"
				  "       pktfuzz stats [fuzzer-list]\n"
				  "       pktfuzz help\n");
}

int parse_rate(struct fuzz_rate *rate, const char *opt)
{
	if (strcmp(opt, "once") == 0) {
		rate->once_done = 0;
		rate->once = 1;
		return 0;
	}

	rate->rate = atof(opt);
	rate->hit = 0;
	rate->total = 0;

	return 0;
}

int parse_num(struct fuzz_num *num, const char *val, int type)
{
	int n;

	tpa_snprintf(num->raw, sizeof(num->raw), "%s", val);

	num->random = 0;
	if (strcmp(val, "random") == 0) {
		num->random = 1;
		return 0;
	}

	n = tpa_parse_num(val, type);
	if (errno)
		return -1;

	num->num = n;
	return 0;
}

static int get_fuzzers(struct fuzz_opt *opts, struct fuzzer **fuzzer_list)
{
	const struct fuzzer *fuzzer;
	int count = 0;
	int i;

	if (opts->argc <= 1) {
		memcpy(fuzzer_list, fuzzers, ARRAY_SIZE(fuzzers) * sizeof(struct fuzzer *));
		return ARRAY_SIZE(fuzzers);
	}

	for (i = 1; i < opts->argc; i++) {
		fuzzer = fuzzer_find(opts->argv[i]);
		if (!fuzzer) {
			shell_append_reply(opts->reply, "error: %s: no such fuzzer\n",
					   opts->argv[i]);
			return -1;
		}
		fuzzer_list[count++] = (struct fuzzer *)(uintptr_t)fuzzer;
	}

	return count;
}

static int cmd_fuzz_stats(struct fuzz_opt *opts)
{
	struct fuzzer *fuzzer_list[ARRAY_SIZE(fuzzers)];
	int count;
	int i;

	count = get_fuzzers(opts, fuzzer_list);
	if (count < 0)
		return -1;

	for (i = 0; i < count; i++) {
		fuzzer_list[i]->stats(opts->reply, opts->fuzz_cfg);
	}

	return 0;
}

static int cmd_fuzz_help(struct fuzz_opt *opts)
{
	struct fuzzer *fuzzer_list[ARRAY_SIZE(fuzzers)];
	int count;
	int i;

	count = get_fuzzers(opts, fuzzer_list);
	if (count < 0)
		return -1;

	usage(opts->reply);
	if (count > 1) {
		shell_append_reply(opts->reply,
				   "\nBelow is a list of the available fuzzers and their arguments.\n");
	}

	for (i = 0; i < count; i++) {
		shell_append_reply(opts->reply, "\n");
		fuzzer_list[i]->help(opts->reply, opts->fuzz_cfg);
	}

	shell_append_reply(opts->reply,
			   "\n"
			   "<-r rate> and <-n num> are two common options for most of fuzzers.\n"
			   "\n"
			   "<rate> specifies how often we should execute a fuzzer. It tells\n"
			   "the possibility (in percentage from 0.000%% to 100%%) to execute a\n"
			   "fuzzer. If 'once' is given, meaning the fuzzer will be executed\n"
			   "once.\n"
			   "\n"
			   "<num> specifies an integer (say the cut size, the number of\n"
			   "packets to drop in a row, etc). If 'random' is given, a random\n"
			   "number will be generated each time a fuzzer is invoked and the\n"
			   "fuzzer should clamp it to a valid size.\n"
			   "\n"
			   "examples:\n"
			   "    tpa pktfuzz egress drop -r 0.1\n"
			   "    tpa pktfuzz egress cut -r 0.1%% -n 10 -h\n");

	return 0;
}

static int cmd_pktfuzz(struct shell_cmd_info *cmd)
{
	const struct fuzzer *fuzzer;
	struct fuzz_opt opts;

	opts.argc = cmd->argc;
	opts.argv = cmd->argv;
	opts.reply = cmd->reply;
	opts.fuzz_cfg = &fuzz_cfg;
	optind = 0;

	if (cmd->argc < 1)
		goto out;

	if  (strcmp(cmd->argv[0], "help") == 0)
		return cmd_fuzz_help(&opts);

	if (!pktfuzz_enabled) {
		shell_append_reply(cmd->reply,
				   "erorr: pktfuzz is not enabled.\n"
				   "\n"
				   "note that cfg option pktfuzz.enable has to be set at startup to run any pktfuzz cmds\n");
		return -1;
	}

	if (strcmp(cmd->argv[0], "egress") == 0) {
		opts.argc = cmd->argc - 1;
		opts.argv = &cmd->argv[1];

		fuzzer = fuzzer_find(cmd->argv[1]);
		if (!fuzzer) {
			shell_append_reply(cmd->reply, "error: %s: no such fuzzer\n",
					   cmd->argv[1]);
			goto out;
		}

		return fuzzer->parse(&opts);
	} else if (strcmp(cmd->argv[0], "ingress") == 0) {
		shell_append_reply(cmd->reply,
				   "error: pktfuzz doesn't support ingress fuzz yet\n");
		return -1;
	} else if (strcmp(cmd->argv[0], "stats") == 0) {
		return cmd_fuzz_stats(&opts);
	}
out:
	usage(cmd->reply);
	return -1;
}

static const struct shell_cmd pktfuzz_cmd = {
	.name    = "pktfuzz",
	.handler = cmd_pktfuzz,
};

static char log_path[PATH_MAX];
static FILE *log_file;

static struct cfg_spec pktfuzz_cfg_specs[] = {
	{
		.name	= "pktfuzz.enable",
		.type   = CFG_TYPE_UINT,
		.data   = &pktfuzz_enabled,
		.flags  = CFG_FLAG_RDONLY,
	}, {
		.name	= "pktfuzz.log",
		.type   = CFG_TYPE_STR,
		.flags  = CFG_FLAG_RDONLY,
		.data   = &log_path,
		.data_len = sizeof(log_path),
	},
};

void pktfuzz_log(const char *fmt, ...)
{
	char buf[4096];
	va_list ap;
	int len = 0;

	if (!log_file)
		return;

	va_start(ap, fmt);
	len += vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	len += tpa_snprintf(buf + len, sizeof(buf) - len, "\n");
	fwrite(buf, len, 1, log_file);
}

void pktfuzz_init(void)
{
	shell_register_cmd(&pktfuzz_cmd);

	cfg_spec_register(pktfuzz_cfg_specs, ARRAY_SIZE(pktfuzz_cfg_specs));
	cfg_section_parse("pktfuzz");

	if (strlen(log_path)) {
		log_file = fopen(log_path, "w");
		if (!log_file) {
			LOG_WARN("failed to open pktfuzz log file: %s: %s\n",
				 log_path, strerror(errno));
		}
	}
}

#define _COPY(f)		(copy->f = pkt->f)

/* XXX: this likely should go to public */
struct packet *pktfuzz_packet_copy(struct packet *pkt)
{
	struct rte_mempool *mempool = packet_pool_get_mempool(generic_pkt_pool);
	struct packet *copy;

	copy = (struct packet *)rte_pktmbuf_copy(&pkt->mbuf, mempool, 0, UINT32_MAX);
	if (copy) {
		/* just copy few we care */
		_COPY(hdr_len);
		_COPY(tsock);
		_COPY(mbuf.tso_segsz);
	}

	return copy;
}

void pktfuzz_update_csum_offload(struct packet *pkt)
{
	struct eth_ip_hdr *net_hdr;
	struct rte_tcp_hdr *tcp;
	struct rte_mbuf *m = &pkt->mbuf;

	net_hdr = rte_pktmbuf_mtod(m, struct eth_ip_hdr *);
	if (net_hdr->eth.ether_type == htons(RTE_ETHER_TYPE_IPV4)) {
		m->ol_flags = PKT_TX_IP_CKSUM | PKT_TX_TCP_CKSUM;
		m->l3_len = sizeof(struct rte_ipv4_hdr);
		m->packet_type = RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_TCP;

		net_hdr->ip4.hdr_checksum = 0;
		tcp = (struct rte_tcp_hdr *)((char *)net_hdr + sizeof(net_hdr->eth) + sizeof(net_hdr->ip4));
		tcp->cksum = 0;
		tcp->cksum = rte_ipv4_phdr_cksum(&net_hdr->ip4, pkt->mbuf.ol_flags);
	} else {
		m->ol_flags = PKT_TX_TCP_CKSUM;
		m->l3_len = sizeof(struct rte_ipv6_hdr);
		m->packet_type = RTE_PTYPE_L3_IPV6;

		tcp = (struct rte_tcp_hdr *)((char *)net_hdr + sizeof(net_hdr->eth) + sizeof(net_hdr->ip6));
		tcp->cksum = 0;
		tcp->cksum = rte_ipv6_phdr_cksum(&net_hdr->ip6, pkt->mbuf.ol_flags);
	}

	if (m->pkt_len >= 1500)
		m->ol_flags |= PKT_TX_TCP_SEG;

	m->l2_len = sizeof(struct rte_ether_hdr);
	m->l4_len = pkt->hdr_len - m->l2_len - m->l3_len;
}
