/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _PKTFUZZ_H_
#define _PKTFUZZ_H_

#include <stdint.h>

#include "lib/utils.h"
#include "packet.h"
#include "shell.h"

struct fuzz_rate {
	int once;
	int once_done;

	double rate;
	uint64_t total;

	uint64_t hit;
};

struct fuzz_num {
	int random;
	int num;
	char raw[32];
};

struct fuzz_drop_cfg {
	int enabled;
	struct fuzz_rate rate;

	struct fuzz_num count;	/* nr to drop in a row at most */
	int head;

	/* when it's given, only matched pkts will be dropped */
	int port;

	struct {
		uint64_t dropped;
	} stats;
};

struct fuzz_reorder_cfg {
	int enabled;
	struct fuzz_rate rate;

	struct {
		uint64_t reordered;
	} stats;
};

struct fuzz_cut_cfg {
	int enabled;
	struct fuzz_rate rate;

	struct fuzz_num size;
	int head;
	int tail;

	struct {
		uint64_t total;
	} stats;
};

struct fuzz_dup_cfg {
	int enabled;
	struct fuzz_rate rate;

	struct fuzz_num nr_pkt;
	int syn;

	struct {
		uint64_t total;
	} stats;
};

struct fuzz_delay_cfg {
	int enabled;
	struct fuzz_rate rate;

	struct fuzz_num usec;

	struct {
		uint64_t total;
	} stats;
};

struct fuzz_cfg {
	struct fuzz_drop_cfg		drop;
	struct fuzz_reorder_cfg		reorder;
	struct fuzz_cut_cfg		cut;
	struct fuzz_dup_cfg		dup;
	struct fuzz_delay_cfg		delay;
};

struct fuzz_opt {
	int argc;
	char **argv;
	struct shell_buf *reply;

	struct fuzz_cfg *fuzz_cfg;
};

static inline int meet_rate_n(struct fuzz_rate *rate, uint32_t n)
{
	rate->total += n;

	if (rate->once) {
		if (rate->once_done == 0) {
			rate->once_done = 1;
			return 1;
		}

		return 0;
	}

	if ((double)rate->hit / rate->total * 100 < rate->rate) {
		rate->hit += 1;

		return 1;
	}

	return 0;
}

static inline int meet_rate(struct fuzz_rate *rate)
{
	return meet_rate_n(rate, 1);
}

#define RATE_FMT			\
	"\trate.rate: %s\n"		\
	"\trate.real_rate: %.3f%%\n"	\
	"\trate.hit: %lu\n"		\
	"\trate.total: %lu\n"

#define RATE_ARGS(rate)			\
	rate_to_str(rate),		\
	(rate)->total ? (double)((rate)->hit) * 100 / (rate)->total : 0, \
	(rate)->hit,			\
	(rate)->total

static inline char *rate_to_str(struct fuzz_rate *rate)
{
	static char buf[64];

	if (rate->once) {
		tpa_snprintf(buf, sizeof(buf), "once(%sdone)", rate->once_done ? "" : "not ");
		return buf;
	}

	tpa_snprintf(buf, sizeof(buf), "%.3f%%", rate->rate);
	return buf;
}

static inline int num_given(struct fuzz_num *num)
{
	return num->random || num->num;
}

static inline char *num_to_str(struct fuzz_num *num)
{
	static char buf[64];

	if (num->random) {
		tpa_snprintf(buf, sizeof(buf), "%s", num->raw);
		return buf;
	}

	tpa_snprintf(buf, sizeof(buf), "%s(%d)", num->raw, num->num);
	return buf;
}

static inline int rate_is_set(struct fuzz_rate *rate)
{
	return rate->once || rate->rate > 0;
}

static inline int num_is_set(struct fuzz_num *num)
{
	return num->random || num->num > 0;
}

int parse_rate(struct fuzz_rate *rate, const char *opt);
int parse_num(struct fuzz_num *num, const char *val, int type);

struct dev_txq;
struct fuzzer {
	const char *name;
	void (*fuzz)(struct dev_txq *txq);
	void (*run)(struct dev_txq * txq);

	int (*parse)(struct fuzz_opt *opts);
	void (*help)(struct shell_buf *reply, struct fuzz_cfg *fuzz_cfg);
	void (*stats)(struct shell_buf *reply, struct fuzz_cfg *fuzz_cfg);
};

extern const struct fuzzer fuzzer_reorder;
extern const struct fuzzer fuzzer_cut;
extern const struct fuzzer fuzzer_dup;
extern const struct fuzzer fuzzer_delay;
extern const struct fuzzer fuzzer_drop;

extern int pktfuzz_enabled;
extern struct fuzz_cfg fuzz_cfg;

void fuzz(struct dev_txq *txq);
struct packet *pktfuzz_packet_copy(struct packet *pkt);
void pktfuzz_update_csum_offload(struct packet *pkt);
void fuzz_run(struct dev_txq *txq);
void pktfuzz_log(const char *fmt, ...);

static inline void pktfuzz(struct dev_txq *txq)
{
	if (unlikely(pktfuzz_enabled))
		fuzz(txq);
}

static inline void pktfuzz_run(struct dev_txq *txq)
{
	if (unlikely(pktfuzz_enabled))
		fuzz_run(txq);
}

void pktfuzz_init(void);

#endif
