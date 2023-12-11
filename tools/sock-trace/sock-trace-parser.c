/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>

#include <packet.h>
#include <trace.h>
#include <lib/utils.h>
#include <stats.h>
#include <tcp.h>
#include <mem_file.h>
#include <tx_desc.h>

struct trace_ctx {
	struct tsock_trace *trace;
	uint64_t iter;

	uint64_t init_time;
	uint64_t init_ts_us;
	uint64_t ts_us;

	uint32_t state;

	uint16_t rxq_size;
	uint16_t rxq_readable_count;

	uint16_t txq_size;
	uint16_t txq_inflight_pkts;
	uint16_t txq_to_send_pkts;

	/* tcp */
	struct {
		uint32_t snd_una;
		uint32_t snd_nxt;

		uint32_t snd_cwnd;
		uint32_t snd_ssthresh;
		uint32_t snd_recover;

		uint32_t rcv_nxt;
		uint32_t rcv_wnd;

		uint32_t ts_recent;
		uint32_t last_ack_sent;

		uint32_t rto;
	};
};

static int show_abs_time = 1;
static int show_abs_seq;
static int list_only;

static struct trace_ctx ctx;

static inline const char *desc_flags_to_str(uint8_t flags)
{
	static char buf[128];
	int len = 0;

	buf[0] = '\0';

	if (flags & TX_DESC_FLAG_MEM_FROM_MBUF)
		len += snprintf(buf + len, sizeof(buf) - len, "NON-ZWRITE ");

	if (flags & TX_DESC_FLAG_MEASURE_LATENCY)
		len += snprintf(buf + len, sizeof(buf) - len, "LAT ");

	if (flags & TX_DESC_FLAG_RETRANS)
		len += snprintf(buf + len, sizeof(buf) - len, "RETRANS ");

	if (flags & TX_DESC_FLAG_SACKED)
		len += snprintf(buf + len, sizeof(buf) - len, "SACKED ");

	return buf;
}

struct str_buf {
	int len;
	char buf[4096];
};

#define str_buf_append(s, ...)                          \
	(s)->len += snprintf((s)->buf + (s)->len, sizeof((s)->buf) - (s)->len, __VA_ARGS__)

#define str_buf_vsnprintf(s, fmt)               do {    \
	va_list ap;                                     \
	va_start(ap, fmt);                              \
	(s)->len += vsnprintf((s)->buf + (s)->len, sizeof((s)->buf) - (s)->len, fmt, ap);      \
	va_end(ap);                                     \
} while (0)

static void dump_ts(struct str_buf *str)
{
	char buf[64];
	uint64_t ts_us;

	if (ctx.ts_us == 0) {
		str_buf_append(str, "?????????? ????????.?????? ");
		return;
	}

	ts_us = ctx.ts_us - ctx.init_ts_us;
	if (show_abs_time) {
		time_t time_sec;

		ts_us += ctx.init_time;
		time_sec = ts_us /  1e6;

		strftime(buf, sizeof(buf), "%Y-%m-%d %T", localtime(&time_sec));
	} else {
		snprintf(buf, sizeof(buf), "%lu", ts_us / 1000000);
	}

	str_buf_append(str, "%s.%06lu ", buf,  ts_us % 1000000);
}

void trace_printf(const char *fmt, ...)
{
	struct str_buf str = {
		.len = 0,
	};

	dump_ts(&str);
	str_buf_vsnprintf(&str, fmt);

	printf("%s", str.buf);
}

#define TRACE_TOOL
#include <trace/tcp.h>
#include <trace/misc.h>


int (*dump_ops[TT_MAX])(struct trace_ctx *ctx);

static void dump_trace(struct tsock_trace *trace)
{
	struct trace_record *record;
	uint64_t size = trace->mask + 1;
	int nr_stale_record = 0;

	if (trace->off > size)
		ctx.iter = trace->off - size;
	else
		ctx.iter = 0;

	ctx.ts_us = 0;
	while (ctx.iter < trace->off) {
		record = &trace->records[ctx.iter & trace->mask];

		if (!dump_ops[record->type]) {
			nr_stale_record += 1;
			ctx.iter += 1;
			continue;
		}

		if (nr_stale_record) {
			printf(":: warn: %d stale record(s) detected\n", nr_stale_record);
			nr_stale_record = 0;
		}

		if (dump_ops[record->type](&ctx) < 0)
			break;
	}
}

static void dump_tsock_trace(struct tsock_trace *trace)
{
	char local_ip[INET6_ADDRSTRLEN];
	char remote_ip[INET6_ADDRSTRLEN];

	ctx.trace = trace;
	ctx.init_time = trace->init_time;
	ctx.init_ts_us = trace->init_ts_us;
	ctx.ts_us = trace->init_ts_us;
	ctx.rxq_size = trace->rxq_size;
	ctx.txq_size = trace->txq_size;

	tpa_ip_to_str(&trace->local_ip, local_ip, sizeof(local_ip));
	tpa_ip_to_str(&trace->remote_ip, remote_ip, sizeof(remote_ip));
	trace_printf("%s:%hu %s:%hu worker=%d\n", local_ip, ntohs(trace->local_port),
		     remote_ip, ntohs(trace->remote_port), trace->worker);

	dump_trace(trace);
}

static void usage(char *name)
{
	fprintf(stderr,
		"usage: %s trace-file [offset] [-o output-mode]\n"
		"       %s trace-file -l\n"
		"\n"
		"Where the support output modes are:\n"
		"   abs-time, relative-time, abs-seq, relative-seq\n",
		name, name);

	exit(1);
}

#define matches(a, b)	strcmp(a, b) == 0

static void parse_args(int argc, char **argv)
{
	char *opts;
	char *p;
	int opt;

	while ((opt = getopt(argc, argv, "o:l")) != -1) {
		switch (opt) {
		case 'o':
			opts = strdup(optarg);

			p = strtok(opts, ",");
			while (p != NULL) {
				if (matches(p, "abs-time"))
					show_abs_time = 1;
				else if (matches(p, "relative-time"))
					show_abs_time = 0;
				else if (matches(p, "abs-seq"))
					show_abs_seq = 1;
				else if (matches(p, "relative-seq"))
					show_abs_seq = 0;
				else {
					fprintf(stderr, "error: invalid output mode: %s\n", p);
					exit(1);
				}

				p = strtok(NULL, ",");
			}

			free(opts);
			break;

		case 'l':
			list_only = 1;
			break;

		default:
			usage(argv[0]);
			break;
		}
	}
}

static int map_tsock_trace_file(const char *path)
{
	struct mem_file *mem_file;

	mem_file = mem_file_map(path, NULL, MEM_FILE_READ);
	if (!mem_file)
		return -1;

	memset(&tsock_trace_ctrl, 0, sizeof(tsock_trace_ctrl));
	tsock_trace_ctrl.file = mem_file_data(mem_file);
	tsock_trace_ctrl.size = mem_file_data_size(mem_file);

	return 0;
}

static int list_tsock_trace(const char *path, struct tsock_trace *trace)
{
	char name[256];

	printf("%-42s %-8s %-6s %-28s %-6s %s\n",
	       "path", "off", "size", "time", "sid", "name");

	TSOCK_TRACE_FOREACH(trace) {
		if (trace->sid < 0)
			continue;

		tsock_trace_name(trace, "", name, sizeof(name));
		printf("%-42s %-8lu %-6lu %-28s %-6d %s\n",
		       path, off, trace->size, str_time(trace->init_ts_us),
		       trace->sid, name);
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct tsock_trace *trace = NULL;
	const char *file;
	uint64_t off = 0;

	parse_args(argc, argv);

	file = argv[optind++];
	if (optind < argc)
		off = strtol(argv[optind], NULL, 10);

	if (map_tsock_trace_file(file) < 0)
		exit(1);

	if (list_only)
		return list_tsock_trace(file, trace);

	trace = tsock_trace_at(off);
	if (!trace || trace->sid < 0) {
		fprintf(stderr, "error: no tsock trace found at %s:%lu\n",
			file, off);
		exit(1);
	}

	dump_tsock_trace(trace);

	return 0;
}
