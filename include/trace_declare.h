/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _TRACE_DECLARE_H_
#define _TRACE_DECLARE_H_

#include "archive_map.h"

/* TODO: remove below two */
#include "sock.h"
#include "worker.h"

enum {
	TT_data,
	TT_ts,
	TT_error,

	TT_tcp_rcv_pkt,
	TT_tcp_set_state,
	TT_tcp_established,
	TT_tcp_ts_opt,	/* we probably don't need that: it's too verbosy */
	TT_tcp_rtt,
	TT_tcp_ooo,
	TT_tcp_rcv_enqueue,
	TT_tcp_dupack,
	TT_tcp_snd_una,
	TT_tcp_ack_sent_data,
	TT_tcp_update_cwnd,
	TT_tcp_update_txq,
	TT_tcp_xmit_syn,
	TT_tcp_xmit_data,
	TT_tcp_xmit_pkt,
	TT_tcp_fast_retrans,
	TT_tcp_rto,
	TT_tcp_zwritev,
	TT_tcp_zreadv,
	TT_tcp_release,
	TT_tcp_sack,
	TT_tcp_desc_sacked,

	TT_pktfuzz_cut,

	TT_MAX,
};

struct trace_record {
	union {
		struct {
			uint8_t type;
			uint8_t u8;
			uint16_t u16;
			uint32_t u32;
		};

		struct {
			uint64_t _type:8;
			uint64_t u56:56;
		};
	};
};

struct tsock_trace {
	struct tpa_ip local_ip;
	struct tpa_ip remote_ip;
	uint16_t local_port;
	uint16_t remote_port;
	int worker;
	uint64_t init_ts_us;
	uint64_t init_time;
	uint32_t snd_isn;
	uint32_t rcv_isn;
	uint32_t rxq_size;
	uint32_t txq_size;
	uint16_t snd_mss;
	uint16_t snd_wscale;

	int sid;

	uint64_t size;
	uint64_t mask;
	uint64_t off;

	struct trace_record records[0] __rte_cache_aligned;
};


struct tsock_trace_ctrl {
	void *file;
	int nr_trace;
	uint64_t size;
	pid_t pid;
	void *parser;
	uint64_t parser_size;

	struct rte_ring *ring;

	struct archive_map *curr_trace_map;
};

extern struct tsock_trace_ctrl tsock_trace_ctrl;

#define TSOCK_TRACE_FOREACH(trace)				\
	for (uint64_t off = 0; (trace = tsock_trace_at(off)) && trace->size > 0; off += trace->size)

static inline struct tsock_trace *tsock_trace_at(uint64_t off)
{
	if (off >= tsock_trace_ctrl.size)
		return NULL;

	return (struct tsock_trace *)((uint8_t *)tsock_trace_ctrl.file + off);
}

void tsock_trace_init(struct tcp_sock *tsock, int sid);
void tsock_trace_uninit(struct tcp_sock *tsock);
void tsock_trace_archive(struct tsock_trace *trace, const char *fmt, ...);

static inline char *tsock_trace_name(struct tsock_trace *trace, const char *mark,
				     char *name, size_t size)
{
	char remote_ip[INET6_ADDRSTRLEN];
	char local_ip[INET6_ADDRSTRLEN];

	tpa_ip_to_str(&trace->remote_ip, remote_ip, sizeof(remote_ip));
	tpa_ip_to_str(&trace->local_ip, local_ip, sizeof(local_ip));

	tpa_snprintf(name, size, "%s:%hu -> %s:%hu %s",
		 local_ip, ntohs(trace->local_port),
		 remote_ip, ntohs(trace->remote_port),
		 mark);

	return name;
}

#ifndef TRACE_TOOL

/* we now depend on sock trace heavily on debug */
#define ENABLE_TRACE

#define TSOCK_TRACE_PROLOG(tsock, nr_record)		do {	\
	struct tsock_trace *trace = tsock->trace;		\
	if (!trace || !tsock_trace_is_enable(tsock))	\
		return;						\
	if (trace_cfg.no_wrap && trace->off + (nr_record) > trace->mask)\
		return;						\
} while (0)

static inline void tsock_trace_base_init(struct tcp_sock *tsock)
{
	struct tsock_trace *trace = tsock->trace;
	char name[256];

	if (!tsock->trace)
		return;

	memcpy(&trace->local_ip,  &tsock->local_ip,  sizeof(struct tpa_ip));
	memcpy(&trace->remote_ip, &tsock->remote_ip, sizeof(struct tpa_ip));
	trace->local_port = tsock->local_port;
	trace->remote_port = tsock->remote_port;
	trace->worker = tsock->worker->id;

	trace->rxq_size = tsock->rxq.size;
	trace->txq_size = tsock->txq.size;

	tsock_trace_name(trace, "", name, sizeof(name));
	archive_map_add(tsock_trace_ctrl.curr_trace_map,
			(char *)trace - (char *)tsock_trace_ctrl.file,
			trace->init_time, trace->size, trace->sid,
			name, tpa_cfg.sock_trace_file);
}

#define R8(x)			(record->u8 = x)
#define R16(x)			(record->u16 = x)
#define R32(x)			(record->u32 = x)
#define R56(x)			(record->u56 = x)

#define R8_(x)			R8(x)
#define R16_(x)			R16(x)
#define R32_(x)			R32(x)
#define R56_(x)			R56(x)

#define TYPE_RECORD(_type, ...)	record = &tsock->trace->records[(tsock->trace->off++) & tsock->trace->mask];	\
				record->type = _type;				\
				__VA_ARGS__
#define DATA_RECORD(...)	record = &tsock->trace->records[(tsock->trace->off++) & tsock->trace->mask];	\
				record->type = TT_data;				\
				__VA_ARGS__


/* argument delimiter */
#define _AD_			,

#ifdef ENABLE_TRACE
#define DECLARE_TRACE(name, nr_record, args, records, parser)		\
static inline void trace_##name(struct tcp_sock *tsock, args)		\
{									\
	struct trace_record *record;					\
									\
	TSOCK_TRACE_PROLOG(tsock, nr_record);				\
	records;							\
}
#else /* !ENABLE_TRACE */
#define DECLARE_TRACE(name, nr_record, args, exp, parser)		\
static inline void trace_##name(struct tcp_sock *tsock, args)		\
{									\
}
#endif

#else /* TRACE_TOOL */

extern int (*dump_ops[])(struct trace_ctx *ctx);

#define TRACE_UPDATE_CTX(x)	ctx->x = x

#define R8(x)			(x = record->u8)
#define R16(x)			(x = record->u16)
#define R32(x)			(x = record->u32)
#define R56(x)			(x = record->u56)

#define R8_(x)			R8(x);  TRACE_UPDATE_CTX(x)
#define R16_(x)			R16(x); TRACE_UPDATE_CTX(x)
#define R32_(x)			R32(x); TRACE_UPDATE_CTX(x)
#define R56_(x)			R56(x); TRACE_UPDATE_CTX(x)

#define TYPE_RECORD(_type, ...)	record = &records[rec_idx++];		\
				record->type = _type;			\
				__VA_ARGS__
#define DATA_RECORD(...)	record = &records[rec_idx++];		\
				record->type = TT_data;			\
				__VA_ARGS__

static inline int trace_record_fetch(struct trace_ctx *ctx, struct trace_record *records, uint64_t count)
{
	int i;

	if (ctx->iter + count > ctx->trace->off)
		return -1;

	for (i = 0; i < count; i++)
		records[i] = ctx->trace->records[(ctx->iter++) & ctx->trace->mask];

	return 0;
}

#define _AD_			__attribute__((__unused__));
#define DECLARE_TRACE(name, nr_record, args, unpack_records, parser)	\
static inline int trace_dump_##name(struct trace_ctx *ctx)		\
{									\
	struct trace_record records[nr_record];				\
	struct trace_record *record;					\
	int rec_idx = 0;						\
	args;								\
									\
	if (trace_record_fetch(ctx, records, nr_record) < 0)		\
		return -1;						\
									\
	unpack_records;							\
	parser;								\
	return 0;							\
}									\
									\
static void __attribute__((constructor)) register_trace_dump_##name(void)\
{									\
	dump_ops[TT_##name] = trace_dump_##name;			\
}

#endif


#define TRACE_ARGS(...)		__VA_ARGS__
#define TRACE_RECORDS(...)	__VA_ARGS__
#define TRACE_PARSER(...)	__VA_ARGS__

#endif
