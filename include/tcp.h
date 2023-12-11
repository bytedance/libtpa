/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _TPA_TCP_H_
#define _TPA_TCP_H_

#include <stdint.h>
#include <arpa/inet.h>
#include <sys/uio.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_cycles.h>

#include "ip.h"
#include "stats.h"

#define TCP_MSS_DEFAULT			536 /* RFC 1122 */
#define TCP_WINDOW_MAX			(1ul << 30)
#define TCP_SSTHRESH_MAX		(128ul << 20)
#define TCP_WSCALE_DEFAULT		10
#define TCP_WSCALE_MAX			14 /* RFC 1323 2.3 */
#define TCP_WSCALE_NONE			0

/* in unit of micro seconds */
#define TCP_RTO_MIN			(100 * 1000)	    /* data center mode */
#define TCP_RTO_MAX			(120 * 1000 * 1000)
#define TCP_RTO_DEFAULT			TCP_RTO_MIN
#define TCP_TIME_WAIT_DEFAULT		(60  * 1000 * 1000) /* 60s */
#define TCP_KEEPALIVE_DEFAULT		TCP_RTO_MAX
#define TCP_KEEPALIVE_MIN		(500 * 1000)        /* 500ms */
#define TCP_DELAYED_ACK_DEFAULT		(1   * 1000)

#define TCP_RTT_MAX			(400 * 1000)

/* Rougly obey RFC 6928: set it to 16k; about 11 pkts */
#define TCP_CWND_DEFAULT		(16 * 1024)
#define TCP_CWND_MAX			(1ul<<30)

#define WRITE_CHUNK_SIZE		(16 << 10)

/* XXX: data center mode: about 12s */
#define TCP_SYN_RETRIES_MAX		7
#define TCP_RETRIES_MAX			7

/* RFC 7323 section 5.5 */
#define TCP_PAWS_IDLE_MAX		(24 * 60 * 60 * 24)

enum {
	TCP_STATE_CLOSED,
	TCP_STATE_LISTEN,
	TCP_STATE_SYN_SENT,
	TCP_STATE_SYN_RCVD,
	TCP_STATE_ESTABLISHED,
	TCP_STATE_FIN_WAIT_1,
	TCP_STATE_FIN_WAIT_2,
	TCP_STATE_CLOSE_WAIT,
	TCP_STATE_CLOSING,
	TCP_STATE_LAST_ACK,
	TCP_STATE_TIME_WAIT,
	TCP_STATE_NUM
};

#define TCP_FLAG_FIN		(1 << 0)
#define TCP_FLAG_SYN		(1 << 1)
#define TCP_FLAG_RST		(1 << 2)
#define TCP_FLAG_PSH		(1 << 3)
#define TCP_FLAG_ACK		(1 << 4)
#define TCP_FLAG_URG		(1 << 5)

static inline int seq_lt(uint32_t a, uint32_t b)
{
	return (int)(a - b) < 0;
}

static inline int seq_le(uint32_t a, uint32_t b)
{
	return (int)(a - b) <= 0;
}

static inline int seq_gt(uint32_t a, uint32_t b)
{
	return (int)(a - b) > 0;
}

static inline int seq_ge(uint32_t a, uint32_t b)
{
	return (int)(a - b) >= 0;
}

uint32_t isn_gen(struct tpa_ip *local_ip, struct tpa_ip *remote_ip,
		 uint16_t local_port, uint16_t remote_port);

/* set tcp tampstamp granularity in tcp ts option roughly to 1ms */
static inline uint32_t us_to_tcp_ts(uint64_t us)
{
	return us >> 10;
}

static inline uint32_t tcp_ts_to_us(uint32_t ts)
{
	return ts << 10;
}

#define TCP_OPT_EOL_KIND	0
#define TCP_OPT_NOP_KIND	1

#define TCP_OPT_MSS_KIND	2
#define TCP_OPT_MSS_LEN		4
#define TCP_OPT_MSS_SPACE	4
#define TCP_OPT_MSS_BIT		(1u << TCP_OPT_MSS_KIND)

#define TCP_OPT_WSCALE_KIND	3
#define TCP_OPT_WSCALE_LEN	3
#define TCP_OPT_WSCALE_SPACE	4
#define TCP_OPT_WSCALE_BIT	(1u << TCP_OPT_WSCALE_KIND)

#define TCP_OPT_TS_KIND		8
#define TCP_OPT_TS_LEN		10
#define TCP_OPT_TS_SPACE	12
#define TCP_OPT_TS_BIT		(1u << TCP_OPT_TS_KIND)

#define TCP_OPT_SACK_PERM_KIND	4
#define TCP_OPT_SACK_PERM_LEN	2
#define TCP_OPT_SACK_PERM_SPACE	4
#define TCP_OPT_SACK_PERM_BIT	(1u << TCP_OPT_SACK_PERM_KIND)

/* len & space are not fixed for sack*/
#define TCP_OPT_SACK_KIND	5
#define TCP_OPT_SACK_LEN(n)	(2 + 8 * (n))
#define TCP_OPT_SACK_SPACE(n)	(4 + 8 * (n))
#define TCP_OPT_SACK_BIT	(1u << TCP_OPT_SACK_KIND)

struct tcp_opt {
	uint8_t type;
	uint8_t len;
	union {
		uint32_t u32[0];
		uint16_t u16[0];
		uint8_t  u8[0];
	};
} __attribute__((__packed__));

#define TCP_MAX_NR_SACK_BLOCK	3

struct tcp_sack_block {
	uint32_t start;
	uint32_t end;
};

struct tcp_opts {
	uint8_t  has_mss;
	uint16_t mss;

	uint8_t has_wscale;
	uint8_t wscale;

	uint8_t has_ts;
	struct {
		uint32_t val;
		uint32_t ecr;
	} ts;

	uint8_t has_sack_perm;
	uint8_t nr_sack;
	struct tcp_sack_block sack_blocks[TCP_MAX_NR_SACK_BLOCK];
};

static inline void fill_opt_ts(uint8_t *addr, uint32_t val, uint32_t ecr)
{
	struct tcp_opt *opt;

	/* recommended per RFC 1323 Appendix A */
	addr[0]     = TCP_OPT_NOP_KIND;
	addr[1]     = TCP_OPT_NOP_KIND;

	opt = (struct tcp_opt *)(addr + 2);
	opt->type   = TCP_OPT_TS_KIND;
	opt->len    = TCP_OPT_TS_LEN;
	opt->u32[0] = htonl(val);
	opt->u32[1] = htonl(ecr);
}

struct tcp_cfg {
	uint32_t enable_tso;
	uint32_t enable_ts;
	uint32_t enable_ws;
	uint32_t enable_sack;
	uint32_t enable_rx_merge;
	uint32_t rcv_queue_size;
	uint32_t snd_queue_size;
	uint32_t time_wait;
	uint32_t keepalive;
	uint32_t delayed_ack;
	uint32_t cwnd_init;
	uint32_t cwnd_max;
	uint32_t drop_ooo_threshold;
	uint32_t measure_latency;
	uint32_t usr_snd_mss;
	uint32_t rcv_ooo_limit;
	uint32_t tcp_rto_min;
	uint32_t nr_max_sock;
	uint32_t pkt_max_chain;
	uint32_t retries;
	uint32_t syn_retries;
	uint32_t write_chunk_size;
};

extern struct tcp_cfg tcp_cfg;

#endif
