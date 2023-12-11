/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _TCP_TRACE_H_
#define _TCP_TRACE_H_

#include "trace_declare.h"
#include "tcp_queue.h"

enum {
	OOO_QUEUED,
	OOO_DROP_PREV_AND_REPLACE,
	OOO_DROP_NEXT,
	OOO_DROP_CURR,
	OOO_DROP_DUE_TO_OOO_LIMIT,
	OOO_CUT_LEFT,
	OOO_CUT_RIGHT,
	OOO_CUT_BEYOND_WND,
	OOO_RECOVERED,
};

enum {
	FAST_RETRANS_ENTERING,
	FAST_RETRANS_FALSE,
	FAST_RETRANS_LEAVING,
};

enum {
	SACK_UPDATE,
	SACK_REGULATE,
	SACK_RCV,
};

#ifdef TRACE_TOOL
static const char *tcp_states[] = {
	[TCP_STATE_CLOSED]	= "closed",
	[TCP_STATE_LISTEN]	= "listen",
	[TCP_STATE_SYN_SENT]	= "syn-sent",
	[TCP_STATE_SYN_RCVD]	= "syn-rcvd",
	[TCP_STATE_ESTABLISHED]	= "established",
	[TCP_STATE_FIN_WAIT_1]	= "fin-wait-1",
	[TCP_STATE_FIN_WAIT_2]	= "fin-wait-2",
	[TCP_STATE_CLOSE_WAIT]	= "close-wait",
	[TCP_STATE_CLOSING]	= "closing",
	[TCP_STATE_LAST_ACK]	= "last-ack",
	[TCP_STATE_TIME_WAIT]	= "time-wait",
};

static inline const char *tcp_flags_to_str(uint8_t flags)
{
	static char buf[128];
	int len = 0;

	buf[0] = '\0';

	if (flags & TCP_FLAG_URG)
		len += tpa_snprintf(buf + len, sizeof(buf) - len, "URG ");

	if (flags & TCP_FLAG_ACK)
		len += tpa_snprintf(buf + len, sizeof(buf) - len, "ACK ");

	if (flags & TCP_FLAG_PSH)
		len += tpa_snprintf(buf + len, sizeof(buf) - len, "PSH ");

	if (flags & TCP_FLAG_RST)
		len += tpa_snprintf(buf + len, sizeof(buf) - len, "RST ");

	if (flags & TCP_FLAG_SYN)
		len += tpa_snprintf(buf + len, sizeof(buf) - len, "SYN ");

	if (flags & TCP_FLAG_FIN)
		len += tpa_snprintf(buf + len, sizeof(buf) - len, "FIN ");

	return buf;
}

static inline const char *pkt_flags_to_str(uint16_t flags)
{
	static char buf[128];
	int len = 0;

	buf[0] = '\0';

	if (flags & PKT_FLAG_RETRANSMIT)
		len += tpa_snprintf(buf + len, sizeof(buf) - len, "RETRANS ");

	return buf;
}

static inline const char *sack_type_to_str(int type)
{
	switch (type) {
	case SACK_UPDATE:
		return "update";

	case SACK_REGULATE:
		return "regulate";

	case SACK_RCV:
		return "rcv";
	}

	return "unknown";
}

#define rcv_seq(seq)		(show_abs_seq ? (seq) : (seq) - ctx->trace->rcv_isn)
#define snd_seq(seq)		(show_abs_seq ? (seq) : (seq) - ctx->trace->snd_isn)

#define snd_ts(ts)		((ts) - us_to_tcp_ts(ctx->init_ts_us))
#endif


DECLARE_TRACE(tcp_rcv_pkt, 2,
	TRACE_ARGS(
		uint32_t seq _AD_ uint32_t ack  _AD_  uint16_t wnd _AD_
		uint16_t len _AD_ uint8_t flags _AD_  uint8_t nr_seg
	),

	TRACE_RECORDS(
		TYPE_RECORD(TT_tcp_rcv_pkt, R32(seq); R16(wnd); R8(flags));
		DATA_RECORD(R32(ack); R16(len); R8(nr_seg));
	),

	TRACE_PARSER(
		trace_printf("tcp_rcv: seq=%u len=%u nr_seg=%u wnd=%hu .-rcv_nxt=%+d | ack=%u .-snd_una=%+d .-snd_nxt=%+d | %s\n",
			     rcv_seq(seq), len, nr_seg, wnd, (int)(seq - ctx->rcv_nxt),
			     snd_seq(ack), (int)(ack - ctx->snd_una), (int)(ack - ctx->snd_nxt),
			     tcp_flags_to_str(flags));
	)
)

DECLARE_TRACE(tcp_set_state, 1,
	TRACE_ARGS(int state _AD_ uint16_t rxq_readable_count),

	TRACE_RECORDS(
		TYPE_RECORD(TT_tcp_set_state, R32_(state); R16(rxq_readable_count));
	),

	TRACE_PARSER(
		trace_printf("state => %s rxq_left=%hu txq_left=%hu\n",
			     tcp_states[state], rxq_readable_count, ctx->txq_inflight_pkts + ctx->txq_to_send_pkts);
	)
)

DECLARE_TRACE(tcp_established, 4,
	TRACE_ARGS(uint32_t snd_nxt _AD_ uint32_t snd_cwnd _AD_
		   uint32_t snd_ssthresh _AD_ uint32_t rcv_nxt),

	TRACE_RECORDS(
		TYPE_RECORD(TT_tcp_established, R32(snd_nxt));
		DATA_RECORD(R32_(snd_cwnd));
		DATA_RECORD(R32_(snd_ssthresh));
		DATA_RECORD(R32_(rcv_nxt));
	),

	TRACE_PARSER(
	)
)

DECLARE_TRACE(tcp_ts_opt, 4,
	TRACE_ARGS(
		uint32_t ts_val    _AD_ uint32_t ts_ecr _AD_
		uint32_t ts_recent _AD_ uint32_t last_ack_sent
	),

	TRACE_RECORDS(
		TYPE_RECORD(TT_tcp_ts_opt, R32(ts_val));
		DATA_RECORD(R32(ts_ecr));
		DATA_RECORD(R32_(ts_recent));
		DATA_RECORD(R32_(last_ack_sent));
	),

	TRACE_PARSER(
		trace_printf("       > ts.val=%u ts_recent=%u last_ack_sent=%u ts_ecr=%u\n",
			     ts_val, ts_recent, rcv_seq(last_ack_sent), snd_ts(ts_ecr));
	)
)


DECLARE_TRACE(tcp_rtt, 4,
	TRACE_ARGS(uint32_t rtt _AD_ uint32_t srtt _AD_ uint32_t rttvar _AD_ uint32_t rto),

	TRACE_RECORDS(
		TYPE_RECORD(TT_tcp_rtt, R32(rtt));
		DATA_RECORD(R32(srtt));
		DATA_RECORD(R32(rttvar));
		DATA_RECORD(R32_(rto));
	),

	TRACE_PARSER(
		trace_printf("       > rtt=%u srtt=%u rttvar=%u rto=%u\n",
			     rtt, srtt, rttvar, rto);
	)
)

DECLARE_TRACE(tcp_ooo, 1,
	TRACE_ARGS(uint16_t event _AD_ uint32_t arg),

	TRACE_RECORDS(
		TYPE_RECORD(TT_tcp_ooo, R32(arg); R16(event));
	),

	TRACE_PARSER(
		switch (event) {
		case OOO_QUEUED:
			trace_printf("       > ooo.enqueued.len=%hu nr_ooo_pkt=%hu\n",
				     arg >> 16, arg & 0xffff);
			break;

		case OOO_DROP_PREV_AND_REPLACE:
			trace_printf("       > ooo.drop.prev.len=%u\n", arg);
			break;

		case OOO_DROP_CURR:
			trace_printf("       > ooo.drop.curr prev.seq=%u\n", rcv_seq(arg));
			break;

		case OOO_DROP_NEXT:
			trace_printf("       > ooo.drop.next.seq=%u\n", rcv_seq(arg));
			break;

		case OOO_DROP_DUE_TO_OOO_LIMIT:
			trace_printf("       > ooo.drop.curr due to ooo limit\n");
			break;

		case OOO_CUT_LEFT:
			trace_printf("       > ooo.cut.left.size=%u\n", arg);
			break;

		case OOO_CUT_RIGHT:
			trace_printf("       > ooo.cut.right.size=%u\n", arg);
			break;

		case OOO_CUT_BEYOND_WND:
			trace_printf("       > ooo.cut.beyond_wnd.size=%u\n", arg);
			break;

		case OOO_RECOVERED:
			trace_printf("       > ooo.recover_time=%u\n", arg);
			break;
		}
	)
)

DECLARE_TRACE(tcp_rcv_enqueue, 2,
	TRACE_ARGS(
		uint32_t rcv_nxt _AD_ uint16_t len _AD_
		uint32_t rcv_wnd _AD_ uint16_t rxq_readable_count
	),

	TRACE_RECORDS(
		TYPE_RECORD(TT_tcp_rcv_enqueue, R32_(rcv_nxt); R16(len));
		DATA_RECORD(R32_(rcv_wnd); R16_(rxq_readable_count));
	),

	TRACE_PARSER(
		trace_printf("       > enqueued.len=%hu rcv_wnd=%u rxq_rxq_readable_count=%u rxq_free_count=%u\n",
			     len, rcv_wnd, rxq_readable_count, ctx->rxq_size - rxq_readable_count);
	)
)

DECLARE_TRACE(tcp_zreadv, 2,
	TRACE_ARGS(uint32_t size        _AD_ uint16_t nr_iov_request _AD_
		   uint8_t nr_iov_read _AD_ uint32_t rxq_readable_count),

	TRACE_RECORDS(
		TYPE_RECORD(TT_tcp_zreadv, R32(size); R16(nr_iov_request); R8(nr_iov_read));
		DATA_RECORD(R16_(rxq_readable_count));
	),

	TRACE_PARSER(
		trace_printf("zreadv: nr_iov_request=%d nr_iov_read=%d size=%u rxq_rxq_readable_count=%u rxq_free_count=%u\n",
			     nr_iov_request, nr_iov_read, size,
			     rxq_readable_count, ctx->rxq_size - rxq_readable_count);
	)
)

DECLARE_TRACE(tcp_dupack, 1,
	TRACE_ARGS(uint32_t nr_dupack),

	TRACE_RECORDS(
		TYPE_RECORD(TT_tcp_dupack, R32(nr_dupack));
	),

	TRACE_PARSER(
		trace_printf("       > dupack detected: nr_dupack=%u\n", nr_dupack);
	)
)

DECLARE_TRACE(tcp_snd_una, 1,
	TRACE_ARGS(
		uint32_t snd_una
	),

	TRACE_RECORDS(
		TYPE_RECORD(TT_tcp_snd_una, R32_(snd_una));
	),

	TRACE_PARSER(
	)
)

DECLARE_TRACE(tcp_ack_sent_data, 4,
	TRACE_ARGS(
		uint32_t acked_len _AD_ uint16_t desc_idx _AD_
		uint32_t seq       _AD_ uint16_t len      _AD_
		uint32_t latency   _AD_ uint16_t flags    _AD_
		uint32_t partial_ack
	),

	TRACE_RECORDS(
		TYPE_RECORD(TT_tcp_ack_sent_data, R32(acked_len); R16(desc_idx));
		DATA_RECORD(R32(seq); R16(len));
		DATA_RECORD(R32(latency); R16(flags));
		DATA_RECORD(R32(partial_ack));
	),

	TRACE_PARSER(
		trace_printf("       > [%d] una=%u partial_ack=%u desc.seq=%u desc.len=%u latency=%u acked_len=%u | %s\n",
			     desc_idx, snd_seq(ctx->snd_una), partial_ack,
			     snd_seq(seq), len, latency, acked_len,
			     desc_flags_to_str(flags));
	)
)

DECLARE_TRACE(tcp_update_cwnd, 1,
	TRACE_ARGS(uint32_t snd_cwnd),

	TRACE_RECORDS(
		TYPE_RECORD(TT_tcp_update_cwnd, R32_(snd_cwnd));
	),

	TRACE_PARSER(
		trace_printf("       > updating cwnd to=%u ssthresh=%u\n", snd_cwnd, ctx->snd_ssthresh);
	)
)

DECLARE_TRACE(tcp_update_txq, 1,
	TRACE_ARGS(uint16_t txq_inflight_pkts _AD_ uint16_t txq_to_send_pkts),

	TRACE_RECORDS(
		TYPE_RECORD(TT_tcp_update_txq, R32_(txq_inflight_pkts); R16_(txq_to_send_pkts));
	),

	TRACE_PARSER(
		trace_printf("txq update: inflight=%hu to_send=%hu free=%hu\n",
			     txq_inflight_pkts, txq_to_send_pkts,
			     ctx->txq_size - (txq_inflight_pkts + txq_to_send_pkts));
	)
)

DECLARE_TRACE(tcp_xmit_syn, 1,
	TRACE_ARGS(uint32_t flags),

	TRACE_RECORDS(
		TYPE_RECORD(TT_tcp_xmit_syn, R32(flags));
	),

	TRACE_PARSER(
		trace_printf("xmit syn%s: snd_isn=%u rto=%u rxq_size=%u txq_size=%u\n",
			     (flags & TCP_FLAG_ACK) ? "ack" : "", ctx->trace->snd_isn,
			     ctx->rto, ctx->rxq_size, ctx->txq_size);
	)
)

DECLARE_TRACE(tcp_zwritev, 2,
	TRACE_ARGS(
		uint32_t size              _AD_ uint16_t nr_iov           _AD_ uint8_t nr_pkt      _AD_
		uint32_t txq_inflight_pkts _AD_ uint16_t txq_to_send_pkts _AD_ uint8_t nr_fallback
	),

	TRACE_RECORDS(
		TYPE_RECORD(TT_tcp_zwritev, R32(size); R16(nr_iov); R8(nr_pkt));
		DATA_RECORD(R32_(txq_inflight_pkts); R16_(txq_to_send_pkts); R8(nr_fallback));
	),

	TRACE_PARSER(
		trace_printf("zwritev: nr_iov=%d nr_pkt=%d nr_fallback=%d size=%u inflight=%u to_send=%u free=%u\n",
			     nr_iov, nr_pkt, nr_fallback,
			     size, txq_inflight_pkts, txq_to_send_pkts,
			     ctx->txq_size - (txq_inflight_pkts + txq_to_send_pkts));
	)
)

DECLARE_TRACE(tcp_xmit_data, 2,
	TRACE_ARGS(
		uint32_t seq _AD_ uint16_t budget _AD_
		uint32_t off _AD_ uint16_t len     _AD_ uint8_t flags
	),

	TRACE_RECORDS(
		TYPE_RECORD(TT_tcp_xmit_data, R32(seq); R16(budget));
		DATA_RECORD(R32(off); R16(len); R8(flags));
	),

	TRACE_PARSER(
		trace_printf("xmit data: seq=%u off=%d len=%u budget=%d | %s\n",
			     snd_seq(seq), off, len, budget,
			     desc_flags_to_str(flags));
	)
)

DECLARE_TRACE(tcp_xmit_pkt, 4,
	TRACE_ARGS(
		uint32_t seq     _AD_ uint16_t len       _AD_ uint8_t tcp_hdr_len _AD_
		uint32_t snd_nxt _AD_ uint16_t pkt_flags _AD_
		uint32_t snd_wnd _AD_ uint8_t nr_seg     _AD_ uint8_t tcp_flags _AD_
		uint32_t ts_val
	),

	TRACE_RECORDS(
		TYPE_RECORD(TT_tcp_xmit_pkt, R32(seq); R16(len); R8(tcp_hdr_len));
		DATA_RECORD(R32_(snd_nxt); R16(pkt_flags));
		DATA_RECORD(R32(snd_wnd); R16(nr_seg); R8(tcp_flags));
		DATA_RECORD(R32(ts_val));
	),

	TRACE_PARSER(
		trace_printf("xmit pkt: seq=%u len=%u hdr_len=%hhu nr_seg=%u ts=%u snd_wnd=%u cwnd=%u ssthresh=%u | %s %s\n",
			     snd_seq(seq), len, tcp_hdr_len, nr_seg, snd_ts(ts_val), snd_wnd,
			     ctx->snd_cwnd, ctx->snd_ssthresh,
			     pkt_flags_to_str(pkt_flags), tcp_flags_to_str(tcp_flags));
	)
)

DECLARE_TRACE(tcp_fast_retrans, 3,
	TRACE_ARGS(
		uint32_t snd_ssthresh _AD_ uint16_t stage _AD_
		uint32_t snd_cwnd     _AD_
		uint32_t snd_recover
	),

	TRACE_RECORDS(
		TYPE_RECORD(TT_tcp_fast_retrans, R32_(snd_ssthresh); R16(stage));
		DATA_RECORD(R32_(snd_cwnd));
		DATA_RECORD(R32_(snd_recover));
	),

	TRACE_PARSER(
		const char *p;

		if (stage == FAST_RETRANS_ENTERING)
			p = "entering";
		else if (stage == FAST_RETRANS_FALSE)
			p = "leaving _false_";
		else
			p = "leaving";

		trace_printf("       > %s fast retrans mode: ssthresh=%u cwnd=%u recover=%u\n",
			     p, snd_ssthresh, snd_cwnd, snd_seq(snd_recover));
	)
)

DECLARE_TRACE(tcp_rto, 3,
	TRACE_ARGS(
		uint32_t snd_ssthresh _AD_ uint16_t rto_shift _AD_
		uint32_t snd_cwnd     _AD_
		uint32_t snd_recover
	),

	TRACE_RECORDS(
		TYPE_RECORD(TT_tcp_rto, R32_(snd_ssthresh); R16(rto_shift));
		DATA_RECORD(R32_(snd_cwnd));
		DATA_RECORD(R32_(snd_recover));
	),

	TRACE_PARSER(
		trace_printf("RTO %hhu: recover=%u txq_unfinished_pkts=%hu rto=%u cwnd=%u ssthresh=%u\n",
			     rto_shift - 1, snd_seq(snd_recover),
			     ctx->txq_inflight_pkts + ctx->txq_to_send_pkts,
			     ctx->rto << rto_shift, snd_cwnd, snd_ssthresh);
	)
)

DECLARE_TRACE(tcp_release, 1,
	TRACE_ARGS(int error),

	TRACE_RECORDS(
		TYPE_RECORD(TT_tcp_release, R32(error));
	),

	TRACE_PARSER(
		trace_printf("release at worker: state=%s errno=%d rxq_left=%hu txq_left=%hu\n",
			     tcp_states[ctx->state], error, ctx->rxq_readable_count,
			     ctx->txq_inflight_pkts + ctx->txq_to_send_pkts);
	)
)

#define SACK_TRACE_PACK_R16_R8(r16, r8, len, type)	do {	\
	r16 = (len) & 0xffff;					\
	r8  = ((type) & 0x3);					\
	r8 |= ((len) >> 16) << 2;				\
} while (0)

#define SACK_TRACE_UNPACK_R16_R8(r16, r8, len, type)	do {	\
	type = (r8) & 0x3;					\
	len  = (r16);						\
	len |= ((uint32_t)(r8) >> 2) << 16;			\
} while (0)

DECLARE_TRACE(tcp_sack, 1,
	TRACE_ARGS(uint32_t start _AD_ uint16_t r16 _AD_ uint8_t r8),

	TRACE_RECORDS(
		TYPE_RECORD(TT_tcp_sack, R32(start); R16(r16); R8(r8));
	),

	TRACE_PARSER(
		uint32_t seq;
		uint32_t end;
		uint32_t len;
		uint8_t  type;

		SACK_TRACE_UNPACK_R16_R8(r16, r8, len, type);

		if (type == SACK_RCV) {
			seq = snd_seq(start);
			end = snd_seq(start + len);
		} else {
			seq = rcv_seq(start);
			end = rcv_seq(start + len);
		}

		trace_printf("       > sack %s: <%u %u %u>\n",
			     sack_type_to_str(type), seq, end, len);
	)
)

DECLARE_TRACE(tcp_desc_sacked, 2,
	TRACE_ARGS(uint32_t seq     _AD_ uint16_t len  _AD_
		   uint32_t latency _AD_ uint16_t flags),

	TRACE_RECORDS(
		TYPE_RECORD(TT_tcp_desc_sacked, R32(seq); R16(len));
		DATA_RECORD(R32(latency); R16(flags));
	),

	TRACE_PARSER(
		trace_printf("       > sacked desc: seq=%u len=%hu latency=%u | %s\n",
			     snd_seq(seq), len, latency, desc_flags_to_str(flags));
	)
)

DECLARE_TRACE(pktfuzz_cut, 1,
	TRACE_ARGS(uint32_t seq _AD_ uint16_t len),

	TRACE_RECORDS(
		TYPE_RECORD(TT_pktfuzz_cut, R32(seq); R16(len));
	),

	TRACE_PARSER(
		trace_printf("pktfuzz cut %u %u\n",
			     snd_seq(seq), len);
	)
)

#endif
