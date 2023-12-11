/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
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

#include <tpa.h>
#include <packet.h>
#include <lib/utils.h>
#include <stats.h>
#include <dev.h>
#include <tcp.h>
#include <tcp_queue.h>
#include <mem_file.h>
#include <sock.h>
#include <worker.h>

static int verbose;
static int list_all;
static int show_json;
static int show_dot;
static int last_sid;
static int show_summary;
static char *socks_file;
static uint8_t *sid_dump_mask;
static int has_dump_mask;

static const char *state_to_str(int state)
{
	static const char *states[] = {
		"closed",
		"listen",
		"syn_sent",
		"syn_rcvd",
		"established",
		"fin_wait_1",
		"fin_wait_2",
		"close_wait",
		"closing",
		"last_ack",
		"time_wait",
	};

	if (state < 0 || state >= (int)(ARRAY_SIZE(states)))
		return "unknown-state";

	return states[state];
}

static const char *event_to_str(uint32_t event)
{
	static char buf[128];
	int len = 0;

	if (event & TPA_EVENT_IN)
		len += snprintf(buf + len, sizeof(buf) - len, "IN | ");

	if (event & TPA_EVENT_OUT)
		len += snprintf(buf + len, sizeof(buf) - len, "OUT | ");

	if (event & TPA_EVENT_ERR)
		len += snprintf(buf + len, sizeof(buf) - len, "ERR | ");

	if (event & TPA_EVENT_HUP)
		len += snprintf(buf + len, sizeof(buf) - len, "HUP | ");

	if (!len)
		return "none";

	buf[len - 3] = '\0';
	return buf;
}

#define PRINT_JSON_COMMA(x)				do {			\
	if (x)									\
		printf(",\n");							\
	x = 1;									\
} while (0)

#define __SHOW(name, fmt, val, quote)		do {				\
	if (show_json) {							\
		PRINT_JSON_COMMA(print_field_comma);				\
		if (quote) 							\
			printf("\t\t\"%s\": \""fmt"\"", name, val);		\
		else								\
			printf("\t\t\"%s\": "fmt"", name, val);			\
	} else if (show_dot) {							\
		printf("\t%d.%-32s: "fmt"\n", last_sid, name, val);		\
	} else {								\
		printf("\t%-32s: "fmt"\n", name, val);				\
	}									\
} while (0)

#define SHOW_FIELD(field, fmt)			__SHOW(#field, fmt, tsock->field, 0)
#define SHOW_FIELD2(field, fmt, val)		__SHOW(#field, fmt, val, 0)
#define SHOW_FIELD_QUOTED(field, fmt)		__SHOW(#field, fmt, tsock->field, 1)
#define SHOW_FIELD2_QUOTED(field, fmt, val)	__SHOW(#field, fmt, val, 1)

static void print_stats(uint64_t *stats, int print_field_comma)
{
	int i;

	for (i = 0; i < STATS_MAX; i++) {
		if (stats[i])
			__SHOW(stats_name(i), "%lu", stats[i], 0);
	}
}

static char *get_sid(struct tcp_sock *tsock)
{
	static char buf[16];

	if (tsock->sid >= 0) {
		if (tsock->sid != (int)(tsock - sock_ctrl->socks))
			fprintf(stderr, "error: invalid sid detected: %d\n", tsock->sid);

		snprintf(buf, sizeof(buf), "%d", tsock->sid);
	} else {
		snprintf(buf, sizeof(buf), "[%d]", (int)(tsock - sock_ctrl->socks));
	}

	return buf;
}

#define _US(cycles)			((double)(cycles) / (sock_ctrl->hz / 1e6))
#define _S(cycles)			((double)(cycles) / (sock_ctrl->hz))

#define SHOW_LAST_TS(field, idx)	do {			\
	if (show_json) {					\
		if (tsock->last_ts[idx])			\
			SHOW_FIELD2(field, "%.3f", (TS_DIFF(_US(now), _US(tsock->last_ts[idx])) / 1e6)); \
	} else {						\
		if (tsock->last_ts[idx])			\
			SHOW_FIELD2(field, "%.3fs ago", (TS_DIFF(_US(now), _US(tsock->last_ts[idx])) / 1e6)); \
		else						\
			SHOW_FIELD2(field, "%s", "N/A");  \
	}							\
} while (0)

#define __STR(x)			(#x)
#define __ARG(a1, a2)			a1, a2
#define __SHOW_VSTATS(field, fmt1, avg1, max1, fmt2, unit, avg2, max2)	do {	\
	if (show_json) {							\
		SHOW_FIELD2(field.avg, fmt1, avg1);				\
		SHOW_FIELD2(field.max, fmt1, max1);				\
	} else {								\
		__SHOW(__STR(field(avg/max)), fmt2"/"fmt2  unit, __ARG(avg2, max2), 0);\
	}									\
} while (0)

#define SHOW_VSTATS(field, u)	__SHOW_VSTATS(field, "%lu", (uint64_t)(vstats_avg(&tsock->field)), (uint64_t)(tsock->field.max), \
					      "%lu", u,     (uint64_t)(vstats_avg(&tsock->field)), (uint64_t)(tsock->field.max))
#define SHOW_LAT_VSTATS(field)	__SHOW_VSTATS(field, "%.7f", _S(vstats_avg(&tsock->field)),  _S(tsock->field.max), \
					      "%.1f", "us", _US(vstats_avg(&tsock->field)), _US(tsock->field.max))
#define SHOW_SIZE_VSTATS(field)	__SHOW_VSTATS(field, "%lu", vstats_avg(&tsock->field), (uint64_t)(tsock->field.max), \
					      "%.3f", "KB", (double)(vstats_avg(&tsock->field)) / 1024, (double)tsock->field.max / 1024)

static char *get_mac_addr(const struct rte_ether_addr *addr)
{
	static char mac[128];

	snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
		 addr->addr_bytes[0], addr->addr_bytes[1], addr->addr_bytes[2],
		 addr->addr_bytes[3], addr->addr_bytes[4], addr->addr_bytes[5]);

	return mac;
}

static void dump_sock(struct tcp_sock *tsock, int verbose)
{
	static int print_section_comma = 0;
	int print_field_comma = 0;
	struct tcp_rxq *rxq = &tsock->rxq;
	struct tcp_txq *txq = &tsock->txq;
	char local_ip[INET6_ADDRSTRLEN];
	char remote_ip[INET6_ADDRSTRLEN];
	char connection[1024];
	uint32_t snd_inflight;
	uint32_t snd_avail;
	uint64_t now = rte_rdtsc();
	int wid = tsock->worker - (struct tpa_worker *)sock_ctrl->workers;

	last_sid = tsock->sid;

	tpa_ip_to_str(&tsock->local_ip, local_ip, sizeof(local_ip));
	tpa_ip_to_str(&tsock->remote_ip, remote_ip, sizeof(remote_ip));
	snprintf(connection, sizeof(connection), "%s:%hu%s%s:%hu",
		 local_ip, htons(tsock->local_port), show_json ? "-" : " ",
		 remote_ip, htons(tsock->remote_port));

	if (show_json) {
		PRINT_JSON_COMMA(print_section_comma);
		printf("\t{\n");

		SHOW_FIELD2(sid,    "%d", tsock->sid);
		SHOW_FIELD2(worker, "%d", wid);
		SHOW_FIELD2_QUOTED(connection,  "%s", connection);
		SHOW_FIELD2_QUOTED(state, "%s", state_to_str(tsock->state));
	} else {
		printf("sid=%s %s worker=%d %s\n", get_sid(tsock), connection, wid, state_to_str(tsock->state));
		if (verbose == 0)
			return;
	}

	SHOW_FIELD2_QUOTED(src_mac, "%s", get_mac_addr(ETH_SRC_ADDR(&tsock->net_hdr.eth)));
	SHOW_FIELD2_QUOTED(dst_mac, "%s", get_mac_addr(ETH_DST_ADDR(&tsock->net_hdr.eth)));

	SHOW_FIELD(err,     "%d");
	SHOW_FIELD_QUOTED(flags, "0x%x");

	SHOW_FIELD(port_id, "%hu");

	SHOW_FIELD(nr_dupack,      "%hu");
	SHOW_FIELD(retrans_stage,  "%hhu");
	SHOW_FIELD(rto_shift,      "%hhu");
	SHOW_FIELD2(rto_shift_max, "%hhu", vstats8_max_get(&tsock->rto_shift_max));
	SHOW_FIELD(keepalive_shift, "%hhu");
	SHOW_FIELD(quickack,       "%hhu");
	SHOW_FIELD(close_issued,   "%hhu");

	SHOW_FIELD(ts_recent,     "%u");
	SHOW_FIELD(last_ack_sent, "%u");

	SHOW_FIELD(rtt,    "%u");
	SHOW_FIELD2(srtt,  "%u", tsock->srtt >> 3);
	SHOW_FIELD(rttvar, "%u");
	SHOW_FIELD(rto,    "%u");

	SHOW_FIELD(rcv_isn,    "%u");
	SHOW_FIELD(rcv_nxt,    "%u");
	SHOW_FIELD(rcv_wnd,    "%u");
	SHOW_FIELD(rcv_wscale, "%u");
	SHOW_FIELD(nr_ooo_pkt, "%hu");

	SHOW_FIELD(partial_ack, "%hu");

	SHOW_FIELD(data_seq_nxt, "%u");
	SHOW_FIELD(snd_isn,      "%u");
	SHOW_FIELD(snd_nxt,      "%u");
	SHOW_FIELD(snd_una,      "%u");
	SHOW_FIELD(snd_recover,  "%u");
	SHOW_FIELD(snd_wnd,      "%u");
	SHOW_FIELD(snd_wl1,      "%u");
	SHOW_FIELD(snd_wl2,      "%u");
	SHOW_FIELD(snd_ts,       "%u");
	SHOW_FIELD(snd_cwnd,     "%u");
	SHOW_FIELD(snd_ssthresh, "%u");
	SHOW_FIELD(snd_mss,      "%hu");
	SHOW_FIELD(snd_wscale,   "%hhu");

	SHOW_FIELD2_QUOTED(interested_events, "%s", event_to_str(tsock->interested_events));
	SHOW_FIELD2_QUOTED(last_events,       "%s", event_to_str(tsock->last_events));
	SHOW_FIELD2_QUOTED(events,            "%s", event_to_str(tsock->event.events));
	SHOW_FIELD2(in_event_queue,           "%lu", NODE_GET_IDX(&tsock->event_node));

	SHOW_FIELD(opts.listen_scaling, "%hu");
	SHOW_FIELD(opts.local_port,     "%hu");

	SHOW_FIELD(tso_enabled,"%d");
	SHOW_FIELD(ts_enabled, "%hhu");
	SHOW_FIELD(ws_enabled, "%hhu");
	SHOW_FIELD(sack_enabled, "%hhu");
	SHOW_FIELD(ts_ok,      "%hhu");
	SHOW_FIELD(ws_ok,      "%hhu");
	SHOW_FIELD(sack_ok,    "%hhu");

	SHOW_FIELD2(rxq.free_count,    "%hu", tcp_rxq_free_count(rxq));
	SHOW_FIELD2(rxq.readable_pkts, "%hu", tcp_rxq_readable_count(rxq));
	SHOW_FIELD2(txq.free_count,    "%hu", tcp_txq_free_count(txq));
	SHOW_FIELD2(txq.inflight_pkts, "%hu", tcp_txq_inflight_pkts(txq));
	SHOW_FIELD2(txq.to_send_pkts,  "%hu", tcp_txq_to_send_pkts(txq));

	snd_inflight = tsock->snd_nxt - tsock->snd_una;
	snd_avail    = RTE_MIN(tsock->snd_wnd, tsock->snd_cwnd) - snd_inflight;
	SHOW_FIELD2(snd.inflight_bytes, "%u", snd_inflight);
	SHOW_FIELD2(snd.avail_bytes,    "%d", snd_avail);

	SHOW_LAST_TS(last_ts.read,     LAST_TS_READ);
	SHOW_LAST_TS(last_ts.write,    LAST_TS_WRITE);
	SHOW_LAST_TS(last_ts.rcv_data, LAST_TS_RCV_DATA);
	SHOW_LAST_TS(last_ts.rcv_pkt,  LAST_TS_RCV_PKT);
	SHOW_LAST_TS(last_ts.snd_data, LAST_TS_SND_DATA);
	SHOW_LAST_TS(last_ts.snd_pkt,  LAST_TS_SND_PKT);

	SHOW_FIELD(zero_wnd_probe_shift, "%hhu");

	SHOW_LAT_VSTATS(write_lat.submit);
	SHOW_LAT_VSTATS(write_lat.xmit);
	SHOW_LAT_VSTATS(write_lat.complete);
	SHOW_LAT_VSTATS(read_lat.submit);
	SHOW_LAT_VSTATS(read_lat.drain);
	SHOW_LAT_VSTATS(read_lat.complete);
	SHOW_LAT_VSTATS(read_lat.last_write);

	SHOW_SIZE_VSTATS(read_size);
	SHOW_SIZE_VSTATS(write_size);

	SHOW_VSTATS(ooo_recover_time, "us");

	print_stats(tsock->stats_base, print_field_comma);
	if (show_json)
		printf("\n\t}");
}

static int dump_tsocks(struct tcp_sock *socks)
{
	struct tcp_sock *tsock;
	int i;

	if (show_json)
		printf("[\n");

	for (i = 0; i < sock_ctrl->nr_max_sock; i++) {
		tsock = &socks[i];

		if (tsock->sid == TSOCK_SID_UNALLOCATED)
			continue;

		if (has_dump_mask && sid_dump_mask[i] == 0)
			continue;

		if (list_all || sid_dump_mask[i] || tsock->sid >= 0)
			dump_sock(tsock, verbose);
	}

	if (show_json)
		printf("\n]\n");

	return 0;
}

static void dump_summary(void)
{
	if (!show_summary)
		return;

	printf("init_nr_max_sock: %d\n", sock_ctrl->nr_max_sock >> sock_ctrl->nr_expand_times);
	printf("curr_nr_max_sock: %d\n", sock_ctrl->nr_max_sock);
	printf("nr_expand_times: %hhu\n", sock_ctrl->nr_expand_times);
	printf("expand_failed: %hhu\n", sock_ctrl->expand_failed);
}

static void usage(void)
{
	fprintf(stderr, "usage: sock-list [-v] [-j] [-a] [-s] [-f socks-file] [sid1] [sid2..n]\n");

	exit(1);
}

static void parse_args(int argc, char **argv)
{
	int opt;

	while ((opt = getopt(argc, argv, "f:advjs")) != -1) {
		switch (opt) {
		case 'f':
			socks_file = optarg;
			break;

		case 'a':
			list_all = 1;
			break;

		case 'd':
			show_dot = 1;
			break;

		case 'v':
			verbose = 1;
			break;

		case 'j':
			show_json = 1;
			break;

		case 's':
			show_summary = 1;
			break;

		default:
			usage();
		}
	}

	if (!socks_file) {
		static char path[PATH_MAX];

		snprintf(path, sizeof(path), "%s/%s", tpa_root_get(), "socks");
		socks_file = path;
	}

	sock_ctrl = mem_file_map_data(socks_file, 0);
	if (!sock_ctrl)
		exit(1);

	sid_dump_mask = malloc(sizeof(uint8_t) * sock_ctrl->nr_max_sock);
	if (!sid_dump_mask) {
		fprintf(stderr, "failed to allocate sid dump mask: nr_max_sock=%u: %s\n",
			sock_ctrl->nr_max_sock, strerror(errno));
		exit(1);
	}

	while (optind < argc) {
		int sid = atoi(argv[optind]);

		if (sid < 0) {
			fprintf(stderr, "invalid sid: %s\n", argv[optind]);
			exit(1);
		}

		sid_dump_mask[sid] = 1;
		has_dump_mask = 1;
		optind += 1;
	}
}

int main(int argc, char *argv[])
{
	parse_args(argc, argv);

	dump_tsocks(sock_ctrl->socks);

	dump_summary();

	return 0;
}
