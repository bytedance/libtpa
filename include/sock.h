/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _SOCK_H_
#define _SOCK_H_

#include <stdint.h>

#include <rte_hash.h>

#include "packet.h"
#include "dev.h"
#include "timer.h"
#include "cfg.h"
#include "ip.h"
#include "sock_table.h"
#include "offload.h"
#include "flex_fifo.h"
#include "trace.h"
#include <tcp_queue.h>

#define DEFAULT_NR_MAX_SOCK		32768

#define INVALID_SOCK_ID			UINT32_MAX
#define TSOCK_SID_UNALLOCATED		-1
#define TSOCK_SID_FREEED		-2

/* TODO:  make it configurable */
#define TSOCK_RCV_OOO_LIMIT		2048

#define TSOCK_RXQ_LEN_DEFAULT		2048
#define TSOCK_TXQ_LEN_DEFAULT		512

/* XXX: a rough estamation */
#define TSOCK_RCV_WND_DEFAULT(tsock)    ((tsock)->rxq.size * 1400)

#define TSOCK_FLAG_FIN_NEEDED		TCP_FLAG_FIN
#define TSOCK_FLAG_SYN_NEEDED		TCP_FLAG_SYN
#define TSOCK_FLAG_RST_NEEDED		TCP_FLAG_RST
#define TSOCK_FLAG_PSH_NEEDED		TCP_FLAG_PSH
#define TSOCK_FLAG_ACK_NEEDED		TCP_FLAG_ACK
#define TSOCK_FLAG_URG_NEEDED		TCP_FLAG_URG

/* we support at most 8 bits tcp flags now */
#define TSOCK_FLAG_TCP_FLAGS_MASK	0xff
#define tsock_flags_to_tcp_flags(flags)	(flags & TSOCK_FLAG_TCP_FLAGS_MASK)

#define TSOCK_FLAG_ACK_NOW		(1ul<<16)
#define TSOCK_FLAG_FIN_PENDING		(1ul<<17)
#define TSOCK_FLAG_FIN_SENT		(1ul<<18)

#define TSOCK_FLAG_CLOSE_PROCESSED	(1ul<<20)
#define TSOCK_FLAG_EOF			(1ul<<21)
#define TSOCK_FLAG_PUT			(1ul<<22)

#define TSOCK_FLAG_MISSING_ARP		(1ul<<24)

#define TSOCK_QUICKACK_COUNT		30

#define TSOCK_MAX_MERGE_SIZE		(1500 * 32)

enum {
	LAST_TS_READ,
	LAST_TS_WRITE,
	LAST_TS_RCV_DATA,
	LAST_TS_RCV_PKT,
	LAST_TS_SND_DATA,
	LAST_TS_SND_PKT,
	LAST_TS_MAX,
};

/* a short version of tpa_sock_opts, to reduce the memory usage */
struct tpa_sock_opts_short {
	uint32_t listen_scaling:1;

	uint16_t local_port;
	void *data;
};

struct eth_ip_hdr {
	struct rte_ether_hdr eth;
	union {
		struct rte_ipv4_hdr  ip4;
		struct rte_ipv6_hdr  ip6;
	};
} __attribute__((packed));

enum {
	NONE,
	FAST_RETRANS,
	RTO,
};

struct tsock_trace;
struct tpa_worker;
struct tcp_sock {
	int sid;               /* has to be first */

	uint16_t state;
	uint16_t tso_enabled:1;
	uint16_t ts_enabled:1;
	uint16_t ts_ok:1;
	uint16_t ws_enabled:1;
	uint16_t ws_ok:1;
	uint16_t sack_enabled:1;
	uint16_t sack_ok:1;
	uint16_t is_ipv6:1;
	uint16_t cwnd_validated:1;
	uint16_t passive_connection:1;
	uint16_t listen_sock:1;
	uint16_t closed_at_syn_rcvd:1;
	uint16_t reserved:4;

	uint32_t data_seq_nxt; /* the next seq to be assigned for tcp write */
	uint32_t snd_nxt;
	uint32_t snd_una;
	uint32_t snd_recover;
	uint32_t snd_wnd;
	uint32_t snd_wl1;
	uint32_t snd_wl2;
	uint32_t snd_ts;
	uint32_t snd_cwnd;
	uint32_t snd_cwnd_uncommited;
	uint32_t snd_cwnd_orig;
	uint64_t snd_cwnd_ts_us;
	uint32_t snd_ssthresh;
	uint16_t snd_mss;
	uint8_t  snd_wscale;

	uint8_t  rcv_wscale;
	uint32_t rcv_nxt;
	uint32_t rcv_wnd;
	uint32_t sacked_bytes;

	uint8_t  nr_sack_block;
	uint16_t packet_id;
	uint32_t flags;
	struct eth_ip_hdr net_hdr;

	uint16_t port_id;

	uint16_t xmit_trace_ts;
	uint32_t trace_size;
	struct tsock_trace *trace;

	struct tpa_ip remote_ip;
	struct tpa_ip local_ip;
	uint16_t remote_port;
	uint16_t local_port;

	uint32_t rcv_isn;
	uint32_t snd_isn;
	uint64_t init_ts_us;

	uint8_t net_hdr_len;
	int err;

	uint16_t nr_dupack;
	uint8_t  retrans_stage;
	uint8_t  rto_shift;
	uint8_t  quickack;
	uint8_t  close_issued;
	struct vstats8_max rto_shift_max;
	uint64_t rto_start_ts;

	/* PAWS RFC 7323 5. */
	uint32_t ts_recent;
	uint32_t ts_recent_in_sec;
	uint32_t last_ack_sent;

	uint32_t last_ack_sent_ts;
	struct flex_fifo_node delayed_ack_node;

	uint32_t rtt;
	uint32_t srtt;
	uint32_t rttvar;
	uint32_t rto;
	uint8_t  zero_wnd_probe_shift;
	uint8_t  keepalive_shift;

	uint16_t nr_ooo_pkt;
	uint32_t ooo_start_ts;
	struct vstats ooo_recover_time;
	struct packet *rx_merge_head;
	struct vstats rx_merge_size;
	struct tcp_rxq rxq;
	struct packet *last_ooo_pkt;
	struct packet_list rcv_ooo_queue;

	struct flex_fifo_node output_node;
	struct tcp_txq txq;
	uint32_t partial_ack;

	struct offload_list offload_list;
	struct tpa_worker *worker;

	uint32_t interested_events;
	uint32_t last_events;
	struct flex_fifo_node event_node;
	struct tpa_event event;

	struct timer timer_rto;
	struct timer timer_wait;
	struct timer timer_keepalive;

	struct {
		uint32_t seq;
		uint32_t ts_val;
		uint16_t desc_base;
	} retrans;

	struct tpa_sock_opts_short opts;

	uint64_t last_ts[LAST_TS_MAX];
	uint64_t stats_base[STATS_MAX];

	struct vstats write_size;
	struct vstats read_size;

	struct {
		struct vstats submit;
		struct vstats drain;
		struct vstats complete;
		struct vstats last_write;
	} read_lat;

	struct {
		struct vstats submit;
		struct vstats xmit;
		struct vstats complete;
	} write_lat;

	/* for protecting the listen tsock trace only so far */
	rte_spinlock_t lock;

	struct flex_fifo_node accept_node;

	struct tcp_sack_block sack_blocks[TCP_MAX_NR_SACK_BLOCK];

	char reserved2[0];
} __rte_cache_aligned;

static inline void tsock_reset_quickack(struct tcp_sock *tsock)
{
	tsock->quickack = TSOCK_QUICKACK_COUNT;
	TSOCK_STATS_INC(tsock, WARN_QUICKACK_RESET);
}

static inline void tsock_rearm_timer_rto(struct tcp_sock *tsock, uint64_t now)
{
	timer_start(&tsock->timer_rto, now, tsock->rto << tsock->rto_shift);
}

static inline void tsock_rearm_timer_keepalive(struct tcp_sock *tsock, uint64_t now)
{
	tsock->keepalive_shift = 0;

	if (tcp_cfg.keepalive)
		timer_start(&tsock->timer_keepalive, now, tcp_cfg.keepalive);
}

static inline char *get_flow_name(struct tcp_sock *tsock, char *name, size_t size)
{
	char remote_ip[INET6_ADDRSTRLEN];
	char local_ip[INET6_ADDRSTRLEN];

	tpa_ip_to_str(&tsock->remote_ip, remote_ip, sizeof(remote_ip));
	tpa_ip_to_str(&tsock->local_ip, local_ip, sizeof(local_ip));
	tpa_snprintf(name, size, "%d %s:%hu -> %s:%hu", tsock->sid,
		 local_ip, ntohs(tsock->local_port),
		 remote_ip, ntohs(tsock->remote_port));

	return name;
}

static inline int init_net_hdr(struct eth_ip_hdr *hdr, struct rte_ether_hdr *eth,
			       struct tpa_ip *local_ip, struct tpa_ip *remote_ip)
{
	hdr->eth = *eth;

	if (tpa_ip_is_ipv4(local_ip)) {
		struct rte_ipv4_hdr *ip = &hdr->ip4;

		ip->src_addr = tpa_ip_get_ipv4(local_ip);
		ip->dst_addr = tpa_ip_get_ipv4(remote_ip);
		ip->version_ihl = 0x45;
		ip->type_of_service = 0;
		ip->fragment_offset = 0;
		ip->time_to_live = 64;
		ip->next_proto_id = IPPROTO_TCP;

		return sizeof(hdr->eth) + sizeof(hdr->ip4);
	} else {
		struct rte_ipv6_hdr *ip = &hdr->ip6;

		ip->vtc_flow = htonl(6 << 28);
		ip->hop_limits = 255;
		ip->proto = IPPROTO_TCP;
		memcpy(ip->src_addr, local_ip, sizeof(struct tpa_ip));
		memcpy(ip->dst_addr, remote_ip, sizeof(struct tpa_ip));

		return sizeof(hdr->eth) + sizeof(hdr->ip6);
	}
}

static inline void init_tpa_ip_from_pkt(struct packet *pkt, struct tpa_ip *src_ip,
					   struct tpa_ip *dst_ip)
{
	if (pkt->flags & PKT_FLAG_IS_IPV6) {
		struct rte_ipv6_hdr *ip6_hdr = packet_ip6_hdr(pkt);

		tpa_ip_set_ipv6(src_ip, ip6_hdr->src_addr);
		tpa_ip_set_ipv6(dst_ip, ip6_hdr->dst_addr);
	} else {
		struct rte_ipv4_hdr *ip4_hdr = packet_ip_hdr(pkt);

		tpa_ip_set_ipv4(src_ip, ip4_hdr->src_addr);
		tpa_ip_set_ipv4(dst_ip, ip4_hdr->dst_addr);
	}
}

static inline int init_net_hdr_from_pkt(struct eth_ip_hdr *net_hdr, struct tpa_ip *local_ip,
					struct tpa_ip *remote_ip, struct packet *pkt)
{
	struct rte_ether_hdr *eth = packet_eth_hdr(pkt);

	init_tpa_ip_from_pkt(pkt, remote_ip, local_ip);

	rte_ether_addr_copy(ETH_DST_ADDR(eth), ETH_SRC_ADDR(&net_hdr->eth));
	rte_ether_addr_copy(ETH_SRC_ADDR(eth), ETH_DST_ADDR(&net_hdr->eth));
	net_hdr->eth.ether_type = eth->ether_type;

	return init_net_hdr(net_hdr, &net_hdr->eth, local_ip, remote_ip);
}

static inline void tcp_reset_retrans(struct tcp_sock *tsock, uint32_t seq,
				     uint16_t desc_base)
{
	tsock->retrans.seq = seq;
	tsock->retrans.desc_base = desc_base;
}

int listen_tsock_lookup(struct packet *pkt, struct tcp_sock **tsock_ptr);
int tsock_lookup_slowpath(struct tpa_worker *worker, struct packet *pkt,
			  struct tcp_sock **tsock_ptr);

struct sock_ctrl {
	uint32_t nr_max_sock;
	rte_spinlock_t lock;
	rte_atomic32_t nr_sock;
	uint8_t nr_expand_times;
	uint8_t expand_failed;

	/* for sock-list only */
	uint64_t hz;
	void *workers;

	struct mem_file *mem_file;

	struct tcp_sock socks[0] __rte_cache_aligned;
};

extern struct sock_ctrl *sock_ctrl;

static inline struct tcp_sock *tsock_get_by_sid(int sid)
{
	struct tcp_sock *tsock;

	if (unlikely((uint32_t)sid >= tcp_cfg.nr_max_sock))
		return NULL;

	tsock = &sock_ctrl->socks[sid];
	if (unlikely(tsock->sid < 0))
		return NULL;

	return tsock;
}

static inline uint32_t make_flow_mark(uint32_t wid, uint32_t sid)
{
	return (sid << tpa_cfg.nr_worker_shift) | wid;
}

static inline int parse_flow_mark(int wid, struct packet *pkt)
{
	int sid;

	if (unlikely((pkt->mbuf.ol_flags & PKT_RX_FDIR_ID) == 0))
		return -WARN_MISSING_FLOW_MARK;

	sid = pkt->mbuf.hash.fdir.hi >> tpa_cfg.nr_worker_shift;
	pkt->wid = pkt->mbuf.hash.fdir.hi  & tpa_cfg.nr_worker_mask;

	if (unlikely(pkt->wid >= tpa_cfg.nr_worker))
		return -ERR_FLOW_MARK_INVALID;

	return sid;
}

static inline int tuple_matches(struct tcp_sock *tsock, struct packet *pkt)
{
	struct tpa_ip src_ip;
	struct tpa_ip dst_ip;

	init_tpa_ip_from_pkt(pkt, &src_ip, &dst_ip);

	if (unlikely(tsock->state == TCP_STATE_LISTEN)) {
		if (unlikely(tsock->local_port != pkt->dst_port))
			return 0;

		/*
		 * we accept both ipv4 and ipv6 clients; therefore, we should
		 * tell the ip version from the pkt.
		 */
		if (pkt->flags & PKT_FLAG_IS_IPV6)
			return tpa_ip_equal(&dev.ip6.ip, &dst_ip);
		else
			return dev.ip4 == tpa_ip_get_ipv4(&dst_ip);
	}

	return tsock->local_port == pkt->dst_port && tsock->remote_port == pkt->src_port &&
	       tpa_ip_equal(&tsock->local_ip, &dst_ip) && tpa_ip_equal(&tsock->remote_ip, &src_ip);
}

static inline int tsock_lookup(struct tpa_worker *worker, int wid,
			       struct packet *pkt, struct tcp_sock **tsock_ptr)
{
	struct tcp_sock *tsock;
	int sid;
	int err;

	sid = parse_flow_mark(wid, pkt);
	if (likely(sid >= 0)) {
		if (unlikely(sid >= tcp_cfg.nr_max_sock))
			return -ERR_NO_SOCK;

		tsock = &sock_ctrl->socks[sid];
		if (unlikely(!tuple_matches(tsock, pkt) || tsock->sid != sid))
			return -WARN_STALE_PKT_TUPLE_MISMATCH;

		if (unlikely(tsock->state == TCP_STATE_LISTEN)) {
			struct tcp_sock *child;

			if (tsock_lookup_slowpath(worker, pkt, &child) == 0) {
				assert(child->state != TCP_STATE_LISTEN);
				tsock = child;
			}
		}

		*tsock_ptr = tsock;
		return 0;
	}

	err = sid;
	if (err == -WARN_MISSING_FLOW_MARK) {
		err = tsock_lookup_slowpath(worker, pkt, tsock_ptr);
		if (err == -ERR_NO_SOCK)
			err = listen_tsock_lookup(pkt, tsock_ptr);
	}

	return err;
}

int sock_init_early(void);
int sock_init(void);

struct tcp_sock *sock_create(const struct tpa_sock_opts *opts, int is_ipv6);
int tsock_close(struct tcp_sock *tsock);
int tsock_free(struct tcp_sock *tsock);
int tcp_connect(struct tcp_sock *tsock);
void tsock_set_state(struct tcp_sock *tsock, int state);
void tsock_remove_ooo_pkt(struct tcp_sock *tsock, struct packet *pkt);
void tsock_drop_ooo_mbufs(struct tcp_sock *tsock);
uint16_t calc_snd_mss(const struct tcp_sock *tsock, int has_ts,
		      int passive, uint16_t nego_mss);

int eth_input(struct tpa_worker *worker, int port_id);
int tcp_input(struct tpa_worker *worker, struct packet **pkts, int nr_pkt);
int tcp_output(struct tpa_worker *worker);
void tcp_timeout(struct timer *timer);

int xmit_syn(struct tpa_worker *worker, struct tcp_sock *tsock);
int xmit_flag_packet_with_seq(struct tpa_worker *worker, struct tcp_sock *tsock, uint32_t seq);
int xmit_flag_packet(struct tpa_worker *worker, struct tcp_sock *tsock);
int xmit_rst_for_listen(struct tpa_worker *worker, struct tcp_sock *tsock, struct packet *pkt);
void tcp_retrans(struct tpa_worker *worker, struct tcp_sock *tsock);
void tcp_fast_retrans(struct tpa_worker *worker, struct tcp_sock *tsock, int budget);

int tsock_write(struct tcp_sock *tsock, const void *buf, size_t size);
ssize_t tsock_zreadv(struct tcp_sock *tsock, struct tpa_iovec *iov, int nr_iov);
ssize_t tsock_zwritev(struct tcp_sock *tsock, const struct tpa_iovec *iov, int nr_iov);

static inline int tsock_trace_is_enable(struct tcp_sock *tsock)
{
	return trace_cfg.enable_trace;
}

void calc_csum(struct eth_ip_hdr *net_hdr, struct rte_tcp_hdr *tcp);

int tsock_try_update_eth_hdr(struct tpa_worker *worker, struct tcp_sock *tsock);

#endif /*_SOCK_H_ */
