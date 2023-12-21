/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _TEST_UTILS_H_
#define _TEST_UTILS_H_

#include <assert.h>
#include <sys/time.h>
#include <netinet/icmp6.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_arp.h>

#include "api/tpa.h"

#include "tpa.h"
#include "packet.h"
#include "sock.h"
#include "eth.h"
#include "tcp.h"
#include "neigh.h"
#include "worker.h"
#include "tcp_queue.h"
#include "tsock_trace.h"
#include "ip.h"
#include "archive.h"

/*
 * IPs are in network order
 */
#define CLIENT_IP		0x1001a8c0
#define CLIENT_IP_STR		"192.168.1.16"
#define CLIENT_IP6		"\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10"
#define CLIENT_IP6_STR		"fe80::10"

#define SERVER_IP		0x2001a8c0
#define SERVER_IP_STR		"192.168.1.32"
#define SERVER_PORT		80
#define SERVER_IP6		"\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20"
#define SERVER_IP6_STR		"fe80::20"

#define IP_MASK_STR		"255.255.255.0"
#define GW_IP_STR		"192.168.1.1"
#define GW_IP			0x0101a8c0
#define GW_IP6			"\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
#define GW6_IP_STR		"fe80::1"

#define TCP_OPT_TYPE_UNKNOWN	100
#define TCP_OPT_LEN_UNKNOWN	2

#define INVALID_FLOW_ID		(0xffffffff)

enum {
	CLOSE_TYPE_4WAY = 1,
	CLOSE_TYPE_RESET,
	CLOSE_TYPE_CLOSE_DIRECTLY,
};

extern struct tpa_worker *worker;
extern int ut_with_timer;
extern int skip_arp;
extern uint16_t ut_port_min;
extern uint16_t ut_port_max;

#define TEST_ZCOPY		1
#define TEST_ZCOPY_FALLBACK	2

#define MESSAGE_SIZE		(ut_test_opts.message_size)
#define WITH_ZEROCOPY		(!!(ut_test_opts.with_zerocopy == TEST_ZCOPY))
#define WITH_TSO		(!!ut_test_opts.with_tso)

#define WHILE_NOT_TIME_UP()					\
	for (uint64_t start_tsc = rte_rdtsc();			\
	     rte_rdtsc() - start_tsc < ut_test_opts.duration * rte_get_tsc_hz(); )

extern uint64_t on_interval_last;
#define ON_INTERVAL(us)			\
	if (TSC_TO_US(rte_rdtsc() - on_interval_last) >= (us) && (on_interval_last = rte_rdtsc()))

struct ut_test_opts {
	int has_ts;
	int mss;
	int wscale;
	int sack;

	int message_size;
	int duration;
	int with_zerocopy;
	int with_tso;
	int with_cksum;
	int with_ipv6;
	int with_flow_mark;
	int with_sock_trace;

	int silent;
	uint32_t remote_ip;
};

extern struct ut_test_opts ut_test_opts;

uint64_t get_rss_size_in_mb(void);
void ut_init(int argc, char **argv);
int ut_spawn_thread(pthread_t *tid, void *(*func)(void *), void *arg);

void setup_tpa_iovec(struct tpa_iovec *iov, size_t size, int zerocopy);
ssize_t ut_write(struct tcp_sock *tsock, size_t size);
ssize_t ut_zwrite(struct tcp_sock *tsock, size_t size);
ssize_t ut_write_assert(struct tcp_sock *tsock, size_t size);
ssize_t ut_readv(struct tcp_sock *tsock, int nr_iov);
void ut_event_ctrl(struct tcp_sock *tsock, int op, uint32_t events);
uint32_t ut_event_poll(struct tcp_sock *tsock);
void ut_tsock_txq_drain(struct tcp_sock *tsock);

void ut_tcp_set_hdr(struct packet *pkt, uint32_t seq, uint32_t ack, uint16_t flags, uint16_t win);
int ut_tcp_set_opt(struct rte_tcp_hdr *tcp, int off, int opt, uint32_t val);
void ut_ip_set_hdr(struct packet *pkt, uint16_t tcp_opt_len, uint16_t tcp_payload_len);
int ut_parse_tcp_packet(struct packet *pkt);

struct packet *ut_make_packet(int is_reply, uint16_t client_port, uint32_t flow_id);
struct packet *make_synack_packet(struct tcp_sock *tsock, int has_ts, int mss, int wscale, int sack);
struct packet *make_arp_rsp_pkt(uint32_t rsp_ip, uint8_t *mac);
struct packet *make_ndp_rsp_pkt(struct tpa_ip *rsp_ip, uint8_t *mac);
struct packet *ut_inject_data_packet(struct tcp_sock *tsock, uint32_t seq, int payload_len);
struct packet *ut_make_input_pkt_chain(struct tcp_sock *tsock, int nr_pkt, int *pkt_size);
void ut_make_input_pkt_bulk_with_seq(struct tcp_sock *tsock, struct packet **pkts,
				     int nr_pkt, int *pkt_size, uint32_t seq);
void ut_make_input_pkt_bulk_randomly_with_seq(struct tcp_sock *tsock, struct packet **pkts,
					      int nr_pkt, uint32_t seq);
void ut_make_input_pkt_bulk(struct tcp_sock *tsock, struct packet **pkts,
			    int nr_pkt, int *pkt_size);
struct packet *ut_inject_ack_packet(struct tcp_sock *tsock, uint32_t ack);
struct packet *ut_inject_sack_packet(struct tcp_sock *tsock, uint32_t ack,
				     struct tcp_sack_block *blocks, int nr_sack);
struct packet *ut_inject_rst_packet(struct tcp_sock *tsock);
struct packet *ut_inject_tcp_pkt(struct tcp_sock *tsock, uint32_t seq, uint32_t ack,
				 uint16_t flags, uint16_t win, int payload_len,
				 struct tcp_opts *opts);

int ut_connect_to(const char *server, uint16_t port, struct tpa_sock_opts *opts);
struct tcp_sock *ut_trigger_connect(void);
struct tcp_sock *do_ut_tcp_connect(int has_ts, int mss, int wscale, int sack);
struct tcp_sock *ut_tcp_connect(void);
void ut_close(struct tcp_sock *tsock, int close_type);
struct packet *ut_drain_send_buff_at_close(struct tcp_sock *tsock);
void ut_tcp_input_raw(struct tcp_sock *tsock, struct packet **pkts, uint16_t nr_pkt);
void ut_tcp_input_one(struct tcp_sock *tsock, struct packet *pkt);
void ut_arp_input(struct packet *pkt);
void ut_ndp_input(struct packet *pkt);
void ut_tcp_input(struct tcp_sock *tsock, struct packet **pkts, uint16_t nr_pkt);
uint16_t ut_tcp_output(struct packet **pkts, uint16_t count);
uint16_t ut_tcp_output_skip_csum_verify(struct packet **pkts, uint16_t count);
uint16_t ut_tcp_output_no_drain(void);
uint16_t ut_port_tcp_output(uint16_t port_id, struct packet **pkts, uint16_t count);

void ut_tcp_input_one_and_drain(struct tcp_sock *tsock, struct packet *pkt);
int ut_timer_process(void);

void ut_dump_tsock_stats(struct tcp_sock *tsock);
void ut_measure_rate(struct tcp_sock *tsock, int interval);

static inline void ut_simulate_rto_timeout(struct tcp_sock *tsock)
{
	usleep((tsock->rto << tsock->rto_shift) + GRAGNULARITY * 1.1);
}

static inline struct rte_tcp_hdr *ut_packet_tcp_hdr(struct packet *pkt)
{
	int off = 14 + (ut_test_opts.with_ipv6 ? 40 : 20);
	return rte_pktmbuf_mtod_offset(&pkt->mbuf, struct rte_tcp_hdr *, off);
}

static inline uint32_t mbuf_cache_count(struct rte_mempool *mp)
{
	uint32_t sum = 0;
	int i;

	if (mp->cache_size == 0)
		return 0;

	for (i = 0; i < RTE_MAX_LCORE; i++)
		sum += mp->local_cache[i].len;

	return sum;
}

#define ut_free_mbuf_count()	(rte_mempool_ops_get_count(packet_pool_get_mempool(generic_pkt_pool)) + \
				 mbuf_cache_count(packet_pool_get_mempool(generic_pkt_pool)))
#define ut_total_mbuf_count()	(packet_pool_get_mempool(generic_pkt_pool)->populated_size)

#define ut_assert_mbuf_count()		do {				\
	if (ut_free_mbuf_count() != ut_total_mbuf_count()) {		\
		printf("fatal: expected mbuf free count is %u, but we got %u\n",\
			ut_total_mbuf_count(), ut_free_mbuf_count());	\
		assert(0);						\
	}								\
} while (0)

struct ndp_solicit_hdr {
	struct rte_ether_hdr eth;
	struct rte_ipv6_hdr ip6;
	struct nd_neighbor_solicit ns;
	struct nd_opt_hdr opt;
	struct rte_ether_addr mac;
} __attribute__((packed));

struct ndp_advert_hdr {
	struct rte_ether_hdr eth;
	struct rte_ipv6_hdr ip6;
	struct nd_neighbor_advert na;
	struct nd_opt_hdr opt;
	struct rte_ether_addr mac;
} __attribute__((packed));


struct timer_snapshot {
	int slot_idx;
	uint32_t active;
	uint32_t closed;
};

static inline void ut_take_timer_snapshot(struct timer *timer, struct timer_snapshot *snapshot)
{
	snapshot->slot_idx = timer->slot_idx;
	snapshot->active   = timer->active;
	snapshot->closed   = timer->closed;
}

static inline int ut_time_not_changed(struct timer *timer, struct timer_snapshot *snapshot)
{
	return snapshot->slot_idx == timer->slot_idx &&
	       snapshot->active   == timer->active   &&
	       snapshot->closed   == timer->closed;
}

#endif
