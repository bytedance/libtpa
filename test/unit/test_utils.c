/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <malloc.h>
#include <unistd.h>
#include <sched.h>
#include <pthread.h>

#include "test_utils.h"

struct tpa_worker *worker;
int ut_with_timer = 1;
int skip_arp;
uint16_t ut_port_min;
uint16_t ut_port_max;
uint64_t on_interval_last;
static rte_atomic32_t nr_malloc;

int ut_spawn_thread(pthread_t *tid, void *(*func)(void *), void *arg)
{
	return pthread_create(tid, NULL, func, arg);
}

static void free_write_buffer(void *iov_base, void *iov_param)
{
	free(iov_base);
	rte_atomic32_dec(&nr_malloc);
}

void setup_tpa_iovec(struct tpa_iovec *iov, size_t size, int zerocopy)
{
	memset(iov, 0, sizeof(*iov));

	if (zerocopy) {
		iov->iov_base = malloc(size);

		/* A fake one just for enabling the zero copy write */
		iov->iov_phys = 1;
		if (zerocopy == TEST_ZCOPY_FALLBACK)
			iov->iov_phys = 0;
	}

	/*
	 * fallback to non zero copy mode if zwrite is not enabled
	 */
	if (!iov->iov_base) {
		iov->iov_base = malloc(size);
		assert(iov->iov_base != NULL);
	}

	iov->iov_len = size;
	iov->iov_write_done = free_write_buffer;

	rte_atomic32_inc(&nr_malloc);
}

ssize_t ut_write(struct tcp_sock *tsock, size_t size)
{
	struct tpa_iovec iov;
	ssize_t ret;

	if (!ut_test_opts.with_zerocopy) {
		char buf[size];

		ret = tpa_write(tsock->sid, buf, size);
		goto out;
	}

	setup_tpa_iovec(&iov, size, ut_test_opts.with_zerocopy);
	ret = tpa_zwritev(tsock->sid, &iov, 1);
	if (ret < 0)
		iov.iov_write_done(iov.iov_base, iov.iov_param);

out:
	return ret;
}

ssize_t ut_zwrite(struct tcp_sock *tsock, size_t size)
{
	struct tpa_iovec iov;
	ssize_t ret;

	setup_tpa_iovec(&iov, size, 1);
	ret = tpa_zwritev(tsock->sid, &iov, 1);
	if (ret < 0)
		iov.iov_write_done(iov.iov_base, iov.iov_param);

	return ret;
}

ssize_t ut_write_assert(struct tcp_sock *tsock, size_t size)
{
	ssize_t ret;

	ret = ut_write(tsock, size);
	assert(ret == size || (ret == -1 && errno == EAGAIN));

	return ret;
}

ssize_t ut_readv(struct tcp_sock *tsock, int nr_iov)
{
	struct tpa_iovec iov[nr_iov];
	ssize_t ret;

	ret = tpa_zreadv(tsock->sid, iov, nr_iov);
	if (ret > 0) {
		int i;
		ssize_t off = 0;

		for (i = 0; i < nr_iov; i++) {
			iov[i].iov_read_done(iov[i].iov_base, iov[i].iov_param);

			off += iov[i].iov_len;
			if (off == ret)
				break;

			assert(off < ret);
		}
	}

	return ret;
}

void ut_event_ctrl(struct tcp_sock *tsock, int op, uint32_t events)
{
	struct tpa_event event;

	event.events = events;
	event.data = NULL;
	assert(tpa_event_ctrl(tsock->sid, op, &event) == 0);
}

uint32_t ut_event_poll(struct tcp_sock *tsock)
{
	struct tpa_event events[2];
	int ret;

	ret = tpa_event_poll(worker, events, 2);
	assert(ret == 0 || ret == 1);

	if (ret)
		return events[0].events;

	return 0;
}

void ut_tsock_txq_drain(struct tcp_sock *tsock)
{
	struct packet *pkt;

	/* drain unsent data pkts */
	while (tcp_txq_unfinished_pkts(&tsock->txq)) {
		ut_tcp_output(NULL, -1);
		pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt);
		ut_tcp_input_one(tsock, pkt); {
			assert(tsock->snd_nxt == tsock->snd_una);
		}
	}
}

void ut_dump_tsock_stats(struct tcp_sock *tsock)
{
	int i;

	for (i = 0; i < STATS_MAX; i++) {
		if (tsock->stats_base[i])
			printf("\t%-32s: %lu\n", stats_name(i), tsock->stats_base[i]);
	}
}

void ut_measure_rate(struct tcp_sock *tsock, int interval)
{
	static struct {
		int i;
		uint64_t ts_us;
		uint64_t bytes_read;
		uint64_t bytes_write;
	} last;
	uint64_t bytes_read;
	uint64_t bytes_write;

	if (worker->ts_us - last.ts_us < interval)
		return;

	bytes_read  = tsock->stats_base[BYTE_RECV] - last.bytes_read;
	bytes_write = tsock->stats_base[BYTE_XMIT] - last.bytes_write;

	if (last.ts_us) {
		printf(":: %d read %.3f Gb/s   write %.3f Gb/s\n",
			last.i++,
			(double)(bytes_read  * 8 * 1e6 / interval / (1<<30)),
			(double)(bytes_write * 8 * 1e6 / interval / (1<<30)));
	}

	last.bytes_read  = tsock->stats_base[BYTE_RECV];
	last.bytes_write = tsock->stats_base[BYTE_XMIT];
	last.ts_us = worker->ts_us;
}

struct packet *ut_make_packet(int is_reply, uint16_t client_port, uint32_t flow_id)
{
	struct packet *pkt;
	struct rte_mbuf *m;
	struct rte_ether_hdr *eth;
	struct rte_ipv4_hdr  *ip;
	struct rte_ipv6_hdr  *ip6;
	struct rte_tcp_hdr   *tcp;

	pkt = packet_alloc(generic_pkt_pool);
	assert(pkt != NULL);

	pkt->flags |= PKT_FLAG_VERIFY_CUT;
	m = &pkt->mbuf;

	/*
	 * randomly setting the data_off, to pollute the mbuf headroom;
	 * hopefully, it would detect issues when we assume the mbuf
	 * headroom won't be changed.
	 */
	m->data_off = (worker->cycles.start % m->data_off) + 1;

	eth = rte_pktmbuf_mtod_offset(m, struct rte_ether_hdr *, 0);

	/* don't really care about the remote mac */
	if (is_reply)
		rte_ether_addr_copy(&dev.mac, ETH_DST_ADDR(eth));
	else
		rte_ether_addr_copy(&dev.mac, ETH_SRC_ADDR(eth));

	if (ut_test_opts.with_ipv6) {
		ip6 = rte_pktmbuf_mtod_offset(m, struct rte_ipv6_hdr *,  14);
		tcp = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *,   14 + 40);

		eth->ether_type = htons(RTE_ETHER_TYPE_IPV6);
		m->packet_type = RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_TCP;
		m->ol_flags |= PKT_RX_L4_CKSUM_GOOD;
	} else {
		ip  = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *,  14);
		tcp = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *,   14 + 20);

		eth->ether_type = RTE_ETHER_TYPE_IPV4;
		m->packet_type = RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_TCP;
		m->ol_flags |= PKT_RX_IP_CKSUM_GOOD | PKT_RX_L4_CKSUM_GOOD;
	}

	if (is_reply) {
		if (ut_test_opts.with_ipv6) {
			memcpy(ip6->src_addr, SERVER_IP6, 16);
			memcpy(ip6->dst_addr, CLIENT_IP6, 16);
		} else {
			ip->src_addr = SERVER_IP;
			ip->dst_addr = CLIENT_IP;
		}
		tcp->src_port = htons(SERVER_PORT);
		tcp->dst_port = client_port;
	} else {
		if (ut_test_opts.with_ipv6) {
			memcpy(ip6->src_addr, CLIENT_IP6, 16);
			memcpy(ip6->dst_addr, SERVER_IP6, 16);
		} else {
			ip->src_addr = CLIENT_IP;
			ip->dst_addr = SERVER_IP;
		}
		tcp->src_port = client_port;
		tcp->dst_port = htons(SERVER_PORT);
	}

	if (ut_test_opts.with_flow_mark && flow_id != INVALID_FLOW_ID) {
		m->ol_flags |= PKT_RX_FDIR_ID;
		m->hash.fdir.hi = make_flow_mark(0, flow_id);
	}

	return pkt;
}

/* TODO: remove dupcode */
struct packet *ut_inject_tcp_pkt(struct tcp_sock *tsock, uint32_t seq, uint32_t ack,
				 uint16_t flags, uint16_t win, int payload_len,
				 struct tcp_opts *opts)
{
	struct rte_tcp_hdr *tcp;
	struct packet *pkt;
	int opt_len = 0;

	pkt = ut_make_packet(1, tsock->local_port, tsock->sid);
	ut_tcp_set_hdr(pkt, seq, ack, flags, win);
	tcp = ut_packet_tcp_hdr(pkt);

	/* TODO: fill customized opt val */
	if (opts->has_ts > 0)
		opt_len = ut_tcp_set_opt(tcp, opt_len, TCP_OPT_TS_KIND, tsock->snd_ts);

	if (opts->has_mss > 0)
		opt_len = ut_tcp_set_opt(tcp, opt_len, TCP_OPT_MSS_KIND, 1400);

	if (opts->has_wscale > 0)
		opt_len = ut_tcp_set_opt(tcp, opt_len, TCP_OPT_WSCALE_KIND, 10);

	if (opt_len)
		opt_len = ut_tcp_set_opt(tcp, opt_len, TCP_OPT_EOL_KIND, 0);

	ut_ip_set_hdr(pkt, opt_len, payload_len);

	return pkt;
}

struct packet *ut_inject_data_packet(struct tcp_sock *tsock, uint32_t seq, int payload_len)
{
	struct packet *pkt;
	int opt_len;

	pkt = ut_make_packet(1, tsock->local_port, tsock->sid);
	ut_tcp_set_hdr(pkt, seq, tsock->snd_nxt, TCP_FLAG_ACK, tsock->snd_wnd >> tsock->snd_wscale);
	opt_len = ut_tcp_set_opt(ut_packet_tcp_hdr(pkt), 0, TCP_OPT_TS_KIND, tsock->snd_ts);
	ut_ip_set_hdr(pkt, opt_len, payload_len);

	return pkt;
}

struct packet *ut_make_input_pkt_chain(struct tcp_sock *tsock, int nr_pkt, int *pkt_size)
{
	struct packet *pkts[nr_pkt];
	uint32_t off = 0;
	int i;

	for (i = 0; i < nr_pkt; i++) {
		pkts[i] = ut_inject_data_packet(tsock, tsock->rcv_nxt + off, pkt_size[i]);
		off += pkt_size[i];

		parse_tcp_packet(pkts[i]);

		if (i > 0)
			packet_chain(pkts[0], pkts[i]);
	}

	pkts[0]->to_read = pkts[0];

	return pkts[0];
}

void ut_make_input_pkt_bulk_with_seq(struct tcp_sock *tsock, struct packet **pkts,
				     int nr_pkt, int *pkt_size, uint32_t seq)
{
	uint32_t off = 0;
	int i;

	for (i = 0; i < nr_pkt; i++) {
		pkts[i] = ut_inject_data_packet(tsock, seq + off, pkt_size[i]);
		off += pkt_size[i];
	}
}

void ut_make_input_pkt_bulk_randomly_with_seq(struct tcp_sock *tsock, struct packet **pkts,
					      int nr_pkt, uint32_t seq)
{
	int pkt_size[nr_pkt];
	int i;

	for (i = 0; i < nr_pkt; i++)
		pkt_size[i] = (rand() % 1300) + 1;

	ut_make_input_pkt_bulk_with_seq(tsock, pkts, nr_pkt, pkt_size, seq);
}

void ut_make_input_pkt_bulk(struct tcp_sock *tsock, struct packet **pkts,
			    int nr_pkt, int *pkt_size)
{
	ut_make_input_pkt_bulk_with_seq(tsock, pkts, nr_pkt, pkt_size, tsock->rcv_nxt);
}

struct packet *ut_inject_ack_packet(struct tcp_sock *tsock, uint32_t ack)
{
	struct packet *pkt;
	int opt_len = 0;

	pkt = ut_make_packet(1, tsock->local_port, tsock->sid);
	ut_tcp_set_hdr(pkt, tsock->rcv_nxt, ack, TCP_FLAG_ACK, tsock->snd_wnd >> tsock->snd_wscale);
	if (tsock->ts_ok)
		opt_len = ut_tcp_set_opt(ut_packet_tcp_hdr(pkt), 0, TCP_OPT_TS_KIND, tsock->snd_ts);
	ut_ip_set_hdr(pkt, opt_len, 0);

	return pkt;
}

struct packet *ut_inject_sack_packet(struct tcp_sock *tsock, uint32_t ack,
				     struct tcp_sack_block *blocks, int nr_sack)
{
	struct rte_tcp_hdr *tcp;
	struct packet *pkt;
	int opt_len = 0;

	pkt = ut_make_packet(1, tsock->local_port, tsock->sid);
	tcp = ut_packet_tcp_hdr(pkt);

	ut_tcp_set_hdr(pkt, tsock->rcv_nxt, ack, TCP_FLAG_ACK, tsock->snd_wnd >> tsock->snd_wscale);
	if (tsock->ts_ok)
		opt_len = ut_tcp_set_opt(tcp, 0, TCP_OPT_TS_KIND, tsock->snd_ts);

	if (nr_sack) {
		uint8_t *addr = (uint8_t *)(tcp + 1) + opt_len;
		struct tcp_sack_block *blk;
		struct tcp_opt *opt;
		int i;

		addr[0] = TCP_OPT_NOP_KIND;
		addr[1] = TCP_OPT_NOP_KIND;
		addr += 2;

		opt = (struct tcp_opt *)addr;
		opt->type  = TCP_OPT_SACK_KIND;
		opt->len   = TCP_OPT_SACK_LEN(nr_sack);

		blk = (struct tcp_sack_block *)opt->u8;
		for (i = 0; i < nr_sack; i++) {
			blk->start = htonl(blocks[i].start);
			blk->end   = htonl(blocks[i].end);

			blk += 1;
		}

		opt_len += opt->len + 2;
		tcp->data_off = ((sizeof(struct rte_tcp_hdr) + opt_len) / 4) << 4;
	}

	ut_ip_set_hdr(pkt, opt_len, 0);

	return pkt;
}

struct packet *ut_inject_rst_packet(struct tcp_sock *tsock)
{
	struct packet *pkt;
	int opt_len;

	pkt = ut_make_packet(1, tsock->local_port, tsock->sid);
	ut_tcp_set_hdr(pkt, tsock->rcv_nxt, tsock->snd_nxt, TCP_FLAG_ACK | TCP_FLAG_RST, tsock->snd_wnd >> tsock->snd_wscale);
	opt_len = ut_tcp_set_opt(ut_packet_tcp_hdr(pkt), 0, TCP_OPT_TS_KIND, tsock->snd_ts);
	ut_ip_set_hdr(pkt, opt_len, 0);

	return pkt;
}

void ut_tcp_set_hdr(struct packet *pkt, uint32_t seq, uint32_t ack, uint16_t flags, uint16_t win)
{
	struct rte_tcp_hdr *tcp = ut_packet_tcp_hdr(pkt);

	tcp->sent_seq  = htonl(seq);
	tcp->recv_ack  = htonl(ack);
	tcp->tcp_flags = flags;
	tcp->rx_win    = htons(win);
	tcp->data_off  = (20 / 4) << 4;
}

void ut_ip_set_hdr(struct packet *pkt, uint16_t tcp_opt_len, uint16_t tcp_payload_len)
{
	uint32_t ip_payload_len = sizeof(struct rte_tcp_hdr) + tcp_opt_len + tcp_payload_len;

	if (ut_test_opts.with_ipv6) {
		struct rte_ipv6_hdr *ip6;

		ip6 = rte_pktmbuf_mtod_offset(&pkt->mbuf, struct rte_ipv6_hdr *,  14);
		ip6->vtc_flow = htonl(6 << 28);
		ip6->hop_limits = 255;
		ip6->proto = IPPROTO_TCP;
		ip6->payload_len = htons(ip_payload_len);

		pkt->mbuf.pkt_len  = 14 + 40 + ip_payload_len;
		pkt->mbuf.data_len = 14 + 40 + ip_payload_len;
	} else {
		struct rte_ipv4_hdr *ip;
		uint16_t ip_len;

		ip_len = sizeof(struct rte_ipv4_hdr) + ip_payload_len;

		ip = rte_pktmbuf_mtod_offset(&pkt->mbuf, struct rte_ipv4_hdr *,  14);
		ip->version_ihl   = 0x45;
		ip->total_length  = htons(ip_len);
		ip->time_to_live  = 64;
		ip->next_proto_id = IPPROTO_TCP;

		ip->fragment_offset = 0;
		ip->hdr_checksum = 0;

		pkt->mbuf.pkt_len  = 14 + ip_len;
		pkt->mbuf.data_len = 14 + ip_len;
	}
}

int ut_tcp_set_opt(struct rte_tcp_hdr *tcp, int off, int opt, uint32_t val)
{
	uint8_t *start = (uint8_t *)(tcp + 1) + off;

	switch (opt) {
	case TCP_OPT_TS_KIND:
		fill_opt_ts(start, worker->cycles.start >> 10, val);
		off += 12;
		break;
	case TCP_OPT_MSS_KIND:
		start[0] = TCP_OPT_MSS_KIND;
		start[1] = TCP_OPT_MSS_LEN;
		*((uint16_t *)(start + 2)) = htons(val);
		off += 4;
		break;
	case TCP_OPT_WSCALE_KIND:
		start[0] = TCP_OPT_WSCALE_KIND;
		start[1] = TCP_OPT_WSCALE_LEN;
		start[2] = val;
		start[3] = TCP_OPT_NOP_KIND;
		off += 4;
		break;
	case TCP_OPT_SACK_PERM_KIND:
		start[0] = TCP_OPT_SACK_PERM_KIND;
		start[1] = TCP_OPT_SACK_PERM_LEN;
		start[2] = TCP_OPT_NOP_KIND;
		start[3] = TCP_OPT_NOP_KIND;
		off += 4;
		break;
	case TCP_OPT_EOL_KIND:
		start[0] = TCP_OPT_EOL_KIND;
		start[1] = TCP_OPT_NOP_KIND;
		start[2] = TCP_OPT_NOP_KIND;
		start[3] = TCP_OPT_NOP_KIND;
		off += 4;
		break;
	case TCP_OPT_TYPE_UNKNOWN:
		start[0] = TCP_OPT_TYPE_UNKNOWN;
		start[1] = TCP_OPT_LEN_UNKNOWN;
		start[2] = TCP_OPT_NOP_KIND;
		start[3] = TCP_OPT_NOP_KIND;
		off += 4;
		break;
	default:
		break;
	}

	tcp->data_off = ((sizeof(struct rte_tcp_hdr) + off) / 4) << 4;

	return off;
}

struct packet *make_arp_rsp_pkt(uint32_t rsp_ip, uint8_t *mac)
{
	struct packet *pkt;
	struct rte_ether_hdr *eth;
	struct rte_ether_addr server_mac_addr;
	struct rte_arp_hdr *arp;
	struct rte_arp_ipv4 *arp_data;

	pkt = packet_alloc(generic_pkt_pool);
	assert(pkt != NULL);

	memcpy(server_mac_addr.addr_bytes, mac, 6);

	eth = (struct rte_ether_hdr *)rte_pktmbuf_append(&pkt->mbuf, sizeof(*eth));
	rte_ether_addr_copy(&server_mac_addr, ETH_SRC_ADDR(eth));
	rte_ether_addr_copy(&dev.mac, ETH_DST_ADDR(eth));
	eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

	arp = (struct rte_arp_hdr *)rte_pktmbuf_append(&pkt->mbuf, sizeof(*arp));
	arp->arp_hardware = htons(RTE_ARP_HRD_ETHER);
	arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
	arp->arp_hlen = sizeof(struct rte_ether_addr);
	arp->arp_plen = sizeof(struct in_addr);
	arp->arp_opcode = htons(RTE_ARP_OP_REPLY);

	arp_data = &arp->arp_data;
	rte_ether_addr_copy(&server_mac_addr, &arp_data->arp_sha);
	rte_ether_addr_copy(&dev.mac, &arp_data->arp_tha);
	arp_data->arp_sip = rsp_ip;
	arp_data->arp_tip = dev.ip4;
	rte_pktmbuf_append(&pkt->mbuf, RTE_ETHER_MIN_LEN - sizeof(*eth) - sizeof(*arp));

	return pkt;
}

struct packet *make_ndp_rsp_pkt(struct tpa_ip *rsp_ip, uint8_t *mac)
{
	struct ndp_advert_hdr *hdr;
	struct packet *pkt;
	struct rte_ether_hdr *eth;
	struct rte_ether_addr server_mac_addr;
	struct rte_ipv6_hdr *ip;
	struct nd_neighbor_advert *na;

	pkt = packet_alloc(generic_pkt_pool);
	assert(pkt != NULL);

	memcpy(server_mac_addr.addr_bytes, mac, 6);

	hdr = (struct ndp_advert_hdr *)rte_pktmbuf_append(&pkt->mbuf, sizeof(*hdr));

	eth = &hdr->eth;
	rte_ether_addr_copy(&server_mac_addr, ETH_SRC_ADDR(eth));
	rte_ether_addr_copy(&dev.mac, ETH_DST_ADDR(eth));
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV6);

	ip = &hdr->ip6;
	memcpy(ip->dst_addr, &dev.ip6.ip, 16);
	memcpy(ip->src_addr, rsp_ip, 16);
	ip->vtc_flow = htonl(6 << 28);
	ip->payload_len = htons(sizeof(*hdr) - sizeof(hdr->eth) - sizeof(hdr->ip6));
	ip->hop_limits = 255;
	ip->proto = IPPROTO_ICMPV6;

	na = &hdr->na;
	na->nd_na_hdr.icmp6_type = ND_NEIGHBOR_ADVERT;
	na->nd_na_hdr.icmp6_code = 0;
	memcpy(&na->nd_na_target, rsp_ip, 16);

	hdr->opt.nd_opt_type = ND_OPT_TARGET_LINKADDR;
	hdr->opt.nd_opt_len = 1;
	rte_ether_addr_copy(&server_mac_addr, &hdr->mac);

	na->nd_na_hdr.icmp6_cksum = 0;
	na->nd_na_hdr.icmp6_cksum = rte_ipv6_udptcp_cksum(ip, na);

	return pkt;
}

struct packet *make_synack_packet(struct tcp_sock *tsock, int has_ts, int mss, int wscale, int sack)
{
	struct packet *pkt;
	struct rte_tcp_hdr *tcp;
	uint32_t isn;
	int opt_len = 0;

	isn = isn_gen(&tsock->local_ip, &tsock->remote_ip,
		      tsock->local_port, tsock->remote_port);

	pkt = ut_make_packet(1, tsock->local_port, tsock->sid);
	tcp = ut_packet_tcp_hdr(pkt);

	ut_tcp_set_hdr(pkt, isn, tsock->snd_nxt, RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG, 65535);
	if (has_ts)
		opt_len = ut_tcp_set_opt(tcp, opt_len, TCP_OPT_TS_KIND, tsock->snd_ts);
	if (mss)
		opt_len = ut_tcp_set_opt(tcp, opt_len, TCP_OPT_MSS_KIND, mss);
	if (wscale)
		opt_len = ut_tcp_set_opt(tcp, opt_len, TCP_OPT_WSCALE_KIND, wscale);
	if (sack)
		opt_len = ut_tcp_set_opt(tcp, opt_len, TCP_OPT_SACK_PERM_KIND, 0);
	if (opt_len)
		opt_len = ut_tcp_set_opt(tcp, opt_len, TCP_OPT_EOL_KIND, 0);

	ut_ip_set_hdr(pkt, opt_len, 0);

	return pkt;
}

/*
 * below pair is for "fixing" the timer speedup made at ut_close
 */

static struct timer_ctrl saved_timer_ctrl;

static void ut_timer_ctrl_save(void)
{
	saved_timer_ctrl = worker->timer_ctrl;
}

static void ut_timer_ctrl_restore(void)
{
	worker->timer_ctrl.next_run = saved_timer_ctrl.next_run;
	worker->timer_ctrl.last_run = saved_timer_ctrl.last_run;
	worker->timer_ctrl.curr_slot_idx = saved_timer_ctrl.curr_slot_idx;
}

int ut_timer_process(void)
{
	if (ut_with_timer)
		return timer_process(&worker->timer_ctrl, worker->ts_us);

	return 0;
}

void ut_arp_input(struct packet *pkt)
{
	cycles_update_begin(worker);
	ut_timer_process();

	arp_input(rte_pktmbuf_mtod(&pkt->mbuf, uint8_t *), 64);

	neigh_flush(worker);

	packet_free(pkt);
}

void ut_ndp_input(struct packet *pkt)
{
	size_t off = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr);

	cycles_update_begin(worker);
	ut_timer_process();

	ndp_input(rte_pktmbuf_mtod_offset(&pkt->mbuf, uint8_t *, off),
		  pkt->mbuf.pkt_len - off);

	neigh_flush(worker);

	packet_free(pkt);
}

void ut_tcp_input_raw(struct tcp_sock *tsock, struct packet **pkts, uint16_t nr_pkt)
{
	struct dev_rxq *rxq = dev_port_rxq(0, worker->queue);
	int i;

	assert(rxq->read == rxq->write);

	for (i = 0; i < nr_pkt; i++)
		rxq->pkts[(rxq->write++) & DEV_RXQ_MASK] = pkts[i];

	while (tcp_input(worker, 0))
		;
}

void ut_tcp_input(struct tcp_sock *tsock, struct packet **pkts, uint16_t nr_pkt)
{
	cycles_update_begin(worker);
	ut_timer_process();

	ut_tcp_input_raw(tsock, pkts, nr_pkt);

	assert(tsock->stats_base[ERR_TCP_INVALID_TS] == 0);
	assert(tsock->rcv_wnd < TCP_WINDOW_MAX);

	/*
	 * In the stress mode, we get below "false alarming" quite
	 * often due to the huge schedule latency. Therefore, we
	 * have to disable it.
	 *
	 * XXX: probably we should open it in non stress mode?
	 *
	 * assert(tsock->rtt <= TCP_RTT_MAX);
	 */
	 assert(tsock->rto < 2e6);
}

void ut_tcp_input_one(struct tcp_sock *tsock, struct packet *pkt)
{
	ut_tcp_input(tsock, &pkt, 1);
}

void ut_tcp_input_one_and_drain(struct tcp_sock *tsock, struct packet *pkt)
{
	struct tpa_iovec iov;

	ut_tcp_input_one(tsock, pkt);

	ut_tcp_output(NULL, -1);
	while (tpa_zreadv(tsock->sid, &iov, 1) > 0)
		iov.iov_read_done(iov.iov_base, iov.iov_param);
}

static void assert_on_mbuf_chain(struct rte_mbuf *mbuf)
{
	int nr_seg_claimed = mbuf->nb_segs;
	int pkt_len_claimed = mbuf->pkt_len;
	int nr_seg_detected = 0;
	int pkt_len_detected = 0;

	while (mbuf) {
		if (mbuf->data_off != 0) {
			/* meaning it doesn't reference to an external buf */
			char *orig_addr = (char *)mbuf + sizeof(struct rte_mbuf) +
					  rte_pktmbuf_priv_size(mbuf->pool);
			assert((char *)(mbuf->buf_addr) == orig_addr);
		}
		nr_seg_detected += 1;
		pkt_len_detected += mbuf->data_len;

		if (nr_seg_detected >= 2)
			assert(mbuf->pkt_len == mbuf->data_len);

		mbuf = mbuf->next;
	}

	assert(nr_seg_detected  == nr_seg_claimed);
	assert(pkt_len_detected == pkt_len_claimed);
	assert(nr_seg_claimed - 1 <= tcp_cfg.pkt_max_chain);
}

static uint16_t parse_output_pkt(struct packet *pkt)
{
	struct eth_ip_hdr *hdr = rte_pktmbuf_mtod(&pkt->mbuf, struct eth_ip_hdr *);
	struct rte_tcp_hdr *tcp;

	assert(memcmp(dev.mac.addr_bytes, ETH_SRC_ADDR(&hdr->eth)->addr_bytes, 6) == 0);
	if (hdr->eth.ether_type == htons(RTE_ETHER_TYPE_ARP)) {
		assert(pkt->mbuf.pkt_len == 64);
		assert(pkt->mbuf.data_len == 64);
		return RTE_ETHER_TYPE_ARP;
	}

	if (hdr->eth.ether_type == ntohs(RTE_ETHER_TYPE_IPV6)) {
		if (hdr->ip6.proto == IPPROTO_ICMPV6) {
			/* TODO: we could add more checks here */
			assert(pkt->mbuf.pkt_len == sizeof(struct ndp_solicit_hdr));
			return IPPROTO_ICMPV6;
		}

		assert(pkt->mbuf.l3_len == 40);

		assert(hdr->ip6.vtc_flow == 0x60);
		assert(hdr->ip6.proto == IPPROTO_TCP);
		assert(hdr->ip6.hop_limits == 255);
		assert(hdr->ip6.payload_len == htons(pkt->mbuf.pkt_len - sizeof(*hdr)));
		assert(memcmp(hdr->ip6.src_addr, CLIENT_IP6, 16) == 0);
		assert(memcmp(hdr->ip6.dst_addr, SERVER_IP6, 16) == 0);

		tcp = (struct rte_tcp_hdr *)((char *)hdr + 54);
	} else {
		assert(pkt->mbuf.l3_len == 20);

		assert(hdr->ip4.version_ihl == 0x45);
		assert(hdr->ip4.next_proto_id == IPPROTO_TCP);
		assert(hdr->ip4.src_addr == CLIENT_IP);
		assert(hdr->ip4.time_to_live > 0);
		assert(hdr->ip4.total_length == htons(pkt->mbuf.pkt_len - sizeof(struct rte_ether_hdr)));
		if (ut_test_opts.remote_ip)
			assert(hdr->ip4.dst_addr == htonl(ut_test_opts.remote_ip));
		else
			assert(hdr->ip4.dst_addr == SERVER_IP);

		tcp = (struct rte_tcp_hdr *)((char *)hdr + 34);
	}

	assert(pkt->mbuf.l2_len == 14);
	assert(pkt->mbuf.l4_len >= 20);

	assert(tcp->dst_port == htons(SERVER_PORT));
	assert(tcp->src_port != 0);

	return ntohs(hdr->eth.ether_type);
}

/* XXX: we are okay to introduce one var for that, as we have one worker only */
static int last_nr_output_pkt;
/*
 * returns the number of pkts hold on the txq instead of the number we get
 */
static uint16_t do_ut_tcp_output(struct packet **pkts, uint16_t count, int skip_csum_verify)
{
	struct packet *pkt;
	struct dev_txq *txq = dev_port_txq(0, worker->queue);
	uint16_t i = 0;
	uint16_t nr_pkt;
	uint32_t orig_len;
	int pkt_type;

	cycles_update_begin(worker);
	ut_timer_process();

	tcp_output(worker);

	nr_pkt = txq->nr_pkt;
	for (i = 0; i < nr_pkt; i++) {
		pkt = txq->pkts[i];

		pkt_type = parse_output_pkt(pkt);
		if (pkt_type == RTE_ETHER_TYPE_ARP || pkt_type == IPPROTO_ICMPV6)
			goto next;

		if (skip_csum_verify)
			pkt->mbuf.ol_flags |= PKT_RX_IP_CKSUM_GOOD | PKT_RX_L4_CKSUM_GOOD;
		if (pkt->mbuf.ol_flags & PKT_TX_IP_CKSUM)
			pkt->mbuf.ol_flags |= PKT_RX_IP_CKSUM_GOOD;
		if (pkt->mbuf.ol_flags & PKT_TX_TCP_CKSUM)
			pkt->mbuf.ol_flags |= PKT_RX_L4_CKSUM_GOOD;

		orig_len = TCP_SEG(pkt)->len;
		assert_on_mbuf_chain(&pkt->mbuf);

		assert(parse_tcp_packet(pkt) == 0);
		assert(seq_le((TCP_SEG(pkt)->seq + TCP_SEG(pkt)->len), pkt->tsock->snd_nxt));

		if (WITH_TSO) {
			assert(pkt->hdr_len + pkt->mbuf.tso_segsz <= 1514);
			assert(pkt->mbuf.pkt_len - pkt->hdr_len < 64 * 1024);
		} else {
			assert(pkt->mbuf.pkt_len <= 1514);
		}

		/*
		 * For the xmited pkts, the TCP_SEG(pkt)->len logs ONE segment length. For
		 * chained mbufs, every seg will note the seg len in it's own meta-data
		 * (see xmit_data for details).

		 * However, for recv-ed packets, the TCP_SEG(pkt)->len logs the lenght of
		 * the whole packet (it may have mbuf chains, though this should rarely
		 * happen). That being said, above `parse_tcp_packet` will set the TCP_SEG(pkt)
		 * incorrectly, which makes `ack_sent_data` behaviour badly.
		 *
		 * To workaround this difference (right, it's a bit nasty), we reset it
		 * back again here.
		 */
		if (orig_len)
			TCP_SEG(pkt)->len = orig_len;

	next:
		if (pkts && i < count)
			pkts[i] = pkt;
		else
			packet_free(pkt);
	}

	last_nr_output_pkt = nr_pkt;
	txq->nr_pkt = 0;

	return nr_pkt;
}

uint16_t ut_tcp_output(struct packet **pkts, uint16_t count)
{
	return do_ut_tcp_output(pkts, count, 0);
}

uint16_t ut_tcp_output_skip_csum_verify(struct packet **pkts, uint16_t count)
{
	return do_ut_tcp_output(pkts, count, 1);
}

uint16_t ut_tcp_output_no_drain(void)
{
	cycles_update_begin(worker);
	ut_timer_process();

	tcp_output(worker);

	return dev_port_txq(0, worker->queue)->nr_pkt;
}

int ut_connect_to(const char *server, uint16_t port, struct tpa_sock_opts *opts)
{
	return tpa_connect_to(server, port, opts);
}

struct tcp_sock *ut_trigger_connect(void)
{
	struct tcp_sock *tsock;
	const char *server;
	int sid;

	if (WITH_TSO)
		tcp_cfg.enable_tso = 1;
	else
		tcp_cfg.enable_tso = 0;

	if (ut_test_opts.with_ipv6)
		server = SERVER_IP6_STR;
	else
		server = SERVER_IP_STR;

	sid = ut_connect_to(server, SERVER_PORT, NULL);
	assert(sid >= 0);

	tsock = &sock_ctrl->socks[sid];
	assert(((uint64_t)(uintptr_t)tsock & 63) == 0);
	assert(htons(tsock->local_port) >= ut_port_min && htons(tsock->local_port) < ut_port_max);

	return tsock;
}

struct tcp_sock *do_ut_tcp_connect(int has_ts, int mss, int wscale, int sack)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	struct tcp_opts opts;

	/*
	 * 1. tx syn
	 */
	tsock = ut_trigger_connect();
	assert(ut_tcp_output(&pkt, 1) == 1); {
		/* verify the syn pkt being sent out is okay */
		assert(parse_tcp_opts(&opts, pkt) == 0);
		assert(opts.has_ts == tsock->ts_enabled);
		assert(opts.has_wscale == tsock->ws_enabled);
		assert(opts.has_sack_perm == tsock->sack_enabled);
		assert(opts.nr_sack == 0);
		packet_free(pkt);
	}

	/*
	 * 2. rcv syn-ack
	 */
	pkt = make_synack_packet(tsock, has_ts, mss, wscale, sack);
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->state == TCP_STATE_ESTABLISHED);
		assert(tsock->snd_nxt - tsock->snd_isn == 1);
		assert(tsock->snd_una == tsock->snd_nxt);
		assert(tsock->snd_mss > 0);
		assert(tsock->snd_cwnd > 0);
		assert(tsock->snd_wscale <= TCP_WSCALE_MAX);
		assert(tsock->snd_ssthresh <= TCP_SSTHRESH_MAX);
		assert(tsock->rcv_wscale <= TCP_WSCALE_MAX);
		assert(tsock->rcv_wnd < TCP_WINDOW_MAX);
		assert(tsock->ts_ok == !!has_ts);
		assert(tsock->ws_ok == !!wscale);
		assert(tsock->sack_ok == !!sack);

		/*
		 * XXX: check ut_tcp_input for more info
		 *
		 * assert(tsock->rtt < TCP_RTT_MAX);
		 */
	}

	/*
	 * 3. verify ack being sent out
	 */
	assert(ut_tcp_output(&pkt, 1) == 1); {
		assert(has_flag_ack(pkt));
		assert(!has_flag_syn(pkt));
		assert(!has_flag_rst(pkt));
		assert(parse_tcp_opts(&opts, pkt) == 0);
		assert(tsock->ts_ok == !!has_ts);
		assert(opts.has_mss == 0);
		assert(opts.has_wscale == 0);
		assert(opts.has_sack_perm == 0);
		assert(TCP_SEG(pkt)->len == 0);
		packet_free(pkt);
	}

	ut_assert_mbuf_count();

	return tsock;
}

struct tcp_sock *ut_tcp_connect(void)
{
	return do_ut_tcp_connect(1, 1448, 10, 1);
}

struct packet *ut_drain_send_buff_at_close(struct tcp_sock *tsock)
{
	struct packet *pkts[TXQ_BUF_SIZE];
	uint16_t nr_pkt;
	uint32_t ack;

	/*
	 * Try to make some snd space by freeing sent data.
	 */
	if (!(tsock->flags & TSOCK_FLAG_FIN_SENT)) {
		pkts[0] = ut_inject_ack_packet(tsock, tsock->snd_nxt);
		ut_tcp_input_one(tsock, pkts[0]);
		assert(tsock->snd_una == tsock->snd_nxt);
	}

	while (1) {
		nr_pkt = ut_tcp_output(pkts, TXQ_BUF_SIZE);
		assert(nr_pkt != 0);

		if (TCP_SEG(pkts[nr_pkt - 1])->flags & TCP_FLAG_FIN) {
			if (nr_pkt >= 2)
				packet_free_batch(pkts, nr_pkt - 1);
			return pkts[nr_pkt - 1];
		}
		packet_free_batch(pkts, nr_pkt);

		/* never ack FIN here */
		ack = tsock->snd_nxt;
		if (tsock->flags & TSOCK_FLAG_FIN_SENT)
			ack -= 1;
		pkts[0] = ut_inject_ack_packet(tsock, ack);
		ut_tcp_input_one(tsock, pkts[0]);
		assert(tsock->snd_una == ack);
	}

	abort();
}

void ut_close(struct tcp_sock *tsock, int close_type)
{
	struct packet *pkt;
	uint32_t fin_seq;

	/* send FIN */
	tpa_close(tsock->sid);

	if (close_type == CLOSE_TYPE_RESET) {
		struct packet *pkts[TXQ_BUF_SIZE];
		uint16_t nr_pkt;

		assert(tcp_rxq_readable_count(&tsock->rxq));

		/* we probably should do drain as we drain the unsent data below */
		nr_pkt = ut_tcp_output(pkts, TXQ_BUF_SIZE); {
			assert(nr_pkt > 0);
			assert(tsock->state == TCP_STATE_CLOSED);
			assert(tsock->stats_base[RST_XMIT] == 1);
			assert(tsock->stats_base[FIN_XMIT] == 0);

			pkt = pkts[nr_pkt - 1];
			assert(TCP_SEG(pkt)->flags == (TCP_FLAG_RST | TCP_FLAG_ACK));

			packet_free_batch(pkts, nr_pkt);
		}
		goto closed;
	}

	if (close_type == CLOSE_TYPE_CLOSE_DIRECTLY) {
		assert(tsock->state == TCP_STATE_LISTEN || tsock->state == TCP_STATE_SYN_SENT ||
		       tsock->state == TCP_STATE_CLOSED);
		assert(ut_tcp_output(NULL, 1) == 0); {
			assert(tsock->state == TCP_STATE_CLOSED);
			assert(tsock->stats_base[RST_XMIT] == 0);
			assert(tsock->stats_base[FIN_XMIT] == 0);
		}
		goto closed;
	}

	/* Now go simulate the normal 4-way close */
	assert(close_type == CLOSE_TYPE_4WAY);
	assert(tcp_rxq_readable_count(&tsock->rxq) == 0);

	/*
	 * first we need drain the unsent data if any. Then
	 * make sure FIN is sent.
	 */
	pkt = ut_drain_send_buff_at_close(tsock); {
		assert(tsock->state == TCP_STATE_FIN_WAIT_1);
		assert(TCP_SEG(pkt)->flags == (TCP_FLAG_FIN | TCP_FLAG_ACK));
		assert(tsock->stats_base[FIN_XMIT] == 1);
		assert(tsock->stats_base[RST_XMIT] == 0);
		fin_seq = TCP_SEG(pkt)->seq;
		packet_free(pkt);
	}

	/* simulate the ack from the remote end */
	pkt = ut_inject_ack_packet(tsock, fin_seq + 1);
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->state == TCP_STATE_FIN_WAIT_2);

		/* inject ack again to make sure we still remain in FIN_WAIT_2 state */
		pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt);
		ut_tcp_input_one(tsock, pkt);
		assert(tsock->state == TCP_STATE_FIN_WAIT_2);
	}

	/* simulate the FIN from the remote end */
	pkt = ut_inject_ack_packet(tsock, fin_seq + 1);
	ut_packet_tcp_hdr(pkt)->tcp_flags |= TCP_FLAG_FIN;
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->state == TCP_STATE_TIME_WAIT);

		/* verify FIN ACK is sent out */
		assert(ut_tcp_output(&pkt, 1) == 1);
		assert(TCP_SEG(pkt)->flags == TCP_FLAG_ACK);
		packet_free(pkt);
	}

	/* wait to free tsock */
	worker->ts_us += TCP_TIME_WAIT_DEFAULT + 100 * 1000;
	ut_timer_ctrl_save();
	assert(ut_timer_process() >= 1); {
		assert(tsock->state == TCP_STATE_CLOSED);
		assert(tsock->nr_ooo_pkt == 0);
	}
	ut_timer_ctrl_restore();

closed:
	if (!ut_test_opts.silent)
		ut_dump_tsock_stats(tsock);
	ut_assert_mbuf_count();
}

struct ut_test_opts ut_test_opts;

static void usage(char *cmd)
{
	fprintf(stderr, "%s [-m mss] [-w wscale] [-t] [-C 0|1] [-M message size] "
			"   [-T 0|1] [-Z 0|1]\n", cmd);
	exit(1);
}

static void parse_test_opts(int argc, char **argv)
{
	int opt;

	memset(&ut_test_opts, 0, sizeof(ut_test_opts));
	ut_test_opts.message_size = 1000;
	ut_test_opts.with_cksum = 1;
	ut_test_opts.with_flow_mark = 1;
	ut_test_opts.with_sock_trace = 1;
	ut_test_opts.duration = 5;

	while ((opt = getopt(argc, argv, "d:m:w:C:M:T:Z:ts6:F:S:")) != -1) {
		switch (opt) {
		case 'd':
			ut_test_opts.duration = atoi(optarg);
			break;

		case 'm':
			ut_test_opts.mss = atoi(optarg);
			break;

		case 'w':
			ut_test_opts.wscale = atoi(optarg);
			break;

		case 't':
			ut_test_opts.has_ts = 1;
			break;

		case 's':
			ut_test_opts.sack = 1;
			break;

		case 'C':
			ut_test_opts.with_cksum = atoi(optarg);
			break;

		case 'M':
			ut_test_opts.message_size = atoi(optarg);
			break;

		case 'T':
			ut_test_opts.with_tso = atoi(optarg);
			break;

		case 'Z':
			ut_test_opts.with_zerocopy = atoi(optarg);
			break;

		case '6':
			ut_test_opts.with_ipv6 = atoi(optarg);
			break;

		case 'F':
			ut_test_opts.with_flow_mark = atoi(optarg);
			break;

		case 'S':
			ut_test_opts.with_sock_trace = atoi(optarg);
			break;

		default:
			usage(argv[0]);
		}
	}
}

static const char *getenv_with_default(const char *env, const char *def)
{
	const char *var;

	var = getenv(env);
	if (!var)
		var = def;

	return var;
}

static void init_arp_cache()
{
	uint8_t mac[6] = {0x2, 1, 1, 1, 1, 1};
	struct tpa_ip ip;

	if (skip_arp)
		return;

	neigh_update(tpa_ip_set_ipv4(&ip, SERVER_IP), mac);
	neigh_update(tpa_ip_set_ipv6(&ip, (uint8_t *)SERVER_IP6), mac);
}

static int ut_rss_before_testing;

uint64_t get_rss_size_in_mb(void)
{
	FILE *f = fopen("/proc/self/statm", "r");
	uint64_t data[7];

	assert(f != NULL);
	assert(fscanf(f, "%lu %lu %lu %lu %lu %lu %lu",
		      &data[0], &data[1], &data[2], &data[3],
		      &data[4], &data[5], &data[6]) == 7);

	return data[1] * 4 / 1024;
}

void ut_exit(void)
{
	int rss_after;

	malloc_trim(0);
	rss_after = get_rss_size_in_mb();

	printf("rss diff: %d - %d = %d; nr_malloc=%d\n",
		rss_after, ut_rss_before_testing,
		rss_after - ut_rss_before_testing,
		rte_atomic32_read(&nr_malloc));
	assert(rte_atomic32_read(&nr_malloc) == 0);
	assert(rss_after - ut_rss_before_testing < 100);
}

static void ut_dev_port_init(void)
{
	dev.nr_port = MAX_PORT_NR;
	dev_port_init();
	dev.nr_port = 1;
	dev.ports[0].nic_spec = nic_spec_find_by_type(DEV_NIC_MLNX);
}

void ut_init(int argc, char **argv)
{
	const char *ut_root_prefix;
	const char *ut_id;
	char dpdk_params[PATH_MAX];
	char cmd[PATH_MAX];
	char cfg[1024];
	int mem_size = 80; /* MB */
	int nr_sock = 4; /* let's start small and it will be enlarged dynamically */

	parse_test_opts(argc, argv);

	ut_root_prefix = getenv_with_default("UT_ROOT_PREFIX", "/run/tpa/");
	ut_id          = getenv_with_default("UT_ID", "ut");

	if (strstr(argv[0], "tcp_connect_crr") || strstr(argv[0], "arp"))
		mem_size = 256;

	ut_port_min = 54000;
	ut_port_max = 64000 - 1;
	if (strstr(argv[0], "port_alloc")) {
		ut_port_min = 42000;
		ut_port_max = 50000;
	}

	tpa_snprintf(dpdk_params, sizeof(dpdk_params), "--no-huge -m %d --no-pci %s",
		 mem_size, getenv("TPA_LOG_DISABLE") ? "--log-level 0" : "");

	/* hardcode some key cfgs to overwrite the system one (if exist) */
	tpa_snprintf(cfg, sizeof(cfg), "net { ip = %s; mask = %s; gw = %s; "
					 "ip6 = %s/%d; gw6 = %s; } "
				   "dpdk { mbuf_mem_size = 32MB; extra_args = %s; } "
				   "tcp { nr_max_sock = %d; tso = 0; "
				   "      trace = %d; trace_size = 16KB; "
				   "      more_trace = 1; rto_min = 1s; "
				   "      local_port_range = %d %d; "
				   "} "
				   "archive { flush_interval = 1;} "
				   "%s",
		 CLIENT_IP_STR, IP_MASK_STR, GW_IP_STR,
		 CLIENT_IP6_STR, 64, GW6_IP_STR, dpdk_params,
		 nr_sock, ut_test_opts.with_sock_trace,
		 ut_port_min, ut_port_max,
		 getenv("TPA_CFG"));

	setenv("TPA_ROOT_PREFIX", ut_root_prefix, 1);
	setenv("TPA_ID", ut_id, 1);
	setenv("TPA_CFG", cfg, 1);

	setenv("MALLOC_INSTANCE_COUNT", "1024", 1);

	/* make sure we have no stale socks left before testing */
	tpa_snprintf(cmd, sizeof(cmd), "rm -f %s/%s/socks; rm -rf %s/%s/trace",
		 ut_root_prefix, ut_id, ut_root_prefix, ut_id);
	system(cmd);

	assert(tpa_init(1) == 0);
	init_arp_cache();

	worker = tpa_worker_init();
	ut_dev_port_init();

	ut_rss_before_testing = get_rss_size_in_mb();
	atexit(ut_exit);
}
