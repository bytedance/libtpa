/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <stdint.h>

#include <rte_ether.h>
#include <rte_ip.h>

#include "worker.h"
#include "packet.h"
#include "dev.h"
#include "neigh.h"

static __rte_noinline void parse_packet_type(struct packet *pkt)
{
	struct rte_mbuf *m = &pkt->mbuf;
	struct rte_ether_hdr *eth = packet_eth_hdr(pkt);
	struct rte_ipv4_hdr *ip;
	struct rte_ipv6_hdr *ip6;

	m->packet_type = 0;

	switch (htons(eth->ether_type)) {
	case RTE_ETHER_TYPE_IPV4:
		ip = packet_ip_hdr(pkt);
		if (ip->next_proto_id == IPPROTO_TCP)
			m->packet_type |= RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_TCP;
		break;

	case RTE_ETHER_TYPE_IPV6:
		ip6 = packet_ip6_hdr(pkt);
		if (ip6->proto == IPPROTO_TCP)
			m->packet_type |= RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_TCP;
		break;

	case RTE_ETHER_TYPE_ARP:
		m->packet_type |= RTE_PTYPE_L2_ETHER_ARP;
		break;
	}
}

int parse_eth_ip(struct packet *pkt)
{
	struct rte_mbuf *m = &pkt->mbuf;
	uint64_t csum_flags = 0;
	int err;

	debug_assert(pkt->mbuf.data_off <= 128);
	pkt->l2_off = pkt->mbuf.data_off;
	pkt->l3_off = pkt->l2_off + sizeof(struct rte_ether_hdr);

	if (unlikely(!(dev.caps & RX_OFFLOAD_PACKET_TYPE)))
		parse_packet_type(pkt);

	if ((m->packet_type & (RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_TCP)) ==
			      (RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_TCP)) {
		struct rte_ipv4_hdr *ip = packet_ip_hdr(pkt);

		/* TODO: handle ip frags */
		if (unlikely(ip_is_frag(ip->fragment_offset)))
			return -PKT_IP_FRAG;

		csum_flags = PKT_RX_IP_CKSUM_GOOD | PKT_RX_L4_CKSUM_GOOD;
		pkt->ip_payload_len = ntohs(ip->total_length) - IP4_HDR_LEN(ip);
		pkt->l4_off = pkt->l3_off + IP4_HDR_LEN(ip);
	} else if ((m->packet_type & (RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_TCP)) ==
				     (RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_TCP)) {
		struct rte_ipv6_hdr *ip = packet_ip6_hdr(pkt);

		if (unlikely(ip->proto != IPPROTO_TCP))
			return -ERR_PKT_HAS_IPV6_OPT;

		csum_flags = PKT_RX_L4_CKSUM_GOOD;
		pkt->ip_payload_len = ntohs(ip->payload_len);
		pkt->l4_off = pkt->l3_off + sizeof(struct rte_ipv6_hdr);
		pkt->flags |= PKT_FLAG_IS_IPV6;
	}

	if ((m->ol_flags & csum_flags) != csum_flags) {
		err = verify_csum(pkt);
		if (err)
			return err;
	}

	return 0;
}

/*
 * Handles non-tcp packets here
 */
static __rte_noinline void misc_input(struct tpa_worker *worker, struct packet *pkt)
{
	struct rte_mbuf *m = &pkt->mbuf;
	int err = -ERR_PKT_INVALID_TYPE;

	if (m->packet_type == RTE_PTYPE_L2_ETHER_ARP)
		err = arp_input(worker, pkt);

	free_err_pkt(worker, NULL, pkt, err);
}

int eth_input(struct tpa_worker *worker, int port_id)
{
	struct port_rxq *rxq = dev_port_rxq(port_id, worker->queue);
	uint32_t nr_rx_burst = dev_port_rx_burst(port_id);
	struct packet *tcp_pkts[nr_rx_burst];
	struct packet *pkt;
	uint32_t nr_tcp_pkt = 0;
	uint32_t nr_pkt;
	uint32_t i;
	int err;

	nr_pkt = RTE_MIN(nr_rx_burst, rxq->write - rxq->read);
	WORKER_STATS_ADD(worker, PKT_RECV, nr_pkt);

	for (i = 0; i < nr_pkt; i++) {
		pkt = rxq->pkts[(rxq->read++) & PORT_RXQ_MASK];

		if (i + 1 < nr_pkt) {
			rte_prefetch0(rxq->pkts[rxq->read & PORT_RXQ_MASK]);
			rte_prefetch0(rte_pktmbuf_mtod(&rxq->pkts[rxq->read & PORT_RXQ_MASK]->mbuf, void *));
		}

		err = parse_eth_ip(pkt);
		if (unlikely(err)) {
			free_err_pkt(worker, NULL, pkt, err);
			continue;
		}

		if (likely(pkt->mbuf.packet_type & RTE_PTYPE_L4_TCP))
			tcp_pkts[nr_tcp_pkt++] = pkt;
		else
			misc_input(worker, pkt);
	}

	return tcp_input(worker, tcp_pkts, nr_tcp_pkt);
}
