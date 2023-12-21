/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <stdint.h>

#include "worker.h"
#include "packet.h"

int eth_input(struct tpa_worker *worker, int port_id)
{
	struct port_rxq *rxq = dev_port_rxq(port_id, worker->queue);
	uint32_t nr_rx_burst = dev_port_rx_burst(port_id);
	struct packet *tcp_pkts[nr_rx_burst];
	struct packet *pkt;
	uint32_t nr_pkt;
	uint32_t i;

	nr_pkt = RTE_MIN(nr_rx_burst, rxq->write - rxq->read);
	WORKER_STATS_ADD(worker, PKT_RECV, nr_pkt);

	for (i = 0; i < nr_pkt; i++) {
		pkt = rxq->pkts[(rxq->read++) & PORT_RXQ_MASK];

		if (i + 1 < nr_pkt) {
			rte_prefetch0(rxq->pkts[rxq->read & PORT_RXQ_MASK]);
			rte_prefetch0(rte_pktmbuf_mtod(&rxq->pkts[rxq->read & PORT_RXQ_MASK]->mbuf, void *));
		}

		tcp_pkts[i] = pkt;
	}

	return tcp_input(worker, tcp_pkts, nr_pkt);
}
