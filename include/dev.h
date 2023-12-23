/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _DEV_H_
#define _DEV_H_

#include <netinet/in.h>

#include "ip.h"
#include "pktfuzz.h"
#include "dpdk_port.h"

#define DEFAULT_MTU			1500
#define DEFAULT_MAX_MTU			9216
#define PKT_MAX_HDR_LEN			128

struct dev_ip {
	int prefixlen;
	struct tpa_ip ip;
};

struct net_dev {
	uint32_t ip4;
	uint32_t mask;
	uint32_t gw4;

	int nic;
	uint32_t caps;
	uint32_t pkt_max_chain;

	struct dev_ip ip6;
	struct dev_ip gw6;

	struct rte_ether_addr mac;
	struct rte_ether_addr gw_mac;

	struct dpdk_port *ports;
	uint16_t nr_port;

	pthread_spinlock_t lock;
	uint64_t all_port_down;

	pthread_mutex_t mutex;


	char name[32];
	uint16_t mtu;
};

extern struct net_dev dev;

int net_dev_init_early(void);
int net_dev_init(void);

static inline struct port_txq *dev_port_txq(uint16_t port_id, uint16_t queue_id)
{
	return &dev.ports[port_id].txq[queue_id];
}

static inline struct port_rxq *dev_port_rxq(uint16_t port_id, uint16_t queue_id)
{
	return &dev.ports[port_id].rxq[queue_id];
}

static inline uint32_t dev_port_rx_burst(uint16_t port_id)
{
	return dev.ports[port_id].nr_rx_burst;
}

static inline int dev_port_txq_free_count(uint16_t port_id, uint16_t queue_id)
{
	return TXQ_BUF_SIZE - dev_port_txq(port_id, queue_id)->nr_pkt;
}

static inline uint16_t dev_port_id_get(void)
{
	static uint16_t idx = 0;
	uint16_t i;
	uint16_t ret;

	pthread_spin_lock(&dev.lock);
	for (i = 0; i < dev.nr_port; i++) {
		ret = (idx++) % dev.nr_port;
		if (dev.ports[ret].state == PORT_LINK_UP) {
			pthread_spin_unlock(&dev.lock);
			return ret;
		}
	}
	pthread_spin_unlock(&dev.lock);

	__sync_fetch_and_add_8(&dev.all_port_down, 1);

	/* return port 0 when every ports of cur dev is down */
	return dev.ports[0].port_id;
}

static inline void dev_port_txq_flush(uint16_t port_id, uint16_t queue_id)
{
	struct port_txq *txq = dev_port_txq(port_id, queue_id);
	uint16_t count;

	if (txq->nr_pkt == 0 || tpa_cfg.nr_dpdk_port == 0)
		return;

	/*
	 * We should do dump before tx burst, as the driver may
	 * free some of them (say the heading pkts on zwrite).
	 * It may lead to some duplication dump though, when
	 * partial of the pkts are transmited successfully.
	 */
	count = RTE_MIN(txq->nr_pkt, (uint16_t)BATCH_SIZE);

	debug_assert(port_id < dev.nr_port);
	if (unlikely(dev.ports[port_id].state != PORT_LINK_UP))
		port_id = dev_port_id_get();

	count = rte_eth_tx_burst(port_id, queue_id, (struct rte_mbuf **)txq->pkts, count);

	txq->nr_pkt -= count;
	if (txq->nr_pkt)
		memmove(&txq->pkts[0], &txq->pkts[count], txq->nr_pkt * sizeof(struct packet *));
}

static inline void dev_txq_flush(uint16_t queue_id)
{
	uint16_t i;

	for (i = 0; i < dev.nr_port; i++) {
		dev_port_txq_flush(i, queue_id);
	}
}

static inline void dev_port_txq_drain(uint16_t port_id, uint16_t queue_id)
{
	struct port_txq *txq = dev_port_txq(port_id, queue_id);
	if (txq->nr_pkt == 0 || tpa_cfg.nr_dpdk_port == 0)
		return;

	while (txq->nr_pkt) {
		dev_port_txq_flush(port_id, queue_id);
	}
}

static inline void dev_txq_drain(uint16_t queue_id)
{
	uint16_t i;

	for (i = 0; i < dev.nr_port; i++) {
		dev_port_txq_drain(i, queue_id);
	}
}

static inline int dev_port_txq_enqueue(uint16_t port_id, uint16_t queue_id, struct packet *pkt)
{
	struct port_txq *txq = dev_port_txq(port_id, queue_id);

	if (txq->nr_pkt >= TXQ_BUF_SIZE)
		return -ERR_DEV_TXQ_FULL;

	txq->pkts[txq->nr_pkt++] = pkt;

	pktfuzz(txq);

	if (txq->nr_pkt >= BATCH_SIZE)
		dev_port_txq_flush(port_id, queue_id);

	return 0;
}

static inline void dev_port_rxq_recv(uint16_t port_id, uint16_t queue_id)
{
	struct port_rxq *rxq = dev_port_rxq(port_id, queue_id);
	uint32_t nr_rx_burst = dev_port_rx_burst(port_id);
	struct packet *pkts[nr_rx_burst];
	uint32_t nr_pkt;
	uint32_t budget;
	uint64_t now = 0;
	uint32_t i;

	/*
	 * When incast traffic pattern happens and the APP is processing slowly
	 * (say due to some heavy operations), it's very likely libtpa/DPDK will
	 * not get enough chance to drain the NIC rx queue, therefore, pkt loss
	 * happens.
	 *
	 * To mitigate it, here we try to recv as many pkts as we can, and
	 * process them later.
	 */
	while (1) {
		budget = PORT_RXQ_SIZE - (rxq->write - rxq->read);
		budget = RTE_MIN(budget, nr_rx_burst);
		if (budget == 0)
			break;

		nr_pkt = rte_eth_rx_burst(port_id, queue_id, (struct rte_mbuf **)pkts, budget);

		for (i = 0; i < nr_pkt; i++) {
			packet_init(pkts[i]);

			pkts[i]->port_id = port_id;

			if (unlikely(tcp_cfg.measure_latency)) {
				if (!now)
					now = rte_rdtsc();
				pkts[i]->flags |= PKT_FLAG_MEASURE_READ_LATENCY;
				pkts[i]->read_tsc.start = now;
			}

			rxq->pkts[(rxq->write++) & PORT_RXQ_MASK] = pkts[i];
		}

		if (nr_pkt < budget)
			break;
	}
}

static inline void dev_rxq_recv(uint16_t queue_id)
{
	uint16_t i;

	for (i = 0; i < dev.nr_port; i++) {
		dev_port_rxq_recv(i, queue_id);
	}
}

int parse_bonding_proc_file(const char *path);

#endif
