/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _DPDK_PORT_H_
#define _DPDK_PORT_H_

#include <rte_ether.h>
#include <rte_ethdev.h>

#include "cfg.h"

#define NR_RX_DESC			4096
#define NR_TX_DESC			4096

#define BATCH_SIZE			64
#define TXQ_BUF_SIZE			4096

#define PORT_RXQ_SIZE			NR_RX_DESC
#define PORT_RXQ_MASK			(PORT_RXQ_SIZE - 1)
#define MAX_PORT_NR			2


#define TX_OFFLOAD_IPV4_CKSUM		(1u << 0)
#define TX_OFFLOAD_TCP_CKSUM		(1u << 1)
#define TX_OFFLOAD_TSO			(1u << 2)
#define TX_OFFLOAD_MULTI_SEG		(1u << 3)
#define TX_OFFLOAD_PSEUDO_HDR_CKSUM	(1u << 4)

struct port_txq {
	uint16_t nr_pkt;
	uint64_t nr_dropped;
	struct packet *pkts[TXQ_BUF_SIZE];
} __rte_cache_aligned;

struct port_rxq {
	uint32_t write;
	uint32_t read;
	struct packet *pkts[PORT_RXQ_SIZE];
} __rte_cache_aligned;

#define PORT_INFO_LEN		128

enum {
	PORT_LINK_DOWN,
	PORT_LINK_UP,
};

enum {
	NIC_TYPE_MLNX = 1,
	NIC_TYPE_UNKNOWN,
};

struct nic_spec {
	char *name;
	int type;
	uint32_t rx_burst_cap;
};

struct dpdk_port {
	uint16_t port_id;
	uint16_t nr_queue;
	int state;

	uint32_t nr_rx_burst;
	uint32_t caps;

	struct port_txq *txq;
	struct port_rxq *rxq;

	char name[PORT_INFO_LEN];
	char device_id[PORT_INFO_LEN];

	struct nic_spec *nic_spec;
} __rte_cache_aligned;

extern struct dpdk_port *dpdk_ports;

struct dpdk_port *get_dpdk_port_by_name(const char *name);
void set_dpdk_port_name(uint32_t port_id, const char *name);
int dpdk_port_init(struct dpdk_port *port, int port_id, int nr_queue);

#endif
