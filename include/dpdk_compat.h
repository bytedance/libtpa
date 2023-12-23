/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
 * Author: Tao Liu <liutao.xyz@bytedance.com>
 */
#ifndef _DPDK_COMPAT_H_
#define _DPDK_COMPAT_H_

#include <rte_ethdev.h>
#include <rte_version.h>


#if RTE_VERSION >= RTE_VERSION_NUM(22,11,0,0)

#undef  PKT_RX_IP_CKSUM_GOOD
#define PKT_RX_IP_CKSUM_GOOD		RTE_MBUF_F_RX_IP_CKSUM_GOOD
#undef  PKT_RX_L4_CKSUM_GOOD
#define PKT_RX_L4_CKSUM_GOOD		RTE_MBUF_F_RX_L4_CKSUM_GOOD
#undef  PKT_RX_FDIR_ID
#define PKT_RX_FDIR_ID			RTE_MBUF_F_RX_FDIR_ID

#undef  PKT_TX_IP_CKSUM
#define PKT_TX_IP_CKSUM 		RTE_MBUF_F_TX_IP_CKSUM
#undef  PKT_TX_TCP_CKSUM
#define PKT_TX_TCP_CKSUM		RTE_MBUF_F_TX_TCP_CKSUM
#undef  PKT_TX_TCP_SEG
#define PKT_TX_TCP_SEG			RTE_MBUF_F_TX_TCP_SEG

#undef  PKT_TX_IPV4
#define PKT_TX_IPV4			RTE_MBUF_F_TX_IPV4
#undef  PKT_TX_IPV6
#define PKT_TX_IPV6			RTE_MBUF_F_TX_IPV6

#undef  ETH_RSS_IP
#define ETH_RSS_IP			RTE_ETH_RSS_IP
#undef  ETH_RSS_TCP
#define ETH_RSS_TCP			RTE_ETH_RSS_TCP
#undef  ETH_RSS_NONFRAG_IPV6_TCP
#define ETH_RSS_NONFRAG_IPV6_TCP	RTE_ETH_RSS_NONFRAG_IPV6_TCP
#undef  ETH_RSS_NONFRAG_IPV4_TCP
#define ETH_RSS_NONFRAG_IPV4_TCP	RTE_ETH_RSS_NONFRAG_IPV4_TCP

#undef  DEV_RX_OFFLOAD_IPV4_CKSUM
#define DEV_RX_OFFLOAD_IPV4_CKSUM	RTE_ETH_RX_OFFLOAD_IPV4_CKSUM
#undef  DEV_RX_OFFLOAD_TCP_CKSUM
#define DEV_RX_OFFLOAD_TCP_CKSUM	RTE_ETH_RX_OFFLOAD_TCP_CKSUM
#undef  DEV_TX_OFFLOAD_IPV4_CKSUM
#define DEV_TX_OFFLOAD_IPV4_CKSUM	RTE_ETH_TX_OFFLOAD_IPV4_CKSUM
#undef  DEV_TX_OFFLOAD_TCP_CKSUM
#define DEV_TX_OFFLOAD_TCP_CKSUM	RTE_ETH_TX_OFFLOAD_TCP_CKSUM
#undef  DEV_TX_OFFLOAD_MULTI_SEGS
#define DEV_TX_OFFLOAD_MULTI_SEGS	RTE_ETH_TX_OFFLOAD_MULTI_SEGS
#undef  DEV_TX_OFFLOAD_TCP_TSO
#define DEV_TX_OFFLOAD_TCP_TSO		RTE_ETH_TX_OFFLOAD_TCP_TSO

#define ETH_SRC_ADDR(eth)		(&(eth)->src_addr)
#define ETH_DST_ADDR(eth)		(&(eth)->dst_addr)

static inline struct rte_device *eth_device_get(uint16_t port)
{
	struct rte_eth_dev_info dev_info;
	int err;

	err = rte_eth_dev_info_get(port, &dev_info);
	if (err != 0)
		return NULL;

	return dev_info.device;
}

static inline void dpdk_enable_jumbo_frame(struct rte_eth_conf *conf, uint32_t max_rx_pkt_len)
{
	conf->rxmode.mtu = max_rx_pkt_len;
}

#else

#define ETH_SRC_ADDR(eth)		(&(eth)->s_addr)
#define ETH_DST_ADDR(eth)		(&(eth)->d_addr)

static inline struct rte_device *eth_device_get(uint16_t port)
{
	return rte_eth_devices[port].device;
}

static inline void dpdk_enable_jumbo_frame(struct rte_eth_conf *conf, uint32_t max_rx_pkt_len)
{
	if (max_rx_pkt_len > RTE_ETHER_MAX_LEN)
		conf->rxmode.offloads |= DEV_RX_OFFLOAD_JUMBO_FRAME;

	conf->rxmode.max_rx_pkt_len = max_rx_pkt_len;
}

/*
 * just to make the build happy
 */
#define RTE_FLOW_ACTION_TYPE_PORT_REPRESENTOR		-1

struct rte_flow_action_ethdev {
	uint16_t port_id;
};

#endif

#endif /* _DPDK_COMPAT_H_ */
