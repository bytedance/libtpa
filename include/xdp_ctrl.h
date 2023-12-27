/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023, ByteDance Ltd. and/or its Affiliates
 * Author: Wenlong Luo <luowenlong.linl@bytedance.com>
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _XDP_CTRL_H_
#define _XDP_CTRL_H_

#include <rte_flow.h>

#ifdef WITH_XDP
#include <linux/bpf.h>

enum {
	MAP_TYPE_DST_IP4,
	MAP_TYPE_DST_IP6,
	MAP_TYPE_DST_PORT,
	MAP_TYPE_XSKS,
	MAP_TYPE_STATS,
	MAP_TYPE_MAX,
};

struct xdp_flow {
	int port_id;
	uint16_t port;
	uint16_t port_mask;
};

struct xdp_map {
	uint32_t id;
	int fd;
	struct bpf_map_info info;
};

struct xdp_prog {
	char name[128];
	uint32_t ifindex;
	uint32_t id;
	int fd;

	struct xdp_map maps[MAP_TYPE_MAX];
	struct bpf_prog_info info;
};

extern struct xdp_prog xdp_prog;

int xdp_ctrl_init(void);

struct rte_flow *xdp_flow_create(uint16_t port_id,
				 const struct rte_flow_attr *attr,
				 const struct rte_flow_item pattern[],
				 const struct rte_flow_action actions[],
				 struct rte_flow_error *error);
int xdp_flow_destroy(uint16_t port_id, struct rte_flow *flow, struct rte_flow_error *error);

int xdp_flow_add_port_rules(uint16_t port);
int xdp_flow_remove_port_rules(uint16_t port);

int xdp_flow_add_port_rules_batch(uint16_t port, int cnt);
int xdp_flow_remove_port_rules_batch(uint16_t port, int cnt);
#else /* !WITH_XDP */
static inline struct rte_flow *xdp_flow_create(uint16_t port_id,
				 const struct rte_flow_attr *attr,
				 const struct rte_flow_item pattern[],
				 const struct rte_flow_action actions[],
				 struct rte_flow_error *error)
{
	return NULL;
}

static inline int xdp_flow_destroy(uint16_t port_id, struct rte_flow *flow, struct rte_flow_error *error)
{
	return -1;
}
#endif /* WITH_XDP */

int xdp_prog_id_query(const char *dev_name);
int xdp_prog_detach(const char *dev_name);

#endif