/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023, ByteDance Ltd. and/or its Affiliates
 * Author: Wenlong Luo <luowenlong.linl@bytedance.com>
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <linux/limits.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "xdp_ctrl.h"
#include "xdp_common.h"
#include "dev.h"
#include "log.h"

static const struct shell_cmd xdp_cmd;

static const char *map_type_to_str[] = {
	[MAP_TYPE_DST_IP4]     = "dst_ip4_map",
	[MAP_TYPE_DST_IP6]     = "dst_ip6_map",
	[MAP_TYPE_DST_PORT]    = "dst_port_map",
	[MAP_TYPE_XSKS]        = "xsks_map",
	[MAP_TYPE_STATS]       = "xdp_stats",
};

static const char *stats_to_str[] = {
	[XDP_STATS_PASS]	      = "pass",
	[XDP_STATS_REDIRECT]	      = "redirect",
	[XDP_STATS_INVALID_PKT]       = "invalid-pkt",
	[XDP_STATS_NOT_IP]	      = "not-ip",
	[XDP_STATS_NOT_TCP]	      = "not-tcp",
	[XDP_STATS_NO_XSKS]	      = "no-xsks",
	[XDP_STATS_UNEXPECTED_ACTION] = "uexpected-action",
	[XDP_STATS_DST_PORT_MISMATCH] = "dst-port-mismatch",
	[XDP_STATS_DST_IP_MISMATCH]   = "dst-ip-mismatch",
};

struct xdp_prog xdp_prog;

#define MATCH(a, b)	(strcmp(a, b) == 0)

static int xdp_map_type_find(const char *name)
{
	int i;

	for (i = 0; i < MAP_TYPE_MAX; i++) {
		if (MATCH(map_type_to_str[i], name))
			return i;
	}

	return -1;
}

static void xdp_map_init(struct xdp_map *map, int fd, struct bpf_map_info *info)
{
	map->fd = fd;
	map->id = info->id;
	map->info = *info;
}

static int xdp_prog_maps_init(struct xdp_prog *prog, int nr_maps)
{
	struct bpf_prog_info prog_info = {0};
	struct bpf_map_info map_info;
	uint32_t map_ids[nr_maps];
	uint32_t len;
	int fd;
	int err;
	int i;
	int idx;

	len = sizeof(prog_info);
	prog_info.nr_map_ids = nr_maps;
	prog_info.map_ids = (uintptr_t)map_ids;
	err = bpf_obj_get_info_by_fd(prog->fd, &prog_info, &len);
	if (err) {
		LOG_ERR("failed to get xdp prog maps id, %s", strerror(errno));
		return -1;
	}

	len = sizeof(map_info);
	for (i = 0; i < prog_info.nr_map_ids; i++) {
		fd = bpf_map_get_fd_by_id(map_ids[i]);
		if (err) {
			LOG_ERR("failed to get fd by map id %d, %s", map_ids[i], strerror(errno));
			return -1;
		}

		memset(&map_info, 0, sizeof(map_info));
		err = bpf_obj_get_info_by_fd(fd, &map_info, &len);
		if (err) {
			LOG_ERR("failed to get map info for fd %d, %s", strerror(errno));
			return -1;
		}

		idx = xdp_map_type_find(map_info.name);
		debug_assert(idx >= 0);
		xdp_map_init(&prog->maps[idx], fd, &map_info);
	}

	return 0;
}

static int xdp_prog_init(void)
{
	struct bpf_prog_info info = {};
	uint32_t len;
	uint32_t ifindex;
	uint32_t prog_id;
	int fd;
	int err;

	ifindex = if_nametoindex(dev.name);
	if (ifindex == 0) {
		LOG_ERR("failed to get ifindex of %s: %s", dev.name, strerror(errno));
		return -1;
	}

	if (bpf_xdp_query_id(ifindex, XDP_FLAGS_DRV_MODE, &prog_id) < 0) {
		LOG_ERR("failed to query xdp prog id: %s", strerror(errno));
		return -1;
	}

	fd = bpf_prog_get_fd_by_id(prog_id);
	if (fd < 0) {
		LOG_ERR("failed to get fd for xdp prog %d: %s", prog_id, strerror(errno));
		return -1;
	}

	len = sizeof(info);
	err = bpf_obj_get_info_by_fd(fd, &info, &len);
	if (err) {
		LOG_ERR("failed to get xdp prog %d info, fd %d: %s", prog_id, fd, strerror(errno));
		return -1;
	}

	xdp_prog.fd = fd;
	xdp_prog.id = prog_id;
	xdp_prog.ifindex = ifindex;
	xdp_prog.info = info;
	strncpy(xdp_prog.name, info.name, sizeof(xdp_prog.name));

	if (xdp_prog_maps_init(&xdp_prog, info.nr_map_ids) < 0)
		return -1;

	return 0;
}

static int do_xdp_map_update(int type, void *key, void *value)
{
	int fd = xdp_prog.maps[type].fd;
	int err;

	err = bpf_map_update_elem(fd, key, value, 0);
	if (unlikely(err)) {
		LOG_ERR("failed to update map elem for %s: %s",
			 map_type_to_str[type], strerror(errno));
		return -1;
	}

	return 0;
}

static int do_xdp_map_delete(int type, void *key)
{
	int fd = xdp_prog.maps[type].fd;
	int err;

	err = bpf_map_delete_elem(fd, key);
	if (unlikely(err)) {
		LOG_ERR("failed to delete map elem for %s: %s",
			 map_type_to_str[type], strerror(errno));
		return -1;
	}

	return 0;
}

static int xdp_flow_add_ip_rules(void)
{
	uint8_t queue = 0;

	if (dev.ip4 && do_xdp_map_update(MAP_TYPE_DST_IP4, &dev.ip4, &queue) < 0) {
		LOG_ERR("failed to app ip4 into xdp: %s", strerror(errno));
		return -1;
	}

	/* TODO: check ipv6 */
	if (do_xdp_map_update(MAP_TYPE_DST_IP6, &dev.ip6.ip, &queue) < 0) {
		LOG_ERR("failed to app ip6 into xdp: %s", strerror(errno));
		return -1;
	}

	return 0;
}

int xdp_ctrl_init(void)
{
	if (xdp_prog_init() < 0)
		return -1;

	if (xdp_flow_add_ip_rules() < 0)
		return -1;

	shell_register_cmd(&xdp_cmd);

	return 0;
}

int xdp_flow_add_port_rules(uint16_t port)
{
	uint8_t queue = 0;

	if (!port)
		return -1;

	if (do_xdp_map_update(MAP_TYPE_DST_PORT, &port, &queue) < 0)
		return -1;

	return 0;
}

int xdp_flow_remove_port_rules(uint16_t port)
{
	if (!port)
		return -1;

	if (do_xdp_map_delete(MAP_TYPE_DST_PORT, &port) < 0)
		return -1;

	return 0;
}

int xdp_flow_add_port_rules_batch(uint16_t port, int cnt)
{
	int i;
	int ret;

	for (i = 0; i < cnt; i++) {
		ret = xdp_flow_add_port_rules(port + i);
		if (ret < 0) {
			i--;
			goto fail;
		}
	}

	return 0;

fail:
	while (i >= 0) {
		xdp_flow_remove_port_rules(port + i);
		i--;
	}

	return -1;
}

int xdp_flow_remove_port_rules_batch(uint16_t port, int cnt)
{
	int i;
	int ret = 0;

	for (i = 0; i < cnt; i++)
		ret += xdp_flow_remove_port_rules(port + i);

	if (ret != 0)
		return -1;

	return 0;
}

struct rte_flow *xdp_flow_create(uint16_t port_id,
				 const struct rte_flow_attr *attr,
				 const struct rte_flow_item pattern[],
				 const struct rte_flow_action actions[],
				 struct rte_flow_error *error)
{
	const struct rte_flow_item_tcp *tcp_spec;
	const struct rte_flow_item_tcp *tcp_mask;
	const struct rte_flow_item *item = &pattern[0];
	struct xdp_flow *flow;
	uint16_t port;
	uint16_t port_mask;
	uint16_t cnt;
	int i = 0;

	flow = malloc(sizeof(struct xdp_flow));
	if (!flow)
		return NULL;

	do {
		item = &pattern[i++];
		if (item->type == RTE_FLOW_ITEM_TYPE_TCP)
			break;
	} while (item->type != RTE_FLOW_ITEM_TYPE_END);

	if (item->type != RTE_FLOW_ITEM_TYPE_TCP)
		goto fail;

	tcp_spec = item->spec;
	tcp_mask = item->mask;

	port = ntohs(tcp_spec->hdr.dst_port);
	port_mask = ntohs(tcp_mask->hdr.dst_port);
	cnt = ~port_mask + 1;

	if (xdp_flow_add_port_rules_batch(port, cnt) < 0) {
		error->type = RTE_FLOW_ERROR_TYPE_UNSPECIFIED;
		error->cause = NULL;
		error->message = "failed to batch add port rules";

		goto fail;
	}

	flow->port_id = port_id;
	flow->port = port;
	flow->port_mask = port_mask;

	return (struct rte_flow *)flow;

fail:
	free(flow);
	return NULL;
}

int xdp_flow_destroy(uint16_t port_id, struct rte_flow *flow, struct rte_flow_error *error)
{
	struct xdp_flow *xdp_flow = (struct xdp_flow *)flow;
	uint16_t cnt = ~xdp_flow->port_mask + 1;
	int ret = 0;

	if (xdp_flow_remove_port_rules_batch(xdp_flow->port, cnt) < 0) {
		ret = -1;

		error->type = RTE_FLOW_ERROR_TYPE_UNSPECIFIED;
		error->cause = NULL;
		error->message = "failed to batch remove port rules";
	}

	free(flow);

	return ret;
}

static void dump_dst_port(struct shell_buf *reply, uint16_t port)
{
	int fd = xdp_prog.maps[MAP_TYPE_DST_PORT].fd;
	uint8_t queue;
	int err;

	err = bpf_map_lookup_elem(fd, &port, &queue);
	if (err) {
		shell_append_reply(reply, "can't find port %hu: %s\n", port, strerror(errno));
		return;
	}

	shell_append_reply(reply, "port %hu, queue %hhu\n", port, queue);
}

static void dump_dst_port_cnt(struct shell_buf *reply)
{
	int fd = xdp_prog.maps[MAP_TYPE_DST_PORT].fd;
	int cnt = 0;
	void *prev_key = NULL;
	uint16_t port;
	int err;

	while (1) {
		err = bpf_map_get_next_key(fd, prev_key, &port);
		if (err) {
			if (errno == ENOENT)
				err = 0;
			break;
		}

		prev_key = &port;
		cnt++;
	}

	shell_append_reply(reply, "%-32s: %d\n", "port total cnt", cnt);
}

static void dump_stats(struct shell_buf *reply)
{
	int fd = xdp_prog.maps[MAP_TYPE_STATS].fd;
	int i;
	uint32_t stats;
	uint64_t cnt;

	for (i = 0; i < XDP_STATS_MAX; i++) {
		stats = i;
		bpf_map_lookup_elem(fd, &stats, &cnt);
		shell_append_reply(reply, "%-32s: %lu\n", stats_to_str[i], cnt);
	}
}

static int do_ip_lookup(int type, void *addr)
{
	void *prev_key = NULL;
	int fd = xdp_prog.maps[type].fd;
	int err;

	while (1) {
		err = bpf_map_get_next_key(fd, prev_key, addr);
		if (err) {
			if (errno == ENOENT)
				err = 0;
			break;
		}

		prev_key = addr;
	}

	return 0;
}

static void dump_ip(struct shell_buf *reply)
{
	char buf[INET6_ADDRSTRLEN];
	struct in6_addr addr6;
	uint64_t addr4;

	if (do_ip_lookup(MAP_TYPE_DST_IP4, &addr4) == 0)
		shell_append_reply(reply, "%-32s: %s\n", "ip4", inet_ntop(AF_INET, &addr4, buf, sizeof(buf)));

	if (do_ip_lookup(MAP_TYPE_DST_IP6, &addr6) == 0)
		shell_append_reply(reply, "%-32s: %s\n", "ip6", inet_ntop(AF_INET6, &addr6, buf, sizeof(buf)));
}

static int cmd_xdp(struct shell_cmd_info *cmd)
{
	uint16_t port;

	if (cmd->argc == 0) {
		dump_ip(cmd->reply);
		dump_dst_port_cnt(cmd->reply);
		dump_stats(cmd->reply);
	} else if (cmd->argc == 2 && strcmp("port", cmd->argv[0]) == 0) {
		port = atoi(cmd->argv[1]);
		dump_dst_port(cmd->reply, port);
	}

	return 0;
}

static const struct shell_cmd xdp_cmd = {
	.name    = "xdp",
	.handler = cmd_xdp,
};

void xdp_prog_detach(const char *dev_name)
{
	uint32_t ifindex;
	int err;

	ifindex = if_nametoindex(dev_name);
	if (ifindex == 0) {
		LOG_ERR("failed to get ifindex of %s: %s", dev_name, strerror(errno));
		return;
	}

	err = bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL);
	if (err) {
		LOG_ERR("failed to detach xdp prog on dev %u:%s: %s",
			ifindex, dev_name, strerror(errno));
	}
}