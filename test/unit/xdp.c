/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023, ByteDance Ltd. and/or its Affiliates
 * Author: Wenlong Luo <luowenlong.linl@bytedance.com>
 */
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <linux/limits.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "test_utils.h"
#include "xdp_ctrl.h"

struct xdp_ctx {
	struct bpf_object *obj;
	int dst_port_map_fd;
} ctx;

static const char *get_xdp_prog_path(void)
{
	static char path[PATH_MAX];

	return tpa_path_resolve("xdp_flow_steering.o", path, sizeof(path));
}

static int xdp_ctx_init(void)
{
	struct bpf_object *obj;
	struct bpf_map *map;
	int map_fd;
	int err;

	obj = bpf_object__open_file(get_xdp_prog_path(), NULL);
	err = libbpf_get_error(obj);
	if (err) {
		printf("failed to open bpf object for %s: %s\n", get_xdp_prog_path(), strerror(errno));
		return -1;
	}

	err = bpf_object__load(obj);
	if (err) {
		printf("failed to load bpf object, %s\n", strerror(errno));
		goto out;
	}

	map = bpf_object__find_map_by_name(obj, "dst_port_map");
	err = libbpf_get_error(map);
	if (err) {
		printf("failed to find dst_port_map: %s\n", strerror(errno));
		goto out;
	}

	map_fd = bpf_map__fd(map);
	assert(map_fd >= 0);

	ctx.obj = obj;
	ctx.dst_port_map_fd = map_fd;
	xdp_prog.maps[MAP_TYPE_DST_PORT].fd = ctx.dst_port_map_fd;

	return 0;

out:
	bpf_object__close(obj);
	assert(0);
}

static void xdp_ctx_uninit(void)
{
	bpf_object__close(ctx.obj);
}

static struct rte_flow_item patterns[8] = {
	{
		.type = RTE_FLOW_ITEM_TYPE_ETH,
	}, {
		.type = RTE_FLOW_ITEM_TYPE_IPV6,
	}, {
		.type = RTE_FLOW_ITEM_TYPE_TCP,
	}, {
		.type = RTE_FLOW_ITEM_TYPE_END,
	},
};

struct xdp_flow *do_xdp_flow_create(int port_id, uint16_t port, uint16_t port_mask)
{
	struct rte_flow_item *item = &patterns[2];
	struct rte_flow_item_tcp tcp_spec;
	struct rte_flow_item_tcp tcp_mask;
	struct rte_flow_error error;

	item->spec = &tcp_spec;
	item->mask = &tcp_mask;

	tcp_spec.hdr.dst_port = htons(port);
	tcp_mask.hdr.dst_port = htons(port_mask);

	return (struct xdp_flow *)xdp_flow_create(port_id, NULL, patterns, NULL, &error);
}

int do_xdp_flow_destroy(struct xdp_flow *flow)
{
	struct rte_flow_error error;

	return xdp_flow_destroy(0, (struct rte_flow *)flow, &error);
}

static void test_xdp_flow_basic(void)
{
	struct xdp_flow *flow;
	uint16_t port = 10000;
	uint16_t port_mask;
	uint16_t key;
	uint8_t queue;
	uint64_t size;
	int i;

	printf("testing %s ...\n", __func__);

	assert(xdp_flow_add_port_rules(port) == 0);
	assert(bpf_map_lookup_elem(ctx.dst_port_map_fd, &port, &queue) == 0);

	assert(xdp_flow_remove_port_rules(port) == 0);
	assert(bpf_map_lookup_elem(ctx.dst_port_map_fd, &port, &queue) != 0);

	size = 64;
	port = 64;
	port_mask = 0xffff & (~(size - 1));

	flow = do_xdp_flow_create(0, port, port_mask);
	assert(flow);
	for (i = 0; i < size; i++) {
		key = port + i;
		assert(bpf_map_lookup_elem(ctx.dst_port_map_fd, &key, &queue) == 0);
	}

	assert(do_xdp_flow_destroy(flow) == 0);
	for (i = 0; i < size; i++) {
		key = port + i;
		assert(bpf_map_lookup_elem(ctx.dst_port_map_fd, &key, &queue) < 0);
	}
}

static void test_xdp_flow_add_remove_bench(void)
{
	uint16_t key = 40000;
	uint64_t cnt = 0;

	printf("testing %s ...\n", __func__);

	WHILE_NOT_TIME_UP() {
		assert(xdp_flow_add_port_rules(key) == 0);
		assert(xdp_flow_remove_port_rules(key) == 0);
		cnt++;
	}

	printf("xdp flow add/remove %lu/s\n", cnt / ut_test_opts.duration);
}

static void test_xdp_flow_create_destory_bench(size_t size)
{
	uint64_t cnt = 0;
	struct xdp_flow *flow;
	uint16_t port = 64;
	uint16_t port_mask = 0xffff & (~(size - 1));

	printf("testing %s ...\n", __func__);

	WHILE_NOT_TIME_UP() {
		flow = do_xdp_flow_create(0, port, port_mask);
		assert(flow);
		assert(do_xdp_flow_destroy(flow) == 0);

		cnt++;
	}

	printf("xdp flow[%lu] create/destory %lu/s\n", size, cnt / ut_test_opts.duration);
}

static uint64_t do_lookup(int fd, uint16_t key)
{
	uint64_t cnt = 0;
	uint8_t queue;

	WHILE_NOT_TIME_UP() {
		bpf_map_lookup_elem(fd, &key, &queue);
		cnt++;
	}

	return cnt;
}

static void test_map_lookup_bench(int nr_entries)
{
	uint16_t key = 40000;
	uint8_t queue = 0;
	uint64_t cnt = 0;
	int i;

	printf("testing %s %d ...\n", __func__, nr_entries);

	for (i = 1; i <= nr_entries; i++) {
		key = i;
		bpf_map_update_elem(ctx.dst_port_map_fd, &key, &queue, 0);
	}

	cnt = do_lookup(ctx.dst_port_map_fd, 1);
	printf("map[%d] lookup[in] %lu/s\n", nr_entries, cnt / ut_test_opts.duration);

	cnt = do_lookup(ctx.dst_port_map_fd, nr_entries + 1);
	printf("map[%d] lookup[out] %lu/s\n", nr_entries, cnt / ut_test_opts.duration);

	for (i = 1; i < nr_entries; i++) {
		key = i;
		bpf_map_delete_elem(ctx.dst_port_map_fd, &key);
	}
}

int main(int argc, char **argv)
{
	ut_init(argc, argv);
	xdp_ctx_init();

	test_xdp_flow_basic();
	test_xdp_flow_add_remove_bench();
	test_xdp_flow_create_destory_bench(64);

	test_map_lookup_bench(10);
	test_map_lookup_bench(1000);
	test_map_lookup_bench(10000);
	test_map_lookup_bench(60000);

	xdp_ctx_uninit();
}