/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <sched.h>
#include <pthread.h>
#include <numa.h>

#include <rte_eal.h>
#include <rte_malloc.h>
#include <rte_version.h>
#include <rte_ethdev.h>

#include "tpa.h"
#include "lib/utils.h"
#include "log.h"
#include "cfg.h"
#include "dev.h"
#include "shell.h"
#include "packet.h"
#include "dev.h"
#include "dpdk_compat.h"

#define RX_OFFLOAD	(DEV_RX_OFFLOAD_IPV4_CKSUM	|\
			 DEV_RX_OFFLOAD_TCP_CKSUM)
#define TX_OFFLOAD	(DEV_TX_OFFLOAD_IPV4_CKSUM 	|\
			 DEV_TX_OFFLOAD_TCP_CKSUM	|\
			 DEV_TX_OFFLOAD_MULTI_SEGS	|\
			 DEV_TX_OFFLOAD_TCP_TSO)

struct dpdk_cfg {
	char pci[PATH_MAX];
	char extra_args[PATH_MAX];

	int nr_numa;
	uint32_t numa;
	uint32_t socket_mem[TPA_MAX_NUMA];
	uint32_t mbuf_mem_size;
	uint32_t mbuf_cache_size;
	uint32_t huge_unlink;
};

static struct dpdk_cfg dpdk_cfg = {
	.mbuf_cache_size = 512,
	.numa = -1,
	.huge_unlink = 1,
};

struct packet_pool *generic_pkt_pool;
static uint32_t max_rx_pkt_len = 0;
struct dpdk_port *dpdk_ports;

static struct nic_spec nic_spec_list[] = {
	{
	#if RTE_VERSION >= RTE_VERSION_NUM(20,11,0,0)
		.name = "mlx5_pci",
	#else
		.name = "net_mlx5",
	#endif
		.type = NIC_TYPE_MLNX,
		.rx_burst_cap = 64
	},
};

static struct nic_spec nic_unknow = {
	.name = "unknown",
	.type = NIC_TYPE_UNKNOWN,
	.rx_burst_cap = 32
};

static void show_port_stats(struct shell_buf *reply, int port)
{
	int nr_queue = RTE_MIN(tpa_cfg.nr_worker, RTE_ETHDEV_QUEUE_STAT_CNTRS);
	struct rte_eth_stats stats;
	int i;

	rte_eth_stats_get(port, &stats);
	shell_append_reply(reply, "PORT STATS: %d\n", port);
	shell_append_reply(reply, "\t%-10sRX-packets: %-10lu RX-bytes: %-10lu RX-errors: %-10lu\n",
			   "Total", stats.ipackets, stats.ibytes, stats.ierrors);
	shell_append_reply(reply, "\t%-10sTX-packets: %-10lu TX-bytes: %-10lu TX-errors: %-10lu\n",
			   "Total", stats.opackets, stats.obytes, stats.oerrors);
	shell_append_reply(reply, "\n");

	for (i = 0; i < nr_queue; i++) {
		shell_append_reply(reply, "\tQueue %-3d RX-packets: %-10lu RX-bytes: %-10lu RX-errors: %-10lu\n",
				   i, stats.q_ipackets[i], stats.q_ibytes[i], stats.q_errors[i]);
	}
	shell_append_reply(reply, "\n");

	for (i = 0; i < nr_queue; i++) {
		shell_append_reply(reply, "\tQueue %-3d TX-packets: %-10lu TX-bytes: %-10lu\n",
				   i, stats.q_opackets[i], stats.q_obytes[i]);
	}
	shell_append_reply(reply, "\n");
}

static void show_port_xstats(struct shell_buf *reply, int port)
{
	struct rte_eth_xstat_name *xstats_names = NULL;
	struct rte_eth_xstat *xstats = NULL;
	int len;
	int ret;
	int i;

	len = rte_eth_xstats_get_names(port, NULL, 0);
	if (len < 0) {
		shell_append_reply(reply, "error: cant get xstats count\n");
		goto out;
	}

	xstats = calloc(len, sizeof(*xstats));
	if (!xstats) {
		shell_append_reply(reply, "error: cant alloc mem for xstats\n");
		goto out;
	}

	xstats_names = calloc(len, sizeof(*xstats_names));
	if (!xstats_names) {
		shell_append_reply(reply, "error: cant alloc mem for xstats names\n");
		goto out;
	}

	if (rte_eth_xstats_get_names(port, xstats_names, len) != len) {
		shell_append_reply(reply, "error: cant get xstats names\n");
		goto out;
	}

	ret = rte_eth_xstats_get(port, xstats, len);
	if (ret < 0 || ret > len) {
		shell_append_reply(reply, "error: cant get xstats\n");
		goto out;
	}

	shell_append_reply(reply, "PORT XSTATS: %u\n", port);
	for (i = 0; i < len; i++) {
		if (xstats[i].value != 0) {
			shell_append_reply(reply, "\t%-24s: %lu\n",
					   xstats_names[i].name, xstats[i].value);
		}
	}
	shell_append_reply(reply, "\n");
out:
	free(xstats);
	free(xstats_names);
}

static void do_port_stats_get(struct shell_buf *reply, int port_id)
{
	if (port_id < 0 || port_id >= dev.nr_port) {
		shell_append_reply(reply, "error: invalid port id : %d\n", port_id);
		return;
	}

	shell_append_reply(reply, "PORT[%d](%s):\n", port_id,
			   dev.ports[port_id].state == PORT_LINK_UP ? "UP" : "DOWN");
	show_port_stats(reply, port_id);
	show_port_xstats(reply, port_id);
	shell_append_reply(reply, "\n");
}

static void port_stats_get(struct shell_buf *reply, struct shell_cmd_info *cmd)
{
	int i;
	int port_id;

	if (cmd->argc == 1 || strcmp(cmd->argv[1], "all") == 0) {
		shell_append_reply(reply, "All port down:%lu\n", dev.all_port_down);

		for (i = 0; i < rte_eth_dev_count_avail(); ++i)
			do_port_stats_get(reply, i);

		return;
	}

	port_id = atoi(cmd->argv[1]);
	do_port_stats_get(reply, port_id);
}

static void usage(struct shell_cmd_info *cmd)
{
	shell_append_reply(cmd->reply,
			   "usage: port cmd\n"
			   "            stats [all/port id]  show dpdk port detailed stats\n");
}

static int cmd_port(struct shell_cmd_info *cmd)
{
	if (cmd->argc == 0) {
		usage(cmd);
	} else if (strcmp(cmd->argv[0], "stats") == 0) {
		port_stats_get(cmd->reply, cmd);
	} else {
		shell_append_reply(cmd->reply, "error: invalid cmd: %s\n", cmd->argv[0]);
		usage(cmd);
		return -1;
	}

	return 0;
}

static const struct shell_cmd port_cmd = {
	.name    = "port",
	.handler = cmd_port,
};

struct dpdk_port *get_dpdk_port_by_name(const char *name)
{
	int i;

	if (!name)
		return NULL;

	for (i = 0; i < tpa_cfg.nr_dpdk_port; i++) {
		if (strcmp(dev.ports[i].name, name) == 0)
			return &dev.ports[i];
	}

	return NULL;
}

void set_dpdk_port_name(uint32_t port_id, const char *name)
{
	struct dpdk_port *port;

	if (port_id >= tpa_cfg.nr_dpdk_port)
		return;

	port = &dpdk_ports[port_id];
	tpa_snprintf(port->name, sizeof(port->name), "%s", name);
}

static struct nic_spec *nic_spec_find(int port_id)
{
	struct rte_eth_dev_info dev_info;
	int i;

	if (rte_eth_dev_info_get(port_id, &dev_info) < 0)
		goto out;

	for (i = 0; i < ARRAY_SIZE(nic_spec_list); i++) {
		if (strcmp(dev_info.driver_name, nic_spec_list[i].name) == 0)
			return &nic_spec_list[i];
	}

out:
	return &nic_unknow;
}

static uint32_t translate_caps(uint64_t dpdk_offloads, int nic_type)
{
	uint32_t ret = 0;

	if (dpdk_offloads & DEV_TX_OFFLOAD_IPV4_CKSUM)
		ret |= TX_OFFLOAD_IPV4_CKSUM;

	if (dpdk_offloads & DEV_TX_OFFLOAD_TCP_CKSUM)
		ret |= TX_OFFLOAD_TCP_CKSUM;

	if (dpdk_offloads & DEV_TX_OFFLOAD_TCP_TSO)
		ret |= TX_OFFLOAD_TSO;

	if (dpdk_offloads & DEV_TX_OFFLOAD_MULTI_SEGS)
		ret |= TX_OFFLOAD_MULTI_SEG;

	if (nic_type == NIC_TYPE_MLNX) {
		ret |= TX_OFFLOAD_PSEUDO_HDR_CKSUM;
		ret |= RX_OFFLOAD_PACKET_TYPE;
		ret |= FLOW_OFFLOAD;
		ret |= EXTERNAL_MEM_REGISTRATION;
	}

	return ret;
}

static void dpdk_port_start(struct dpdk_port *port)
{
	int port_id = port->port_id;
	int nr_queue = port->nr_queue;
	int socket_id = rte_eth_dev_socket_id(port_id);
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_txconf txq_conf;
	uint16_t nr_rx_desc = NR_RX_DESC;
	uint16_t nr_tx_desc = NR_RX_DESC;
	struct rte_eth_conf port_conf;
	struct rte_ether_addr mac;
	struct rte_mempool *mempool;
	struct nic_spec *nic_spec;
	int ret;
	int i;

	rte_eth_dev_info_get(port_id, &dev_info);

	memset(&port_conf, 0, sizeof(port_conf));
	dpdk_enable_jumbo_frame(&port_conf, max_rx_pkt_len);
	port_conf.rxmode.offloads = RX_OFFLOAD & dev_info.rx_offload_capa;
	port_conf.txmode.offloads = TX_OFFLOAD & dev_info.tx_offload_capa;
	port_conf.lpbk_mode = 1;

	LOG("init port %hu: nr_queue=%hu rx_offload=%lu tx_offload=%lu",
	    port_id, nr_queue, port_conf.rxmode.offloads, port_conf.txmode.offloads);

	ret = rte_eth_dev_configure(port_id, nr_queue, nr_queue, &port_conf);
	if (ret != 0)
		rte_panic("failed to configure device: %d", ret);

	ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nr_rx_desc, &nr_tx_desc);
	if (ret < 0)
		rte_panic("failed to adjust number of rx tx desc: %d\n", ret);

	ret = rte_eth_macaddr_get(port_id, &mac);
	if (ret < 0)
		rte_panic("failed to get mac address for port %hu: %d\n", port_id, ret);

	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = port_conf.rxmode.offloads;
	mempool = packet_pool_get_mempool(generic_pkt_pool);
	for (i = 0; i < nr_queue; i++) {
		ret = rte_eth_rx_queue_setup(port_id, i, nr_rx_desc, socket_id,
					     &rxq_conf, mempool);
		if (ret < 0)
			rte_panic("failed to setup rx queue %hu: %d", i, ret);
	}

	txq_conf = dev_info.default_txconf;
	txq_conf.offloads = port_conf.txmode.offloads;
	for (i = 0; i < nr_queue; i++) {
		ret = rte_eth_tx_queue_setup(port_id, i, nr_tx_desc, socket_id, &txq_conf);
		if (ret < 0)
			rte_panic("failed to setup tx queue %u: %d", i, ret);
	}

	rte_flow_isolate(port_id, 1, NULL);

	if (rte_eth_dev_start(port_id) < 0)
		rte_panic("failed to start dpdk port %hu", port_id);

	nic_spec = nic_spec_find(port_id);
	port->nic_spec = nic_spec;
	port->nr_rx_burst = nic_spec->rx_burst_cap;
	port->caps = translate_caps(port_conf.txmode.offloads, nic_spec->type);

	rte_eth_dev_get_name_by_port(port_id, port->device_id);
	LOG("started port %hu %s <drv_name=%s> %02X:%02X:%02X:%02X:%02X:%02X",
	    port_id, port->device_id, nic_spec->name,
	    mac.addr_bytes[0], mac.addr_bytes[1], mac.addr_bytes[2],
	    mac.addr_bytes[3], mac.addr_bytes[4], mac.addr_bytes[5]);
}

int dpdk_port_init(struct dpdk_port *port, int port_id, int nr_queue)
{
	uint64_t txq_size;
	uint64_t rxq_size;

	txq_size = nr_queue * sizeof(struct port_txq);
	rxq_size = nr_queue * sizeof(struct port_rxq);

	memset(port, 0, sizeof(struct dpdk_port));
	port->port_id = port_id;
	port->nr_queue = nr_queue;
	port->state = PORT_LINK_UP;
	port->nr_rx_burst = BATCH_SIZE;

	port->txq = rte_malloc(NULL, txq_size, 64);
	port->rxq = rte_malloc(NULL, rxq_size, 64);
	if (!port->txq || !port->rxq) {
		LOG_ERR("dev port queue malloc error");
		return -1;
	}

	memset(port->txq, 0, txq_size);
	memset(port->rxq, 0, rxq_size);

	return 0;
}

static int port_init(int nr_queue)
{
	int nr_port = rte_eth_dev_count_avail();
	int i;

	if (nr_port <= 0)
		return -1;

	shell_register_cmd(&port_cmd);

	dpdk_ports = rte_malloc(NULL, sizeof(struct dpdk_port) * nr_port, 64);
	if (!dpdk_ports) {
		LOG_ERR("failed to allocate memory for dpdk ports");
		return -1;
	}

	tpa_cfg.nr_dpdk_port = nr_port;
	for (i = 0; i < nr_port; i++) {
		dpdk_port_init(&dpdk_ports[i], i, nr_queue);
		dpdk_port_start(&dpdk_ports[i]);
	}

	return 0;
}

/* A rough estimation */
#define MBUF_OBJ_SIZE(data_room)	((data_room) + sizeof(struct packet) + 128)

static struct rte_mempool *alloc_mempool(double percent, uint32_t mbuf_size,
					 const char *name, uint32_t numa)
{
	uint64_t mbuf_mem_size = dpdk_cfg.mbuf_mem_size;
	uint32_t nr_mbuf;
	struct rte_mempool *pool;

	if (mbuf_mem_size == 0) {
		/* Reserve 300M for each numa for other stuff. */
		if (dpdk_cfg.socket_mem[numa] <= 300) {
			LOG_ERR("skip mbuf pool: %s due to not enough mem", name);
			return NULL;
		}

		mbuf_mem_size = (dpdk_cfg.socket_mem[numa] - 300) << 20;
	}

	nr_mbuf = mbuf_mem_size * percent / 100 / MBUF_OBJ_SIZE(mbuf_size);
	pool = rte_pktmbuf_pool_create(name, nr_mbuf, dpdk_cfg.mbuf_cache_size,
				       sizeof(struct packet) - sizeof(struct rte_mbuf),
				       mbuf_size, numa);
	if (!pool)
		LOG_ERR("failed to create mbuf pool: %s", name);

	return pool;
}

int packet_pool_create(struct packet_pool *pool, double percent,
		       uint32_t mbuf_size, const char *fmt, ...)
{
	char name[RTE_MEMPOOL_NAMESIZE];
	va_list ap;
	int len;
	int i;

	va_start(ap, fmt);
	len = vsnprintf(name, sizeof(name), fmt, ap);
	va_end(ap);

	memset(pool, 0, sizeof(struct packet_pool));
	for (i = 0; i < dpdk_cfg.nr_numa; i++) {
		tpa_snprintf(name + len, sizeof(name) - len, "-n%u", i);
		pool->pool[i] = alloc_mempool(percent, mbuf_size, name, i);
	}

	return (pool->pool[0] || pool->pool[1]) ? 0 : -1;
}

static void set_preferred_num(void)
{
	int node = dpdk_cfg.numa;
	char *reason = "";

	if (node < 0 || node >= TPA_MAX_NUMA) {
		node = numa_node_of_cpu(sched_getcpu());
		if (node < 0 || node >= TPA_MAX_NUMA)
			node = 0;

		if (dpdk_cfg.socket_mem[node] < dpdk_cfg.socket_mem[!node]) {
			reason = "due to more memory detected";
			node = !node;
		}

		dpdk_cfg.numa = node;
	}

	LOG("setting preferred node to %d %s", node, reason);
	tpa_cfg.preferred_numa = node;
}

static int get_max_rx_pkt_len(void)
{
	int max_rx_pkt;
	int hw_rx_capa;

	hw_rx_capa = dev.mtu + RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN;
	max_rx_pkt = RTE_MAX(RTE_ETHER_MAX_LEN, tcp_cfg.usr_snd_mss + PKT_MAX_HDR_LEN);
	if (max_rx_pkt > hw_rx_capa) {
		LOG_WARN("warning: set max rx pkt len (%d) > hw capa (%d)",
			 max_rx_pkt, hw_rx_capa);

		max_rx_pkt = RTE_MAX(RTE_ETHER_MAX_LEN, hw_rx_capa);
		/* reclac usr_snd_mss by hw rx capa */
		tcp_cfg.usr_snd_mss = RTE_MAX(0, hw_rx_capa - PKT_MAX_HDR_LEN);
	}

	return max_rx_pkt;
}

/* allocate generic/zwrite/hdr mbufs with ratio 5:2:1 */
static void mbuf_mempool_init(void)
{
	int mbuf_size;
	int ret;

	set_preferred_num();
	max_rx_pkt_len = get_max_rx_pkt_len();

	generic_pkt_pool = rte_malloc(NULL, sizeof(struct packet_pool), 64);
	mbuf_size = RTE_MAX(RTE_MBUF_DEFAULT_DATAROOM,
			    max_rx_pkt_len + sizeof(struct rte_mbuf));
	ret = packet_pool_create(generic_pkt_pool, 62.5, mbuf_size + RTE_PKTMBUF_HEADROOM, "mbuf-mempool");

	PANIC_ON(ret == -1, "failed to allocate generic mempool");
}

static int dpdk_socket_mem_set(struct cfg_spec *spec, const char *val)
{
	if (strchr(val, ',')) {
		if (sscanf(val, "%u,%u", &dpdk_cfg.socket_mem[0], &dpdk_cfg.socket_mem[1]) != 2) {
			LOG_WARN("invalid socket-mem: %s", val);
			return -1;
		}
		dpdk_cfg.nr_numa = 2;
	} else {
		int num;

		num = atoi(val);
		if (num <= 0) {
			LOG_WARN("invalid socket-mem: %s", val);
			return -1;
		}

		dpdk_cfg.socket_mem[0] = atoi(val);
		dpdk_cfg.nr_numa = 1;
	}

	return 0;
}

static void do_dpdk_socket_mem_get(char *buf, int size)
{
	if (dpdk_cfg.nr_numa == 1)
		tpa_snprintf(buf, size, "%u", dpdk_cfg.socket_mem[0]);
	else
		tpa_snprintf(buf, size, "%u,%u", dpdk_cfg.socket_mem[0], dpdk_cfg.socket_mem[1]);
}

static int dpdk_socket_mem_get(struct cfg_spec *spec, char *val)
{
	do_dpdk_socket_mem_get(val, VAL_SIZE);

	return 0;
}

static struct cfg_spec dpdk_cfg_specs[] = {
	{
		.name	  = "dpdk.socket-mem",
		.type     = CFG_TYPE_STR,
		.set      = dpdk_socket_mem_set,
		.get      = dpdk_socket_mem_get,
	}, {
		.name	  = "dpdk.pci",
		.type     = CFG_TYPE_STR,
		.data     = dpdk_cfg.pci,
		.data_len = sizeof(dpdk_cfg.pci),
		.flags	  = CFG_FLAG_RDONLY,
	}, {
		.name	  = "dpdk.extra_args",
		.type     = CFG_TYPE_STR,
		.data     = dpdk_cfg.extra_args,
		.data_len = sizeof(dpdk_cfg.extra_args),
		.flags	  = CFG_FLAG_RDONLY,
	}, {
		.name	  = "dpdk.mbuf_cache_size",
		.type     = CFG_TYPE_UINT,
		.data     = &dpdk_cfg.mbuf_cache_size,
		.max      = RTE_MEMPOOL_CACHE_MAX_SIZE,
	}, {
		.name	  = "dpdk.mbuf_mem_size",
		.type     = CFG_TYPE_SIZE,
		.data     = &dpdk_cfg.mbuf_mem_size,
	}, {
		.name	  = "dpdk.numa",
		.type     = CFG_TYPE_UINT,
		.data     = &dpdk_cfg.numa,
		.max      = TPA_MAX_NUMA - 1,
		.flags	  = CFG_FLAG_HAS_MAX | CFG_FLAG_RDONLY,
	}, {
		.name	  = "dpdk.huge-unlink",
		.type     = CFG_TYPE_UINT,
		.data     = &dpdk_cfg.huge_unlink,
		.flags	  = CFG_FLAG_RDONLY,
	},
};

struct dpdk_args {
	int argc;
	char *argv[1024];
};

static void dpdk_args_push_one(struct dpdk_args *args, const char *arg)
{
	char *p = strdup(arg);

	assert(p);
	args->argv[args->argc++] = p;
}

static void dpdk_args_push_pair(struct dpdk_args *args, const char *name, const char *val)
{
	dpdk_args_push_one(args, name);
	dpdk_args_push_one(args, val);
}

static int has_dpdk_arg_m(struct dpdk_args *args)
{
	int i;

	for (i = 0; i < args->argc; i++) {
		if (strcmp(args->argv[i], "-m") == 0)
			return 1;
	}

	return 0;
}

static void dpdk_args_set_mem(struct dpdk_args *args)
{
	char buf[64];

	if (has_dpdk_arg_m(args)) {
		dpdk_cfg.nr_numa = 1;
		return;
	}

	if (!dpdk_cfg.nr_numa) {
		if (numa_num_configured_nodes() >= 2) {
			dpdk_cfg.socket_mem[0] = 1024;
			dpdk_cfg.socket_mem[1] = 1024;
			dpdk_cfg.nr_numa = 2;
		} else {
			dpdk_cfg.socket_mem[0] = 1024;
			dpdk_cfg.nr_numa = 1;
		}
	}

	do_dpdk_socket_mem_get(buf, sizeof(buf));
	dpdk_args_push_pair(args, "--socket-mem", buf);
	dpdk_args_push_pair(args, "--socket-limit", buf);

	dpdk_args_push_pair(args, "--huge-dir", "/dev/hugepages");

	if (dpdk_cfg.huge_unlink)
		dpdk_args_push_one(args, "--huge-unlink");
}

static void dpdk_args_set_pci(struct dpdk_args *args)
{
	char pci[PATH_MAX];
	char *p;

	tpa_snprintf(pci, sizeof(pci), "%s", dpdk_cfg.pci);

	p = strtok(pci, " ");
	while (p) {
	#if RTE_VERSION >= RTE_VERSION_NUM(20,11,0,0)
		dpdk_args_push_pair(args, "-a", p);
	#else
		dpdk_args_push_pair(args, "-w", p);
	#endif
		p = strtok(NULL, " ");
	}
}

static void dpdk_args_set_extra_args(struct dpdk_args *args)
{
	char extra_args[PATH_MAX];
	char *p;

	tpa_snprintf(extra_args, sizeof(extra_args), "%s", dpdk_cfg.extra_args);
	LOG("dpdk extra arg: %s", extra_args);

	p = strtok(extra_args, " ");
	while (p) {
		dpdk_args_push_one(args, p);
		p = strtok(NULL, " ");
	}
}

static void dpdk_args_dump(struct dpdk_args *args)
{
	char buf[1024];
	int len = 0;
	int i;

	for (i = 0; i < args->argc; i++)
		len += tpa_snprintf(buf + len, sizeof(buf) - len, "%s ", args->argv[i]);

	LOG("dpdk args: %s", buf);
}

static int parse_dpdk_args(struct dpdk_args *args)
{
	static char file_prefix[PATH_MAX];
	char *tpa_master_core;

	args->argc = 0;
	dpdk_args_push_one(args, __progname);

	dpdk_args_set_extra_args(args);

	tpa_master_core = getenv("TPA_MASTER_CORE");
	if (tpa_master_core == NULL)
		tpa_master_core = "0";
	dpdk_args_push_pair(args, "-l", tpa_master_core);

	tpa_snprintf(file_prefix, PATH_MAX, "--file-prefix=%s", tpa_id_get());
	dpdk_args_push_one(args, file_prefix);

	dpdk_args_set_mem(args);
	dpdk_args_set_pci(args);

#if RTE_VERSION >= RTE_VERSION_NUM(20,5,0,0)
	dpdk_args_push_one(args, "--no-telemetry");
#endif
	dpdk_args_push_one(args, "--no-shconf");

	dpdk_args_dump(args);

	return 0;
}

static void eal_init(void)
{
	pthread_t tid = pthread_self();
	struct dpdk_args args;
	int restore_affinity = 1;
	cpu_set_t cpuset;

	if (pthread_getaffinity_np(tid, sizeof(cpuset), &cpuset)) {
		restore_affinity = 0;
		LOG_WARN("failed to get cpu affinity: %s; skip restore", strerror(errno));
	}

	optind = 0;
	parse_dpdk_args(&args);
	if (rte_eal_init(args.argc, args.argv) < 0)
		rte_panic("failed to init DPDK");

	/*
	 * re-init getopt per state by the man page so that when the
	 * APP calls getopt, it will function well.
	 */
	optind = 0;

	/*
	 * rte_eal_init sets the cpu affinity to the master lcore.
	 * We need restore the one we captured before it, otherwise,
	 * all threads created later would be bind to the master lcore.
	 */
	if (restore_affinity && pthread_setaffinity_np(tid, sizeof(cpuset), &cpuset))
		LOG_ERR("failed to restore affinity");

	/*
	 * reset per thread lcore_id; it should be set only for
	 * worker threads. Check worker_run_init for more details.
	 */
	RTE_PER_LCORE(_lcore_id) = LCORE_ID_ANY;

}

void dpdk_init(int nr_queue)
{
	LOG("init: DPDK ...");

	cfg_spec_register(dpdk_cfg_specs, ARRAY_SIZE(dpdk_cfg_specs));
	cfg_section_parse("dpdk");

	eal_init();
	mbuf_mempool_init();
	port_init(nr_queue);
}

static void mempool_walk_func(struct rte_mempool *mp, void *arg)
{
	struct shell_buf *reply = arg;
	uint32_t i;

	shell_append_reply(reply, "%16s  %-8u %-8u ",
			   mp->name, mp->size, rte_mempool_ops_get_count(mp));

	if (mp->cache_size == 0) {
		shell_append_reply(reply, "0\n");
		return;
	}

	for (i = 0; i < RTE_MAX_LCORE; i++) {
		if (mp->local_cache[i].len)
			shell_append_reply(reply, "%d/%-4d ", i, mp->local_cache[i].len);
	}
	shell_append_reply(reply, "\n");
}

static void walk_func_long(struct rte_mempool *mp, void *arg)
{
	struct shell_buf *reply = arg;

	shell_append_reply(reply, "\n%s @%p\n", mp->name, mp);
	shell_append_reply(reply, "\t flags=0x%x\n", mp->flags);
	shell_append_reply(reply, "\t pool=%p\n", mp->pool_data);
	shell_append_reply(reply, "\t iova=0x%lx\n", mp->mz->iova);
	shell_append_reply(reply, "\t nb_mem_chunks=%u\n", mp->nb_mem_chunks);
	shell_append_reply(reply, "\t size=%u\n", mp->size);
	shell_append_reply(reply, "\t populated_size=%u\n", mp->populated_size);
	shell_append_reply(reply, "\t header_size=%u\n", mp->header_size);
	shell_append_reply(reply, "\t elt_size=%u\n", mp->elt_size);
	shell_append_reply(reply, "\t trailer_size=%u\n", mp->trailer_size);
	shell_append_reply(reply, "\t total_obj_size=%u\n",
				  mp->header_size + mp->elt_size + mp->trailer_size);
	shell_append_reply(reply, "\t private_data_size=%u\n", mp->private_data_size);
}

static int show_mempool_stats(struct shell_buf *reply, int verbose)
{
	shell_append_reply(reply, "mempool stats\n");
	shell_append_reply(reply, "=============\n\n");

	shell_append_reply(reply, "%16s  %-8s %-8s %s ...\n",
			   "name", "total", "free", "cache");
	rte_mempool_walk(mempool_walk_func, reply);

	if (verbose)
		rte_mempool_walk(walk_func_long, reply);

	return 0;
}

static void show_rte_malloc_stats(struct shell_buf *reply, int verbose)
{
	FILE *f = tmpfile();
	char line[512];
	int id;

	shell_append_reply(reply, "\nrte_malloc stats\n");
	shell_append_reply(reply, "================\n\n");

	if (!f) {
		shell_append_reply(reply, "error: failed to dump dpdk malloc stats: %s\n",
				   strerror(errno));
		return;
	}

	rte_malloc_dump_stats(f, NULL);

	rewind(f);
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "Heap id:%d", &id) == 1) {
			if (verbose == 0 && id >= numa_num_configured_nodes())
				break;
		}
		shell_append_reply(reply, "%s", line);
	}

	fclose(f);
}

static void show_memzone_stats(struct shell_buf *reply)
{
	FILE *f = tmpfile();
	char line[512];

	shell_append_reply(reply, "\nmemzone stats\n");
	shell_append_reply(reply, "================\n\n");

	if (!f) {
		shell_append_reply(reply, "error: failed to dump dpdk memzone stats: %s\n",
				   strerror(errno));
		return;
	}

	rte_memzone_dump(f);
	rewind(f);
	while (fgets(line, sizeof(line), f)) {
		shell_append_reply(reply, "%s", line);
	}

	fclose(f);
}

static int dump_one_memseg(const struct rte_memseg_list *msl,
			   const struct rte_memseg *ms,
			   size_t len, void *arg)
{
	struct shell_buf *reply = arg;

	shell_append_reply(reply,
			   "\tbase=%p size=%lu pagesize=%lu nr_page=%lu socket=%d external=%s\n",
			   msl->base_va, len, msl->page_sz, len / msl->page_sz,
			   msl->socket_id, msl->external ? "yes" : "no");
	return 0;
}

static void show_memseg_stats(struct shell_buf *reply)
{
	shell_append_reply(reply, "\nmemseg stats\n");
	shell_append_reply(reply, "============\n\n");

	rte_memseg_contig_walk(dump_one_memseg, reply);
}

void show_dpdk_mem_stats(struct shell_buf *reply, int verbose)
{
	show_mempool_stats(reply, verbose);
	show_rte_malloc_stats(reply, verbose);
	show_memseg_stats(reply);

	if (verbose)
		show_memzone_stats(reply);
}
