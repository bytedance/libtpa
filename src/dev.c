/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <rte_malloc.h>

#include "tpa.h"
#include "log.h"
#include "neigh.h"
#include "sock.h"
#include "dev.h"
#include "ip.h"
#include "ctrl.h"

struct net_dev dev;

static char bonding_info[PATH_MAX];
static struct cfg_spec net_cfg_specs[] = {
	{
		.name	= "net.ip",
		.type   = CFG_TYPE_IPV4,
		.data   = &dev.ip4,
		.flags	= CFG_FLAG_RDONLY,
	}, {
		.name	= "net.mask",
		.type   = CFG_TYPE_MASK,
		.data   = &dev.mask,
		.flags	= CFG_FLAG_RDONLY,
	}, {
		.name	= "net.gw",
		.type   = CFG_TYPE_IPV4,
		.data   = &dev.gw4,
		.flags	= CFG_FLAG_RDONLY,
	}, {
		.name	= "net.ip6",
		.type   = CFG_TYPE_IPV6,
		.data   = &dev.ip6,
		.flags	= CFG_FLAG_RDONLY,
	}, {
		.name	= "net.gw6",
		.type   = CFG_TYPE_IPV6,
		.data   = &dev.gw6,
		.flags	= CFG_FLAG_RDONLY,
	}, {
		.name	= "net.mac",
		.type   = CFG_TYPE_MAC,
		.data   = &dev.mac,
		.data_len = sizeof(dev.mac),
		.flags	= CFG_FLAG_RDONLY,
	}, {
		.name	= "net.name",
		.type   = CFG_TYPE_STR,
		.data   = dev.name,
		.data_len = sizeof(dev.name),
		.flags	= CFG_FLAG_RDONLY,
	}, {
		.name   = "net.bonding",
		.type   = CFG_TYPE_STR,
		.data   = bonding_info,
		.data_len = sizeof(bonding_info),
		.flags  = CFG_FLAG_RDONLY,
	}
};

static struct nic_spec nic_spec_list[] = {
	{
	#if RTE_VERSION >= RTE_VERSION_NUM(22,11,0,0)
		.name = "mlx5_pci",
	#else
		.name = "net_mlx5",
	#endif
		.type = DEV_NIC_MLNX,
		.rx_burst_cap = 64
	},
};

static struct nic_spec nic_unknow = {
	.name = "unknown",
	.type = DEV_NIC_UNKNOWN,
	.rx_burst_cap = 32
};

static int net_dev_mtu_get(void)
{
	struct ifreq ifr;
	int fd;

	if (strlen(dev.name) == 0)
		goto def;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		goto def;

	tpa_snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev.name);
	if (ioctl(fd, SIOCGIFMTU, &ifr)) {
		close(fd);
		goto def;
	}

	close(fd);

	return ifr.ifr_mtu;

def:
	LOG_WARN("failed to get dev %s mtu: %s", dev.name, strerror(errno));
	return DEFAULT_MTU;
}

int net_dev_init_early(void)
{
	memset(&dev, 0, sizeof(dev));

	cfg_spec_register(net_cfg_specs, ARRAY_SIZE(net_cfg_specs));
	cfg_section_parse("net");

	dev.mtu = net_dev_mtu_get();

	return 0;
}

static struct dev_port *get_port_by_name(const char *name)
{
	int i;

	if (!name)
		return NULL;

	for (i = 0; i < dev.nr_port; i++) {
		if (strcmp(dev.ports[i].name, name) == 0)
			return &dev.ports[i];
	}

	return NULL;
}

static void handle_link_change(const char *name, int state)
{
	struct dev_port *port = get_port_by_name(name);

	if (!port || state == port->state)
		return;

	port->state = state;

	LOG_WARN("handle port %hu: %s/%s link %s\n", port->port_id, port->name,
		 port->device_id, state == DEV_LINK_UP ? "up" : "down");
}

static int is_bond_slave_backup(const char *slave)
{
	char path[PATH_MAX];
	char state[128];
	int backup = 0;
	FILE *file;

	tpa_snprintf(path, PATH_MAX,
		 "/sys/class/net/%s/bonding_slave/state", slave);
	file = fopen(path, "r");
	if (!file)
		return 0;

	if (fgets(state, sizeof(state), file)) {
		if (!strncmp(state, "backup", 6))
			backup = 1;
	}

	fclose(file);
	return backup;
}

static 	char bonding_path[PATH_MAX];
int parse_bonding_proc_file(const char *path)
{
	char line[1024];
	char slave[DEV_INFO_LEN];
	char state[DEV_INFO_LEN];
	FILE *file;
	int status;

	file = fopen(path, "r");
	if (!file) {
		LOG_ERR("failed to open proc file: %s: %s\n", path, strerror(errno));
		return -1;
	}

	slave[0] = '\0';
	while (fgets(line, sizeof(line), file)) {
		if (strstr(line, "Slave Interface") != NULL) {
			sscanf(line, "%*s %*s %s", slave);
		} else if (strstr(line, "MII Status") != NULL) {
			sscanf(line, "%*s %*s %s", state);

			if (strlen(slave) != 0) {
				if (strcmp(state, "up") == 0 && !is_bond_slave_backup(slave))
					status = DEV_LINK_UP;
				else
					status = DEV_LINK_DOWN;

				handle_link_change(slave, status);
			}
			slave[0] = '\0';
		}
	}

	fclose(file);

	return 0;
}

static void *link_detect(struct ctrl_event *event)
{
	if (parse_bonding_proc_file(bonding_path) != 0) {
		LOG_ERR("failed to proc bonding file, link detect quit");
		ctrl_event_destroy(event);
	}

	return NULL;
}

static int bonding_init(void)
{
	char buf[PATH_MAX];
	uint16_t port_id;
	char *info = buf;
	char *slave;
	char *device_id;
	char *p;

	if (strlen(bonding_info) == 0)
		return -1;

	tpa_snprintf(buf, sizeof(buf), "%s", bonding_info);

	do {
		slave = strtok_r(info, " ", &info);
		if (!slave)
			break;

		p = strchr(slave, '/');
		if (!p) {
			LOG_ERR("bonding init: invalid bonding slave cfg : %s", slave);
			return -1;
		}
		*p = '\0';
		device_id = p + 1;

		if (rte_eth_dev_get_port_by_name(device_id, &port_id) != 0) {
			LOG_ERR("bonding init: invalid slave device id: %s", device_id);
			return -1;
		}
		tpa_snprintf(dev.ports[port_id].name, sizeof(dev.ports[port_id].name), "%s", slave);

		LOG("bonding init: port %hu: name=%s, device_id=%s", port_id, slave, device_id);
	} while (1);

	tpa_snprintf(bonding_path, sizeof(bonding_path), "/proc/net/bonding/%s", dev.name);
	parse_bonding_proc_file(bonding_path);

	ctrl_timeout_event_create(1, link_detect, NULL, "link-detect");

	return 0;
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

struct nic_spec *nic_spec_find_by_type(int type)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(nic_spec_list); i++) {
		if (nic_spec_list[i].type == type)
			return &nic_spec_list[i];
	}

	return &nic_unknow;
}

int dev_port_init(void)
{
	uint16_t i;
	uint64_t txq_size;
	uint64_t rxq_size;
	struct nic_spec *nic_spec;

	txq_size = tpa_cfg.nr_worker * sizeof(struct dev_txq);
	rxq_size = tpa_cfg.nr_worker * sizeof(struct dev_rxq);

	for (i = 0; i < dev.nr_port; i++) {
		dev.ports[i].port_id = i;
		dev.ports[i].state = DEV_LINK_UP;
		dev.ports[i].nr_rx_burst = BATCH_SIZE;

		dev.ports[i].txq = rte_malloc(NULL, txq_size, 64);
		dev.ports[i].rxq = rte_malloc(NULL, rxq_size, 64);
		if (!dev.ports[i].txq || !dev.ports[i].rxq) {
			LOG_ERR("dev port queue malloc error");
			return -1;
		}

		memset(dev.ports[i].txq, 0, txq_size);
		memset(dev.ports[i].rxq, 0, rxq_size);

		nic_spec = nic_spec_find(i);
		if (nic_spec->type == DEV_NIC_UNKNOWN)
			LOG_WARN("detected dpdk port %hu: unknown drv name", i);

		dev.ports[i].nic_spec = nic_spec;
		dev.ports[i].nr_rx_burst = nic_spec->rx_burst_cap;

		rte_eth_dev_get_name_by_port(i, dev.ports[i].device_id);
		LOG("detected dpdk port %hu: %s, drv_name %s",
		    i, dev.ports[i].device_id, nic_spec->name);
	}

	if (dev.nr_port == 2)
		return bonding_init();

	return 0;
}

static void dev_mac_init(void)
{
	if (rte_is_zero_ether_addr(&dev.mac)) {
		/*
		 * XXX: if mac addr is not configured, set the mac to
		 * the mac from port 0.
		 */
		rte_eth_macaddr_get(0, &dev.mac);
	}
}

int net_dev_init(void)
{
	assert(tpa_cfg.nr_dpdk_port <= MAX_PORT_NR);
	dev.nr_port = tpa_cfg.nr_dpdk_port;

	if (dev_port_init() == -1)
		return -1;
	dev_mac_init();

	if (pthread_spin_init(&dev.lock, PTHREAD_PROCESS_PRIVATE) != 0) {
		LOG_ERR("net dev lock init error: %s", strerror(errno));
		return -1;
	}

	pthread_mutex_init(&dev.mutex, NULL);

	return 0;
}
