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

static void handle_link_change(const char *name, int state)
{
	struct dpdk_port *port = get_dpdk_port_by_name(name);

	if (!port || state == port->state)
		return;

	port->state = state;

	LOG_WARN("handle port %hu: %s/%s link %s\n", port->port_id, port->name,
		 port->device_id, state == PORT_LINK_UP ? "up" : "down");
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
	char slave[PORT_INFO_LEN];
	char state[PORT_INFO_LEN];
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
					status = PORT_LINK_UP;
				else
					status = PORT_LINK_DOWN;

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
		set_dpdk_port_name(port_id, slave);

		LOG("bonding init: port %hu: name=%s, device_id=%s", port_id, slave, device_id);
	} while (1);

	tpa_snprintf(bonding_path, sizeof(bonding_path), "/proc/net/bonding/%s", dev.name);
	parse_bonding_proc_file(bonding_path);

	ctrl_timeout_event_create(1, link_detect, NULL, "link-detect");

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

static int dev_port_init(void)
{
	dev.ports = dpdk_ports;

	/* FIXME: remove the barrier */
	rte_smp_wmb();
	dev.nr_port = tpa_cfg.nr_dpdk_port;

	if (dev.nr_port == 0) {
		/*
		 * Return 0 here to not break ut
		 * FIXME: we should return -1.
		 */
		return 0;
	}

	dev.caps = dev.ports[0].caps;
	dev.nic  = dev.ports[0].nic_spec->type;
	dev.pkt_max_chain = dev.ports[0].nic_spec->pkt_max_chain;
	dev.write_chunk_size = dev.ports[0].nic_spec->write_chunk_size;

	if (dev.nr_port == 2) {
		/* be conservative here: caps intersection is taken */
		dev.caps = dev.ports[0].caps & dev.ports[1].caps;

		if (dev.ports[0].nic_spec != dev.ports[1].nic_spec) {
			LOG_ERR("bonding requires slaves to be the same nic type");
			return -1;
		}

		if (bonding_init() < 0)
			return -1;
	}

	return 0;
}

int net_dev_init(void)
{
	assert(tpa_cfg.nr_dpdk_port <= MAX_PORT_NR);

	if (dev_port_init() < 0)
		return -1;

	dev_mac_init();

	if (pthread_spin_init(&dev.lock, PTHREAD_PROCESS_PRIVATE) != 0) {
		LOG_ERR("net dev lock init error: %s", strerror(errno));
		return -1;
	}

	pthread_mutex_init(&dev.mutex, NULL);


	return 0;
}
