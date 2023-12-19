/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022, ByteDance Ltd. and/or its Affiliates
 * Author: Wenlong Luo <luowenlong.linl@bytedance.com>
 */
#include <stdio.h>
#include <unistd.h>

#include "test_utils.h"

#define BONDING_PROC_FILE       "bonding.txt"

static void test_parse_bonding_proc_file(void)
{
	printf("testing parse bonding proc file ...\n");

	tpa_cfg.nr_dpdk_port = 2;
	dev.nr_port = 2;
	set_dpdk_port_name(0, "eth0");
	set_dpdk_port_name(1, "eth1");
	dev.ports[0].state = PORT_LINK_DOWN;
	dev.ports[1].state = PORT_LINK_UP;

	parse_bonding_proc_file(BONDING_PROC_FILE);

	assert(dev.ports[0].state == PORT_LINK_UP);
	assert(dev.ports[1].state == PORT_LINK_DOWN);

	tpa_cfg.nr_dpdk_port = 1;
	dev.nr_port = 1;
}

int main(int argc, char **argv)
{
	ut_init(argc, argv);

	test_parse_bonding_proc_file();
}
