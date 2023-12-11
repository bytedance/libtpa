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

	dev.nr_port = 2;
	tpa_snprintf(dev.ports[0].name, sizeof(dev.ports[0].name), "%s", "eth0");
	tpa_snprintf(dev.ports[1].name, sizeof(dev.ports[1].name), "%s", "eth1");
	dev.ports[0].state = DEV_LINK_DOWN;
	dev.ports[1].state = DEV_LINK_UP;

	parse_bonding_proc_file(BONDING_PROC_FILE);

	assert(dev.ports[0].state == DEV_LINK_UP);
	assert(dev.ports[1].state == DEV_LINK_DOWN);

	dev.nr_port = 1;
}

int main(int argc, char **argv)
{
	ut_init(argc, argv);

	test_parse_bonding_proc_file();
}