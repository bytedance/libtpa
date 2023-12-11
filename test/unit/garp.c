/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 * Author: Kai Xiong <xiongkai.123@bytedance.com>
 */
#include <stdio.h>
#include <unistd.h>

#include "test_utils.h"
#include "neigh.h"

static void test_garp_basic(void)
{
	struct packet *pkt;
	struct neigh_entry *entry;
	uint8_t mac[6] = { 0, };
	uint32_t ip = 0x12345678;

	printf("testing %s\n", __func__);

	pkt = make_arp_rsp_pkt(ip, mac);
	ut_arp_input(pkt); {
		entry = neigh_find_ip4(ip);
		assert(entry == NULL);
	}
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_garp_basic();

	return 0;
}
