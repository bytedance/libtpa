/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>

#include "test_utils.h"

static void test_ip_basic(void)
{
	struct tpa_ip ip;

	printf("testing %s ...\n", __func__);

	assert(tpa_ip_from_str(&ip, "::ffff:1.2.3.4") != NULL);
	assert(tpa_ip_is_ipv4(&ip));

	assert(tpa_ip_from_str(&ip, "1.2.3.4") != NULL);
	assert(tpa_ip_is_ipv4(&ip));

	assert(tpa_ip_from_str(&ip, "127.0.0.1") != NULL);
	assert(tpa_ip_is_ipv4(&ip) && tpa_ip_is_loopback(&ip));

	assert(tpa_ip_from_str(&ip, "::1") != NULL);
	assert(!tpa_ip_is_ipv4(&ip) && tpa_ip_is_loopback(&ip));
}

static void test_ipv6_in_same_subnet(void)
{
	struct tpa_ip local;
	struct tpa_ip remote;

	printf("testing %s ...\n", __func__);

	local = (struct tpa_ip){
		.u8 = {
			0xfe, 0x80, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00,
		},
	};

	remote = (struct tpa_ip){
		.u8 = {
			0xfe, 0x80, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x12, 0x34, 0x56, 0x78, 0xab, 0xbc, 0xcd, 0xde,
		},
	};

	assert(in_same_subnet(&local, &remote, 63) == 1);
	assert(in_same_subnet(&local, &remote, 64) == 1);
	assert(in_same_subnet(&local, &remote, 65) == 1);
	assert(in_same_subnet(&local, &remote, 96) == 1);
	assert(in_same_subnet(&local, &remote, 97) == 0);


	remote.u8[1] = 0x7f;
	assert(in_same_subnet(&local, &remote, 8) == 1);
	assert(in_same_subnet(&local, &remote, 9) == 0);
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_ip_basic();
	test_ipv6_in_same_subnet();

	return 0;
}
