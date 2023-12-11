/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <unistd.h>

#include <tcp.h>

int main(int argc, char *argv[])
{
	uint32_t i;
	uint32_t nr_to_alloc = 10;
	struct tpa_ip local_ip;
	struct tpa_ip remote_ip;
	uint16_t local_port;

	tpa_ip_set_ipv4(&local_ip, 0x0a000020);
	tpa_ip_set_ipv4(&remote_ip, 0x0a000021);

	if (argc >= 2)
		nr_to_alloc = atoi(argv[1]);

	for (i = 0; i < nr_to_alloc; i++) {
		if (argc == 3)
			local_port = (rte_rdtsc() % 60000) + 1024;
		else
			local_port = 32486;

		printf("%010u\n", isn_gen(&local_ip, &remote_ip, local_port, 80));
	}

	return 0;
}
