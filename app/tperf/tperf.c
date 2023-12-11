/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>

#include "tperf.h"

struct ctx ctx;

int main(int argc, char **argv)
{
	parse_options(argc, argv);
	integrity_init();

	if (ctx.is_client)
		return tperf_client();

	return tperf_server();
}
