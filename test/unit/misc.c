/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>

#include "test_utils.h"

static void test_log2_ceil(void)
{
	printf("testing %s ...\n", __func__);

	assert(log2_ceil(1) == 1);
	assert(log2_ceil(2) == 1);
	assert(log2_ceil(3) == 2);
	assert(log2_ceil(4) == 2);
	assert(log2_ceil(5) == 3);
	assert(log2_ceil(8) == 3);
	assert(log2_ceil(9) == 4);
	assert(log2_ceil(16) == 4);
}

int main(int argc, char *argv[])
{
	test_log2_ceil();

	return 0;
}
