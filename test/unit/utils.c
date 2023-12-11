/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023, ByteDance Ltd. and/or its Affiliates
 * Author: Wenlong Luo <luowenlong.linl@bytedance.com>
 */
#include <stdio.h>

#include "lib/utils.h"

static void test_tpa_snprintf_basic(void)
{
	char buf[10];
	int ret;

	printf("testing %s ...\n", __func__);

	ret = tpa_snprintf(buf, sizeof(buf), "0123456789"); {
		assert(ret == 9);
		assert(strlen(buf) == 9);
	}

	ret = tpa_snprintf(buf, 1, "1"); {
		assert(ret == 0);
		assert(strlen(buf) == 0);
		assert(buf[0] == '\0');
	}

	buf[0] = 1;
	assert(tpa_snprintf(buf, 0, "1") == 0);
	assert(buf[0] == 1);
}

#define BUF_SIZE	100

static void test_tpa_snprintf_full(void)
{
	char *buf;
	char *str;
	int len = 0;
	int size;
	int ret;

	printf("testing %s ...\n", __func__);

	size = rand() % 1024 + 1;
	buf  = malloc(size);
	str  = strndup("0123456789", rand() % 10 + 1);

	do {
		ret = tpa_snprintf(buf + len, size - len, "%s", str);
		len += ret;
	} while (ret != 0);

	assert(strlen(buf) == size - 1);
	assert(len == size - 1);

	free(str);
}

int main(int argc, char **argv)
{
	test_tpa_snprintf_basic();
	test_tpa_snprintf_full();

	return 0;
}
