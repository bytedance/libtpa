/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>

#include "tperf.h"

static char char_db[256];

void integrity_fill(char *buf, size_t size, uint64_t base)
{
	size_t len;
	uint64_t off = 0;

	do {
		len = MIN(size - off, sizeof(char_db) - ((base + off) & 0xff));
		memcpy(buf + off, &char_db[(base + off) & 0xff], len);
		off += len;
	} while (off < size);
}

int integrity_verify(char *buf, size_t size, uint64_t base)
{
	size_t len;
	uint64_t off = 0;

	do {
		len = MIN(size - off, sizeof(char_db) - ((base + off) & 0xff));
		assert(memcmp(buf + off, &char_db[(base + off) & 0xff], len) == 0);
		off += len;
	} while (off < size);

	return 0;
}

void integrity_init(void)
{
	int i;

	for (i = 0; i < sizeof(char_db); i++)
		char_db[i] = i;
}
