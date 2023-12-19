/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

#include "test_utils.h"

#define EXTBUF_SIZE		(1<<30)
#define EXTBUF_PGSZ		(1<<12)

static void test_extmem_basic(void)
{
	void *addr;

	printf("%s\n", __func__);

	addr = mmap(NULL, EXTBUF_SIZE, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	assert(addr != MAP_FAILED);
	memset(addr, 0, EXTBUF_SIZE);

	assert(tpa_extmem_register(addr, EXTBUF_SIZE, NULL,
					EXTBUF_SIZE / EXTBUF_PGSZ, EXTBUF_PGSZ) == 0);

	assert(tpa_extmem_unregister(addr, EXTBUF_SIZE) == 0);
	assert(munmap(addr, EXTBUF_SIZE) == 0);
}

static void test_extmem_stress(void)
{
	void *addr;
	int i;

	printf("%s\n", __func__);

	for (i = 0; i < 30; i++) {
		addr = mmap(NULL, EXTBUF_SIZE, PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		assert(addr != MAP_FAILED);
		memset(addr, 0, EXTBUF_SIZE);

		assert(tpa_extmem_register(addr, EXTBUF_SIZE, NULL,
						EXTBUF_SIZE / EXTBUF_PGSZ, EXTBUF_PGSZ) == 0);

		assert(tpa_extmem_unregister(addr, EXTBUF_SIZE) == 0);
		assert(munmap(addr, EXTBUF_SIZE) == 0);
	}
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	dev.caps |= EXTERNAL_MEM_REGISTRATION;

	test_extmem_basic();
	test_extmem_stress();

	return 0;
}
