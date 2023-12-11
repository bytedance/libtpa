/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>

#include "test_utils.h"
#include "mem_file.h"

static char *ut_mem_file_path(const char *name)
{
	static char path[PATH_MAX];

	tpa_snprintf(path, sizeof(path), "%s/%s", tpa_root_get(), name);

	return path;
}

static void test_mem_file_expand_basic(void)
{
	struct mem_file *mem_file;
	uint8_t *data;

	printf("testing %s ...\n", __func__);

	mem_file = mem_file_create_expandable(ut_mem_file_path("basic"), 3000, NULL, 1<<20); {
		assert(mem_file != NULL);
	}

	/* now fill the data */
	data = mem_file_data(mem_file);
	memset(data, 0xfe, 3000);

	/*
	 * now expand it and then verify it.
	 */
	assert(mem_file_expand(mem_file, 2000) == 0); {
		int i;

		/* make sure we don't overwrite old data */
		for (i = 0; i < 3000; i++)
			assert(data[i] == 0xfe);

		/* make sure we can access the new area */
		memset(data, 0xfe, 3000 + 2000);
	}
}

static void test_mem_file_expand_failure(void)
{
	struct mem_file *mem_file;
	void *place_holder;

	printf("testing %s ...\n", __func__);

	mem_file = mem_file_create_expandable(ut_mem_file_path("failure"), 3000, NULL, 1<<20); {
		assert(mem_file != NULL);
	}

	/*
	 * place a dummy mapping at the end of above mem file so that
	 * it won't be able to expend.
	 */
	place_holder = mmap((char *)mem_file->hdr + 4096, 1<<30, 0, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); {
		assert(place_holder == (char *)mem_file->hdr + 4096);
	}

	/* now expand it and it should fail */
	assert(mem_file_expand(mem_file, 2000) == -1);

	munmap(place_holder, 1<<30);
}

static void test_mem_file_expand_stress(void)
{
	struct mem_file *mem_file;
	uint64_t init_size = 1;
	uint64_t to_expand;
	int nr_expand = 0;

	printf("testing %s ...\n", __func__);

	mem_file = mem_file_create_expandable(ut_mem_file_path("stress"), init_size, NULL, 1<<20); {
		assert(mem_file != NULL);
	}

	/* 1 << 20 = 1M */
	to_expand = init_size;
	while (nr_expand++ < 20) {
		assert(mem_file_expand(mem_file, to_expand) == 0);
		to_expand <<= 1;
	}

	/* expand would fail as it goes beyond the limit */
	assert(mem_file_expand(mem_file, to_expand) == -1);
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_mem_file_expand_basic();
	test_mem_file_expand_failure();
	test_mem_file_expand_stress();

	return 0;
}
