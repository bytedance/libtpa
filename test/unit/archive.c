/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <unistd.h>

#include "test_utils.h"

static void assert_archive_file_count(const char *prefix, int count)
{
	char cmd[1024];

	tpa_snprintf(cmd, sizeof(cmd), "[ $(ls %s/%s[0-9]* | wc -l) -eq %d ]",
		 tpa_log_root_get(), prefix, count);

	assert(system(cmd) == 0);
}

static void test_archive(const char *prefix, uint32_t data_size,
			 int init_count, int default_count)
{
	struct archive_ctx ctx;
	char *data = malloc(data_size);
	uint64_t start_tsc;
	int i;

	printf(":: testing archive: prefix=%s data_size=%u init_count=%d default_count=%d\n",
		prefix, data_size, init_count, default_count);

	assert(archive_ctx_init(&ctx, tpa_log_root_get(), prefix, init_count) == 0);

	for (i = 0; i < init_count * 2; i++) {
		archive_raw(&ctx, data, data_size);
	} {
		assert(ctx.nr_id == init_count);
		assert_archive_file_count(prefix, init_count);
	}

	/* measure how long it takes to archive one */
	start_tsc = rte_rdtsc();
	archive_raw(&ctx, data, data_size); {
		printf("archive one takes %.3fms\n", (double)(TSC_TO_US(rte_rdtsc() - start_tsc)) / 1000.0);
		assert(ctx.nr_id == init_count);
		assert_archive_file_count(prefix, init_count);
	}

	/* now shrink the budget to default_count */
	archive_ctx_set_nr_to_keep(&ctx, default_count);
	start_tsc = rte_rdtsc();
	archive_raw(&ctx, data, data_size); {
		printf("shrink takes %.3fms\n", (double)(TSC_TO_US(rte_rdtsc() - start_tsc)) / 1000.0);
		assert(ctx.nr_id == default_count);
		assert_archive_file_count(prefix, default_count);
	}

	free(data);
}

int main(int argc, char **argv)
{
	ut_init(argc, argv);

	/* simulate archiving the whole trace file */
	test_archive("trace", 20<<20, 128, 16);

	/* simulate archiving an individual sock trace file */
	test_archive("socktrace", 16 << 10, 8192, 4096);

	return 0;
}
