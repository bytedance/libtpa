/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 * Author: Wenlong Luo <luowenlong.linl@bytedance.com>
 */
#ifndef _ARCHIVE_H_
#define _ARCHIVE_H_

#include <dirent.h>

#include "lib/utils.h"
#include "archive_map.h"

struct archive_ctx {
	const char *dir_path;
	const char *prefix;
	int nr_to_keep;

	DIR *dir;
	int prefix_len;

	uint64_t upper_id;
	uint64_t lower_id;
	uint32_t nr_id;
	uint32_t max_nr_id;
	uint64_t *ids;

	struct archive_map *map;
};

static inline void archive_ctx_set_nr_to_keep(struct archive_ctx *ctx, int nr_to_keep)
{
	ctx->nr_to_keep = nr_to_keep;
	ctx->lower_id = ctx->upper_id - ctx->nr_to_keep + 1;
}

static inline char *archive_path(struct archive_ctx *ctx, uint64_t id)
{
	static char path[PATH_MAX];

	tpa_snprintf(path, sizeof(path), "%s/%s%lu", ctx->dir_path, ctx->prefix, id);

	return path;
}

int archive_ctx_init(struct archive_ctx *ctx, const char *dir_path,
		     const char *prefix, int nr_to_keep);
uint64_t archive_raw(struct archive_ctx *ctx, const void *addr, size_t size);


void archive_init_early(void);
void archive_init(void);
void archive_submit(const char *name, int sid, void *data, size_t data_size,
		    void *parser, size_t parser_size);

extern struct rte_ring *record_to_archive_list;

#endif
