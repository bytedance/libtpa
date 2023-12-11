/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _ARCHIVE_MAP_H_
#define _ARCHIVE_MAP_H_

#define NR_MAP_ENTRY		(16 * 1024)

/*
 * all tpa id share one single archive map file
 */
#define ARCHIVE_MAP_FILE	"/var/log/tpa/.archive_map"
#define CURR_TRACE_MAP_FILE	"/var/log/tpa/.curr_trace_map"

struct archive_map_entry {
	size_t off;
	uint64_t time; /* in unit of us */
	uint32_t size;
	int sid;
	char reserved[40];
	char name[256 - 64];
	char path[256];
};

struct archive_map {
	uint32_t idx;
	char reserved[8192-4];

	struct archive_map_entry entries[NR_MAP_ENTRY];
};

static inline void archive_map_add(struct archive_map *map, size_t off, uint64_t time,
				   uint32_t size, int sid, const char *name, const char *path)
{
	struct archive_map_entry *entry;
	uint32_t idx;

	if (!map)
		return;

	idx = __sync_fetch_and_add_4(&map->idx, 1) % NR_MAP_ENTRY;
	entry = &map->entries[idx];

	entry->off = off;
	entry->time = time;
	entry->size = size;
	entry->sid = sid;
	tpa_snprintf(entry->name, sizeof(entry->name), "%s", name);
	tpa_snprintf(entry->path, sizeof(entry->path), "%s", path);
}

struct archive_map *map_archive_map_file(const char *path);

#endif
