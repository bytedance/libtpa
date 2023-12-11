/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "mem_file.h"
#include "archive_map.h"

static struct archive_map_entry entries[NR_MAP_ENTRY];
static int list_all;

static int is_empty_entry(struct archive_map_entry *entry)
{
	return entry->name[0] == '\0';
}

static int is_valid_entry(struct archive_map_entry *entry)
{
	return access(entry->path, F_OK) == 0;
}

static int map_entry_cmp(const void *__a, const void *__b)
{
	const struct archive_map_entry *a = __a;
	const struct archive_map_entry *b = __b;

	return a->time < b->time;
}

static void print_entries(int nr_entry)
{
	struct archive_map_entry *entry;
	static int print_head = 1;
	int valid;
	int i;

	if (print_head) {
		printf("%-42s %-8s %-6s %-28s %-6s %s\n",
		       "path", "off", "size", "time", "sid", "name");
		print_head = 0;
	}

	for (i = 0; i < nr_entry; i++) {
		entry = &entries[i];
		valid = is_valid_entry(entry);

		if (!(list_all || valid))
			continue;

		if (!valid)
			strcat(entry->path, "[deleted]");

		printf("%-42s %-8lu %-6u %-28s %-6d %s\n",
		       entry->path, entry->off, entry->size,
		       str_time(entry->time), entry->sid, entry->name);
	}
}

static void sock_trace_list(struct archive_map *map)
{
	struct archive_map_entry *entry;
	int nr_entry = 0;
	int i;

	if (!map)
		return;

	for (i = 0; i < NR_MAP_ENTRY; i++) {
		entry = &entries[nr_entry];

		memcpy(entry, &map->entries[i], sizeof(struct archive_map_entry));
		if (is_empty_entry(entry))
			continue;

		nr_entry += 1;
	}

	qsort(entries, nr_entry, sizeof(struct archive_map_entry), map_entry_cmp);
	print_entries(nr_entry);
}

static struct archive_map *map_file(const char *path)
{
	struct mem_file *mem_file;

	mem_file = mem_file_map(path, NULL, MEM_FILE_READ);
	if (!mem_file)
		return NULL;

	return mem_file_data(mem_file);
}

int main(int argc, char *argv[])
{
	if (argc > 1 && strcmp(argv[1], "-a") == 0)
		list_all = 1;

	sock_trace_list(map_file(CURR_TRACE_MAP_FILE));
	sock_trace_list(map_file(ARCHIVE_MAP_FILE));

	return 0;
}
