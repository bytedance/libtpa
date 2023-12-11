/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 * Author: Wenlong Luo <luowenlong.linl@bytedance.com>
 */
#ifndef _MEM_FILE_H_
#define _MEM_FILE_H_

#include "lib/utils.h"

#define MEM_FILE_MAGIC		0x454c49465f4d454d	/* MEM_FILE */
#define MEM_FILE_NAME_LEN	256

#define MEM_FILE_READ		(1 << 0)
#define MEM_FILE_WRITE		(1 << 1)
#define MEM_FILE_NO_UNLINK	(1 << 2)
#define MEM_FILE_EXPANDABLE	(1 << 3)

/* the disk layout */
struct mem_file_hdr {
	uint64_t magic;
	uint64_t size;
	uint64_t data_offset;
	uint64_t parser_offset;
	char name[MEM_FILE_NAME_LEN];
} __attribute__((__aligned__(64)));

struct mem_file {
	struct mem_file_hdr *hdr;

	char path[PATH_MAX];
	int fd;
	int flags;
	size_t limit;
};

static inline void *mem_file_data(struct mem_file *mem_file)
{
	return (uint8_t *)mem_file->hdr + mem_file->hdr->data_offset;
}

/*
 * We used to put data before parser (if any). This layout
 * is not friendly for dynamic expanding. Therefore, we now
 * put data at last.
 */
static inline uint64_t mem_file_data_size(struct mem_file *mem_file)
{
	/* legacy layout */
	if (mem_file->hdr->parser_offset > mem_file->hdr->data_offset)
		return mem_file->hdr->parser_offset - mem_file->hdr->data_offset;

	/* new layout */
	return mem_file->hdr->size - mem_file->hdr->data_offset;
}

static inline uint64_t mem_file_parser_size(struct mem_file *mem_file)
{
	return mem_file->hdr->size - mem_file_data_size(mem_file);
}

static inline void *mem_file_parser(struct mem_file *mem_file)
{
	return (uint8_t *)mem_file->hdr + mem_file->hdr->parser_offset;
}

static inline char *parser_path_resolve(const char *bin, char *path, int size)
{
	char parser[128];

	tpa_snprintf(parser, sizeof(parser), "%s-parser", bin);
	return tpa_path_resolve(parser, path, size);
}

void mem_file_init(void);
struct mem_file *do_mem_file_create(const char *path, size_t size, const char *parser,
				    int flags, size_t limit);
struct mem_file *mem_file_create_expandable(const char *path, size_t size,
					    const char *parser, size_t limit);
struct mem_file *mem_file_create(const char *path, size_t size, const char *parser);
int mem_file_expand(struct mem_file *mem_file, size_t size);
void *mem_file_construct(void *data, size_t data_size, void *parser,
			 size_t parser_size, size_t *total_size);

void *mem_file_map_raw(const char *path, size_t *size, int flags);
void *mem_file_map(const char *path, size_t *size, int flags);

static inline void *mem_file_map_data(const char *path, int flags)
{
	struct mem_file *mem_file;

	mem_file = mem_file_map(path, NULL, flags);
	if (!mem_file)
		return NULL;

	return mem_file_data(mem_file);
}

#endif /* _MEM_FILE_H_ */
