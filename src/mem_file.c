/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 * Author: Wenlong Luo <luowenlong.linl@bytedance.com>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

#include "log.h"
#include "tpa.h"
#include "mem_file.h"

/* DPDK virtual address starts from 4G, here we start from 1T */
static char *next_map_addr = (char *)(uintptr_t)(1ull << 40);
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

struct mem_file *do_mem_file_create(const char *path, size_t size, const char *parser,
				    int flags, size_t limit)
{
	struct mem_file *mem_file;
	struct mem_file_hdr *hdr;
	char parser_path[PATH_MAX];
	void *parser_bin = NULL;
	size_t parser_size = 0;
	size_t mem_file_size;
	int err;
	int fd;

	mem_file = malloc(sizeof(struct mem_file));
	if (!mem_file) {
		LOG_ERR("failed to alloc mem file struct: %s: %s\n", path, strerror(errno));
		return NULL;
	}

	/*
	 * It's observed that tpad may get waken up few seconds (or even
	 * longer than that) after the APP is terminated. That leaves us a
	 * race that the APP may be restarted before the last tpad quits.
	 * And when the last tpad get wakenup for reclaiming socks, it
	 * reclaims the newly created socks by this new instance instead of
	 * the old one.
	 *
	 * Below unlink would avoid above issue.
	 */
	if (!(flags & MEM_FILE_NO_UNLINK))
		unlink(path);

	fd = open(path, O_RDWR | O_CREAT, 0644);
	if (fd < 0) {
		LOG_ERR("failed to open file: %s: %s\n", path, strerror(errno));
		free(mem_file);
		return NULL;
	}

	if (parser) {
		if (parser_path_resolve(parser, parser_path, sizeof(parser_path))) {
			parser_bin = mem_file_map_raw(parser_path, &parser_size, MEM_FILE_READ);
			parser_size = ROUND_UP(parser_size, 64);
		} else {
			LOG_WARN("failed to locate parser %s", parser);
		}
	}

	mem_file_size = sizeof(struct mem_file_hdr) + parser_size + size;

	do {
		err = posix_fallocate(fd, 0, mem_file_size);
	} while (err == EINTR);
	if (err) {
		LOG_ERR("failed to fallocate file: %s: %s\n", path, strerror(err));
		goto fail;
	}

	pthread_mutex_lock(&mutex);
	hdr = mmap(next_map_addr, mem_file_size, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_POPULATE, fd, 0);
	if ((char *)hdr == next_map_addr) {
		if (flags & MEM_FILE_EXPANDABLE) {
			limit += sizeof(struct mem_file_hdr) + parser_size;
			if (limit < mem_file_size)
				limit = mem_file_size;
		} else {
			limit = mem_file_size;
		}
		next_map_addr += ROUND_UP(limit, 4096);
	}
	pthread_mutex_unlock(&mutex);

	if (hdr == MAP_FAILED) {
		LOG_ERR("failed to mmap file: %s: %s\n", path, strerror(errno));
		goto fail;
	}

	mem_file->hdr = hdr;
	mem_file->fd = fd;
	mem_file->flags = flags;
	mem_file->limit = limit;
	tpa_snprintf(mem_file->path, sizeof(mem_file->path), "%s", path);

	hdr->size = mem_file_size;
	hdr->magic = MEM_FILE_MAGIC;
	hdr->parser_offset = sizeof(struct mem_file_hdr);
	hdr->data_offset = hdr->parser_offset + parser_size;
	if (parser_bin) {
		memcpy(mem_file_parser(mem_file), parser_bin, parser_size);
		munmap(parser_bin, parser_size);
	}

	return mem_file;

fail:
	close(fd);
	unlink(path);
	free(mem_file);

	return NULL;
}

struct mem_file *mem_file_create(const char *path, size_t size, const char *parser)
{
	return do_mem_file_create(path, size, parser, 0, 0);
}

struct mem_file *mem_file_create_expandable(const char *path, size_t size,
					    const char *parser, size_t limit)
{
	return do_mem_file_create(path, size, parser, MEM_FILE_EXPANDABLE, limit);
}

int mem_file_expand(struct mem_file *mem_file, size_t size)
{
	size_t new_size = mem_file->hdr->size + size;
	void *addr;
	int err;

	/* not really a warn but this operation deserves a higher priority */
	LOG_WARN("expanding %s to size %lu ...", mem_file->path, new_size);

	if (!(mem_file->flags & MEM_FILE_EXPANDABLE)) {
		LOG_ERR("failed to expand %s to size %lu: not expendable",
			mem_file->path, new_size);
		return -1;
	}

	if (new_size > mem_file->limit) {
		LOG_ERR("failed to expand %s to size %lu: up to the size limit %lu",
			mem_file->path, new_size, mem_file->limit);
		return -1;
	}

	do {
		err = posix_fallocate(mem_file->fd, 0, new_size);
	} while (err == EINTR);
	if (err) {
		LOG_ERR("failed to expand %s to size %lu: fallocate failed: %s",
			mem_file->path, new_size, strerror(err));
		return -1;
	}

	addr = mremap(mem_file->hdr, mem_file->hdr->size, new_size, 0);
	if (addr == MAP_FAILED) {
		LOG_ERR("failed to expand %s to size %lu: mremap failed: %s",
			mem_file->path, new_size, strerror(errno));
		return -1;
	}

	/*
	 * If succeeds, then addr has to be the original map addr as
	 * we don't specify MREMAP_MAYMOVE flag. Below assert serves
	 * as a double confirm.
	 *
	 * XXX: we probably should revoke the remap here if that truly
	 * happens.
	 */
	assert(addr == (void *)mem_file->hdr);

	mem_file->hdr->size += size;

	return 0;
}

void *mem_file_construct(void *data, size_t data_size, void *parser,
			 size_t parser_size, size_t *total_size)
{
	struct mem_file_hdr *hdr;
	size_t size = data_size + parser_size + sizeof(struct mem_file_hdr);

	hdr = malloc(size);
	if (!hdr)
		return NULL;

	hdr->magic = MEM_FILE_MAGIC;
	hdr->size = size;
	hdr->data_offset = sizeof(struct mem_file_hdr);
	hdr->parser_offset = sizeof(struct mem_file_hdr) + data_size;

	if (data)
		memcpy((char *)hdr + hdr->data_offset, data, data_size);
	if (parser)
		memcpy((char *)hdr + hdr->parser_offset, parser, parser_size);

	*total_size = size;
	return hdr;
}

void *mem_file_map_raw(const char *path, size_t *size, int flags)
{
	int fd;
	int prot = PROT_READ;
	int open_flags = O_RDONLY;
	void *addr;
	size_t file_size;
	struct stat st;

	if (flags & MEM_FILE_WRITE) {
		open_flags = O_RDWR;
		prot |= PROT_WRITE;
	}

	fd = open(path, open_flags);
	if (fd < 0) {
		LOG_ERR("failed to open file: %s: %s\n", path, strerror(errno));
		return NULL;
	}

	if (fstat(fd, &st) < 0) {
		LOG_ERR("failed to stat file: %s: %s\n", path, strerror(errno));
		close(fd);
		return NULL;
	}
	file_size = st.st_size;

	addr = mmap(NULL, file_size, prot, MAP_SHARED, fd, 0);
	close(fd);
	if (addr == MAP_FAILED) {
		LOG_ERR("failed to mmap file: %s: %s\n", path, strerror(errno));
		return NULL;
	}

	if (size)
		*size = st.st_size;

	return addr;
}

void *mem_file_map(const char *path, size_t *size, int flags)
{
	struct mem_file *mem_file;
	struct mem_file_hdr *hdr;
	size_t file_size;

	mem_file = malloc(sizeof(struct mem_file));
	if (!mem_file)
		return NULL;

	hdr = mem_file_map_raw(path, &file_size, flags);
	if (!hdr)
		return NULL;

	if (hdr->magic != MEM_FILE_MAGIC) {
		LOG_ERR("mem_file magic mismatch: expecting 0x%lx while getting 0x%lx",
			MEM_FILE_MAGIC, hdr->magic);
		goto err;
	}

	if (hdr->size > file_size) {
		LOG_ERR("mem_file size (%ld) is great than real file size (%zd)",
			hdr->size, file_size);
		goto err;
	}

	if (hdr->data_offset >= file_size) {
		LOG_ERR("mem_file data offset(%ld) is beyond file size(%zd)",
			hdr->data_offset, file_size);
		goto err;
	}

	if (hdr->parser_offset > file_size) {
		LOG_ERR("mem_file parser offset(%ld) is beyond file size(%zd)",
			hdr->parser_offset, file_size);
		goto err;
	}

	if (size)
		*size = file_size;

	mem_file->hdr = hdr;
	mem_file->fd = -1; /* hmm ... */
	tpa_snprintf(mem_file->path, sizeof(mem_file->path), "%s", path);

	return mem_file;
err:
	free(mem_file);
	munmap(hdr, file_size);
	return NULL;
}
