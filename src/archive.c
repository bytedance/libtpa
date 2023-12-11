/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 * Author: Wenlong Luo <luowenlong.linl@bytedance.com>
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <rte_ring.h>

#include "tpa.h"
#include "log.h"
#include "mem_file.h"
#include "archive.h"
#include "worker.h"
#include "tcp_queue.h"
#include "tsock_trace.h"
#include "ctrl.h"

struct archive_record {
	int sid;
	size_t size;
	char *buf;
	char name[PATH_MAX];
};

struct record_stats {
	uint64_t nr_archived;
	uint64_t nr_alloc_failure;
	uint64_t nr_enqueue_failure;
	uint64_t nr_construct_failure;
};

static struct archive_ctx archive_ctx;

#define ARCHIVE_RING_SIZE	64
static struct rte_ring *record_free_list;
struct rte_ring *record_to_archive_list;
static struct record_stats record_stats;

static uint32_t flush_interval = 60; /* in unit of seconds */
static uint32_t enable_archive = 1;

/* TODO: we could make more be configurable */
static struct cfg_spec archive_cfg_specs[] = {
	{
		.name	= "archive.enable",
		.type   = CFG_TYPE_UINT,
		.data   = &enable_archive,
	}, {
		.name	= "archive.flush_interval",
		.type   = CFG_TYPE_UINT,
		.data   = &flush_interval,
		.flags  = CFG_FLAG_HAS_MIN,
		.min    = 1,
	},
};

static struct archive_record *archive_record_alloc(void)
{
	struct archive_record *record;

	if (!record_free_list)
		return NULL;

	if (rte_ring_dequeue(record_free_list, (void **)&record) < 0) {
		__sync_fetch_and_add_8(&record_stats.nr_alloc_failure, 1);
		return NULL;
	}

	debug_assert(record->buf == NULL);

	return record;
}

static void archive_record_free(struct archive_record *record)
{
	free(record->buf);
	record->buf = NULL;

	if (record_free_list)
		rte_ring_enqueue(record_free_list, record);
}

static void queue_to_archive_list(struct archive_record *record)
{
	if (!record_to_archive_list)
		return;

	if (rte_ring_enqueue(record_to_archive_list, record) < 0) {
		archive_record_free(record);
		__sync_fetch_and_add_8(&record_stats.nr_enqueue_failure, 1);
	}
}

static void flush_one_archive_record(struct archive_record *record)
{
	uint64_t id;

	id = archive_raw(&archive_ctx, record->buf, record->size);
	if (id != UINT64_MAX) {
		archive_map_add(archive_ctx.map, 0, get_time_in_us(), record->size,
				record->sid, record->name, archive_path(&archive_ctx, id));
	}
	archive_record_free(record);

	record_stats.nr_archived += 1;
}

static void *flush_archive_record(struct ctrl_event *event)
{
	struct archive_record *record;
	int nr_flushed = 0;

	if (!record_to_archive_list)
		return NULL;

	while (1) {
		if (rte_ring_dequeue(record_to_archive_list, (void **)&record) != 0)
			break;

		flush_one_archive_record(record);

		nr_flushed += 1;
		if (nr_flushed >= ARCHIVE_RING_SIZE)
			break;

		usleep(1000);
	}

	return NULL;
}

void archive_submit(const char *name, int sid, void *data, size_t data_size,
		    void *parser, size_t parser_size)
{
	struct archive_record *record;

	record = archive_record_alloc();
	if (!record)
		return;

	record->sid = sid;
	tpa_snprintf(record->name, sizeof(record->name), "%s", name);

	record->buf = mem_file_construct(data, data_size, parser, parser_size, &record->size);
	if (!record->buf) {
		archive_record_free(record);
		__sync_fetch_and_add_8(&record_stats.nr_construct_failure, 1);
		return;
	}

	queue_to_archive_list(record);
}

void archive_init_early(void)
{
	archive_ctx_init(&archive_ctx, tpa_log_root_get(), "socktrace", 4096);
}

static int cmd_archive(struct shell_cmd_info *cmd)
{
	struct shell_buf *reply = cmd->reply;

	shell_append_reply(reply, "ctx.dir: %s\n",         archive_ctx.dir_path);
	shell_append_reply(reply, "ctx.prefix: %s\n",      archive_ctx.prefix);
	shell_append_reply(reply, "ctx.nr_to_keep: %d\n",  archive_ctx.nr_to_keep);
	shell_append_reply(reply, "ctx.nr_archives: %d\n", archive_ctx.nr_id);
	shell_append_reply(reply, "ctx.next_id: %lu\n",    archive_ctx.upper_id);

	shell_append_reply(reply, "stats.nr_archived: %lu\n",          record_stats.nr_archived);
	shell_append_reply(reply, "stats.nr_alloc_failure: %lu\n",     record_stats.nr_alloc_failure);
	shell_append_reply(reply, "stats.nr_enqueue_failure: %lu\n",   record_stats.nr_enqueue_failure);
	shell_append_reply(reply, "stats.nr_construct_failure: %lu\n", record_stats.nr_construct_failure);

	return 0;
}

static const struct shell_cmd archive_cmd = {
	.name    = "archive",
	.handler = cmd_archive,
};

void archive_init(void)
{
	int i;

	cfg_spec_register(archive_cfg_specs, ARRAY_SIZE(archive_cfg_specs));
	cfg_section_parse("archive");

	shell_register_cmd(&archive_cmd);

	if (!enable_archive)
		return;

	ctrl_timeout_event_create(flush_interval, flush_archive_record, NULL, "archive-flush");

	record_free_list = rte_ring_create("record-ring", ARCHIVE_RING_SIZE, SOCKET_ID_ANY, 0);
	record_to_archive_list = rte_ring_create("archive-ring", ARCHIVE_RING_SIZE, SOCKET_ID_ANY, 0);

	if (!record_free_list || !record_to_archive_list)
		return;

	for (i = 0; i < ARCHIVE_RING_SIZE; i++) {
		struct archive_record *record;

		record = malloc(sizeof(struct archive_record));
		if (!record)
			break;

		memset(record, 0, sizeof(*record));
		rte_ring_enqueue(record_free_list, record);
	}
}

static void archive_ctx_push_id(struct archive_ctx *ctx, uint64_t id)
{
	if (ctx->nr_id == ctx->max_nr_id) {
		ctx->ids = realloc(ctx->ids, sizeof(uint64_t) * ctx->max_nr_id * 2);
		if (!ctx->ids)
			return;

		ctx->max_nr_id *= 2;
	}

	ctx->ids[ctx->nr_id++] = id;
}

static int sort_id(const void *a, const void *b)
{
	return *(uint64_t *)a > *(uint64_t *)b;
}

static void archive_ctx_sort_id(struct archive_ctx *ctx)
{
	qsort(ctx->ids, ctx->nr_id, sizeof(uint64_t), sort_id);
}

#define INIT_MAX_NR_ID		4096
static int ctx_id_init(struct archive_ctx *ctx)
{
	struct dirent *de;
	uint64_t id;

	ctx->ids = malloc(sizeof(uint64_t) * INIT_MAX_NR_ID);
	if (!ctx->ids)
		return -1;

	ctx->max_nr_id = INIT_MAX_NR_ID;

	while (1) {
		de = readdir(ctx->dir);
		if (!de)
			break;

		if (strncmp(de->d_name, ctx->prefix, ctx->prefix_len) != 0)
			continue;

		if (sscanf(de->d_name + ctx->prefix_len, "%lu", &id) != 1)
			continue;

		if (id > ctx->upper_id)
			ctx->upper_id = id;

		archive_ctx_push_id(ctx, id);
	}

	ctx->lower_id = ctx->upper_id - ctx->nr_to_keep + 1;
	archive_ctx_sort_id(ctx);

	return 0;
}

static int delete_old_archives(struct archive_ctx *ctx)
{
	char path[PATH_MAX];
	int nr_deleted = 0;
	uint32_t i;

	if (ctx->nr_id < ctx->nr_to_keep)
		return 0;

	for (i = 0; i < ctx->nr_id; i++) {
		/* it's sorted */
		if (ctx->ids[i] > ctx->lower_id)
			break;

		tpa_snprintf(path, sizeof(path), "%s/%s%lu",
			 ctx->dir_path, ctx->prefix, ctx->ids[i]);

		LOG_DEBUG("deleting archive %s", path);
		if (unlink(path) < 0) {
			LOG_WARN("failed to delete %s: %s", path, strerror(errno));
			return -1;
		}

		nr_deleted += 1;
	}

	ctx->nr_id -= nr_deleted;
	if (ctx->nr_id)
		memmove(ctx->ids, &ctx->ids[nr_deleted], ctx->nr_id * sizeof(uint64_t));

	LOG_DEBUG("deleted %d archives", nr_deleted);

	return 0;
}

struct archive_map *map_archive_map_file(const char *path)
{
	struct mem_file *mem_file;

	mem_file = do_mem_file_create(path, sizeof(struct archive_map),
				      NULL, MEM_FILE_NO_UNLINK, 0);
	if (!mem_file)
		return NULL;

	return mem_file_data(mem_file);
}


int archive_ctx_init(struct archive_ctx *ctx, const char *dir_path,
		     const char *prefix, int nr_to_keep)
{
	DIR *dir;

	if (mkdir_p(dir_path) < 0) {
		LOG_ERR("failed to create dir %s: %s", dir_path, strerror(errno));
		return -1;
	}

	dir = opendir(dir_path);
	if (!dir) {
		LOG_ERR("failed to open dir %s: %s", dir_path, strerror(errno));
		return -1;
	}

	memset(ctx, 0, sizeof(*ctx));
	ctx->dir_path = dir_path;
	ctx->prefix = prefix;
	ctx->nr_to_keep = nr_to_keep;
	ctx->dir = dir;
	ctx->prefix_len = strlen(prefix);

	if (ctx_id_init(ctx) < 0) {
		closedir(dir);
		return -1;
	}

	ctx->map = map_archive_map_file(ARCHIVE_MAP_FILE);

	LOG_DEBUG("archive ctx: dir=%s prefix=%s nr_id=%d upper_id=%lu",
		  dir_path, prefix, ctx->nr_id, ctx->upper_id);

	return 0;
}

uint64_t archive_raw(struct archive_ctx *ctx, const void *addr, size_t size)
{
	char *path;
	int fd;

	if (delete_old_archives(ctx) < 0)
		return UINT64_MAX;

	path = archive_path(ctx, ctx->upper_id + 1);
	fd = open(path, O_WRONLY | O_CREAT | O_NONBLOCK, 0644);
	if (fd < 0) {
		LOG_WARN("failed to open archive file %s for write: %s",
			 path, strerror(errno));
		return UINT64_MAX;
	}

	if (write(fd, addr, size) != size) {
		LOG_WARN("failed to write archive file %s: %s",
			 path, strerror(errno));
		close(fd);
		return UINT64_MAX;
	}

	close(fd);

	ctx->upper_id += 1;
	ctx->lower_id += 1;
	archive_ctx_push_id(ctx, ctx->upper_id);

	return ctx->upper_id;
}
