/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/file.h>
#include <numa.h>

#include <rte_eal.h>
#include <rte_malloc.h>

#include "api/tpa.h"

#include "sock.h"
#include "neigh.h"
#include "log.h"
#include "tpa.h"
#include "shell.h"
#include "dev.h"
#include "worker.h"
#include "archive.h"
#include "ctrl.h"

#include "version.h"
#include "build-info.h"
#include "pktfuzz.h"

/* Using PATH_MAX makes gcc (8.3) complain */
#define TPA_ROOT_PATH_MAX		80

static struct timeval startup_time;
static const char *tpa_id;
int flock_fd = -1;

static const struct shell_cmd mem_stats_cmd;
static const struct shell_cmd vstats_reset_cmd;
static const struct shell_cmd uptime_cmd;

static void tpa_id_set(const char *id)
{
	tpa_id = strdup(id);
}

const char *tpa_id_get(void)
{
	/* mainly for tools; as they do not set tpa_id */
	if (getenv("TPA_ID"))
		return getenv("TPA_ID");

	return tpa_id;
}

static const char *tpa_root_prefix_get(void)
{
	const char *prefix;

	prefix = getenv("TPA_ROOT_PREFIX");
	if (prefix == NULL)
		prefix = "/var/run/tpa";

	return prefix;
}

const char *tpa_root_get(void)
{
	static char tpa_root[TPA_ROOT_PATH_MAX];

	if (tpa_root[0])
		return tpa_root;

	tpa_snprintf(tpa_root, sizeof(tpa_root), "%s/%s",
		    tpa_root_prefix_get(), tpa_id_get());

	return tpa_root;
}

const char *tpa_log_root_get(void)
{
	static char tpa_log_root[TPA_ROOT_PATH_MAX];
	char *prefix;

	if (tpa_log_root[0])
		return tpa_log_root;

	prefix = getenv("TPA_LOG_ROOT_PREFIX");
	if (prefix == NULL)
		prefix = "/var/log/tpa";

	tpa_snprintf(tpa_log_root, sizeof(tpa_log_root), "%s/%s", prefix, tpa_id_get());

	return tpa_log_root;
}

static const char *flock_path_get(const char *id)
{
	static char path[PATH_MAX];
	char dir[PATH_MAX];

	tpa_snprintf(dir, sizeof(dir), "%s/%s", tpa_root_prefix_get(), id);
	mkdir_p(dir);

	tpa_snprintf(path, sizeof(path), "%s/flock", dir);
	return path;
}

static void create_pid_file(void)
{
	FILE *file;
	char path[PATH_MAX];

	mkdir_p(tpa_root_get());
	tpa_snprintf(path, sizeof(path), "%s/pid", tpa_root_get());

	file = fopen(path, "w");
	if (!file)
		return;

	fprintf(file, "%d\n", getpid());

	fclose(file);
}

static int do_tpa_lock(const char *id)
{
	const char *path;
	int fd;

	path = flock_path_get(id);
	fd = open(path, O_RDWR | O_CLOEXEC | O_CREAT, 0600);
	if (fd < 0) {
		fprintf(stderr, "failed to open flock file: %s: %s\n",
			path, strerror(errno));
		return -1;
	}

	if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
		close(fd);
		return -1;
	}

	flock_fd = fd;
	tpa_id_set(id);
	create_pid_file();

	return 0;
}

static int tpa_lock(void)
{
	char name[128];
	const char *id;
	int i = 0;
	int ret;

	id = getenv("TPA_ID");
	if (id) {
		ret = do_tpa_lock(id);
		if (ret < 0)
			fprintf(stderr, "The app with TPA_ID=%s is already running\n", id);

		return ret;
	}

	/*
	 * No TPA_ID given; let's make one based on the
	 * program name.
	 */
	if (do_tpa_lock(__progname) == 0)
		return 0;

	while (1) {
		tpa_snprintf(name, sizeof(name), "%s%d", __progname, ++i);
		if (do_tpa_lock(name) == 0)
			break;
	}

	return 0;
}

static int early_init(void)
{
	archive_init_early();
	net_dev_init_early();

	trace_init();
	if (sock_init_early() == -1)
		return -1;

	/*
	 * fork tpad as early as possible so that it inherits as less
	 * resources as it can from the libtpa APP instance.
	 */
	tpad_init();

	return 0;
}

int tpa_init(int nr_worker)
{
	RTE_BUILD_BUG_ON(sizeof(struct packet) != 64 * 4);
	RTE_BUILD_BUG_ON(sizeof(struct tpa_sock_opts) != 128);

	gettimeofday(&startup_time, NULL);
	LOG("Libtpa version: %s; nr_worker=%d; id=%s", TPA_VERSION, nr_worker, tpa_id_get());
	LOG("build info: %s <%s @%s> %s", BUILD_MODE, BUILD_COMPILER, BUILD_BOX, BUILD_DATE);

	if (tpa_lock() == -1)
		return -1;

	if (nr_worker <= 0)
		return -1;

	cfg_init();

	/* XXX: can be only done after cfg_init */
	log_init();

	if (early_init() == -1)
		return -1;

	if (ctrl_init() == -1)
		return -1;

	shell_init();

	dpdk_init(nr_worker);
	if (worker_init(nr_worker) < 0)
		return -1;

	if (net_dev_init() == -1)
		return -1;

	neigh_init();

	offload_init();
	sock_init();

	pktfuzz_init();

	archive_init();

	shell_register_cmd(&mem_stats_cmd);
	shell_register_cmd(&vstats_reset_cmd);
	shell_register_cmd(&uptime_cmd);

	/* XXX: it's ugly */
	cfg_dump_unknown_opts();

	shell_exec_postinit_cmd();

	return 0;
}

int tpa_extmem_register(void *virt_addr, size_t len, uint64_t *phys_addrs,
			     int nr_page, size_t page_size)
{
#ifdef NIC_MLNX
	uint16_t port;
	int err;

	err = rte_extmem_register(virt_addr, len, (rte_iova_t *)phys_addrs,
				  nr_page, page_size);
	if (err) {
		LOG_ERR("failed to register extmem: va=%p len=%zd page_size=%zd nr_page=%d",
			virt_addr, len, page_size, nr_page);
		return err;
	}

	RTE_ETH_FOREACH_DEV(port) {
		struct rte_device *device = eth_device_get(port);
		if (device == NULL) {
			LOG_ERR("failed to get eth device when register extmem");
			return -1;
		}

		err = rte_dev_dma_map(device, virt_addr, 0, len);
		if (err) {
			LOG_ERR("failed to map DMA for port %hu: va=%p len=%zd", port, virt_addr, len);
			rte_extmem_unregister(virt_addr, len);

			return err;
		}
	}

	LOG("registered extmem: va=%p len=%zd page_size=%zd nr_page=%d",
	    virt_addr, len, page_size, nr_page);
#endif

	return 0;
}

int tpa_extmem_unregister(void *virt_addr, size_t len)
{
#ifdef NIC_MLNX
	uint16_t port;
	int err;

	/*
	 * TODO: we need make sure no inflight packet belong to
	 * this memory region exist.
	 */
	RTE_ETH_FOREACH_DEV(port) {
		struct rte_device *device = eth_device_get(port);
		if (device == NULL) {
			LOG_ERR("failed to get eth device when unregister extmem");
			return -1;
		}

		err = rte_dev_dma_unmap(device, virt_addr, 0, len);
		if (err)
			LOG_ERR("failed to unmap DMA for port %hu: va=%p len=%zd", port, virt_addr, len);
	}

	err = rte_extmem_unregister(virt_addr, len);
	if (err) {
		LOG_ERR("failed to unregister extmem: va=%p len=%zd", virt_addr, len);
		return err;
	}

	LOG("unregistered extmem: va=%p len=%zd", virt_addr, len);
#endif

	return 0;
}

struct get_memsegs_ctx {
	int max_seg;
	int idx;
	int failed;
	struct tpa_memseg *segs;
};

static void append_one_memseg(struct get_memsegs_ctx *ctx, void *virt_addr,
			      size_t size, uint32_t page_size)
{
	struct tpa_memseg *seg;

	if (ctx->failed)
		return;

	if (ctx->idx == ctx->max_seg) {
		int max_seg;

		max_seg = ctx->max_seg;
		if (max_seg == 0)
			max_seg = 1;
		max_seg *= 2;

		ctx->segs = realloc(ctx->segs, max_seg * sizeof(struct tpa_memseg));
		if (ctx->segs == NULL) {
			ctx->failed = 1;
			return;
		}
		ctx->max_seg = max_seg;
	}

	seg = &ctx->segs[ctx->idx++];
	seg->virt_addr = virt_addr;
	seg->phys_addr = 0;
	seg->page_size = page_size;
	seg->size      = size;
}

static int get_one_memseg(const struct rte_memseg_list *msl,
			  const struct rte_memseg *ms,
			  size_t len, void *ctx)
{
	if (!msl->external)
		append_one_memseg(ctx, msl->base_va, len, msl->page_sz);

	return 0;
}

struct tpa_memseg *tpa_memsegs_get(void)
{
	struct get_memsegs_ctx ctx;

	memset(&ctx, 0, sizeof(ctx));
	rte_memseg_contig_walk(get_one_memseg, &ctx);

	if (ctx.idx > 0)
		append_one_memseg(&ctx, NULL, 0, 0);

	if (ctx.failed)
		return NULL;

	return ctx.segs;
}

static int cmd_mem_stats(struct shell_cmd_info *cmd)
{
	int verbose = 0;

	if (cmd->argc == 1 && strcmp(cmd->argv[0], "-v") == 0)
		verbose = 1;

	show_dpdk_mem_stats(cmd->reply, verbose);

	return 0;
}

static const struct shell_cmd mem_stats_cmd = {
	.name    = "mem-stats",
	.handler = cmd_mem_stats,
};

static int cmd_vstats_reset(struct shell_cmd_info *cmd)
{
	vstats_reset_seq += 1;

	shell_append_reply(cmd->reply, "%hhu\n", vstats_reset_seq);

	return 0;
}

static const struct shell_cmd vstats_reset_cmd = {
	.name    = "vstats-reset",
	.handler = cmd_vstats_reset,
};

static int cmd_uptime(struct shell_cmd_info *cmd)
{
	struct timeval now;
	struct timeval delta;
	time_t time_sec;
	char buf[64];

	gettimeofday(&now, NULL);
	timersub(&now, &startup_time, &delta);

	if (cmd->argc == 1 && strcmp(cmd->argv[0], "-s") == 0) {
		shell_append_reply(cmd->reply, "%lu\n", delta.tv_sec);
		return 0;
	}

	time_sec = startup_time.tv_sec;
	strftime(buf, sizeof(buf), "%Y-%m-%d %T", localtime(&time_sec));
	shell_append_reply(cmd->reply, "%s, up %s\n", buf, time_to_duration(delta.tv_sec));

	return 0;
}

static const struct shell_cmd uptime_cmd = {
	.name    = "uptime",
	.handler = cmd_uptime,
};
