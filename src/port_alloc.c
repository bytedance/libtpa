/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <sys/queue.h>

#include <rte_cycles.h>
#include <rte_spinlock.h>

#include "port_alloc.h"
#include "log.h"
#include "shell.h"
#include "sock_table.h"
#include "worker.h"

/* TODO: make it configurable */
#define PORT_MIN		41000
#define PORT_MAX		64000
#define PORT_COUNT		(pac.max - pac.min)

#define PORT_FREED		-1

struct port_alloc_ctrl {
	rte_spinlock_t lock;

	/*
	 * below specifies the local port range for this instance, while
	 * PORT_MIN and PORT_MAX specifies the port range for libtpa
	 */
	uint16_t min;
	uint16_t max;

	uint64_t nr_port_allocated;
	uint64_t nr_port_allocated_total;
	uint64_t nr_socket_failure;
	uint64_t nr_bind_failure;

	uint64_t nr_port_block;

	int port_map[1<<16];
};

static struct port_alloc_ctrl pac = {
	.min = PORT_MIN,
	.max = PORT_MAX,
};

static inline int port_allocated(uint16_t port)
{
	return pac.port_map[port] >= 0;
}

static inline int do_port_alloc(uint16_t port)
{
	struct sockaddr_in6 addr;
	int fd;

	if (port_allocated(port))
		return 0;

	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (fd == -1) {
		pac.nr_socket_failure += 1;
		return 0;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_addr = in6addr_any;
	addr.sin6_port = htons(port);
	if ((bind(fd, (struct sockaddr *)&addr, sizeof(addr))) < 0) {
		pac.nr_bind_failure += 1;
		close(fd);
		return 0;
	}

	pac.port_map[port] = fd;

	pac.nr_port_allocated += 1;
	pac.nr_port_allocated_total += 1;

	return port;
}

uint16_t port_alloc(uint16_t port)
{
	int nr_try = 0;

	if (port)
		return do_port_alloc(port);

	port = (rte_rdtsc() % PORT_COUNT) + pac.min;
	while (nr_try++ < PORT_COUNT) {
		if (do_port_alloc(port) > 0)
			return port;

		port += 1;
		if (port == pac.max)
			port = pac.min;
	}

	return 0;
}

int port_free(uint16_t port)
{
	int fd = pac.port_map[port];

	if (fd >= 0) {
		pac.nr_port_allocated -= 1;
		close(fd);
	}

	pac.port_map[port] = PORT_FREED;

	return fd >= 0 ? 0 : - 1;
}

static inline void port_block_get(struct port_block *block)
{
	debug_assert(block->refcnt >= 0);

	block->refcnt += 1;
	timer_stop(&block->timer);
}

static inline void port_block_put(struct port_block *block)
{
	debug_assert(block->refcnt > 0);

	if (--block->refcnt == 0)
		timer_start(&block->timer, block->worker->ts_us, tcp_cfg.time_wait);
}

static void worker_drop_port_block(struct tpa_worker *worker, struct port_block *block)
{
	int i;

	for (i = 0; i < worker->nr_port_block; i++) {
		if (block == worker->port_blocks[i]) {
			/*
			 * drop the current block by simply swaping
			 * it with the last block.
			 */
			worker->port_blocks[i] = worker->port_blocks[worker->nr_port_block - 1];
			break;
		}
	}

	worker->nr_port_block -= 1;
	debug_assert(worker->nr_port_block >= 0);
}

static void port_block_free(struct port_block *block)
{
	uint16_t port;

	LOG("freeing port block %hu-%hu", block->start, block->end);

	debug_assert(block->refcnt == 0);

	for (port = block->start; port < block->end; port++)
		port_free(port);

	port_block_offload_destroy(block);
	worker_drop_port_block(block->worker, block);

	free(block);
}

static void port_block_timeout(struct timer *timer)
{
	struct port_block *block = timer->arg;

	debug_assert(block->refcnt >= 0);

	if (block->refcnt > 0)
		return;

	port_block_free(block);
}

static struct port_block *port_block_find(struct port_block **blocks, int nr_block, uint16_t port)
{
	int i;

	for (i = 0; i < nr_block; i++) {
		if (port >= blocks[i]->start && port < blocks[i]->end)
			return blocks[i];
	}

	return NULL;
}

static inline int port_range_is_free(uint16_t start, uint16_t size)
{
	uint16_t i;

	for (i = 0; i < size; i++)
		if (pac.port_map[start + i] >= 0)
			return 0;

	return 1;
}

static struct port_block *do_port_block_alloc(struct tpa_worker *worker, uint16_t start, uint16_t size)
{
	struct port_block *block;
	uint16_t ports[DEFAULT_PORT_BLOCK_SIZE];
	uint16_t i;

	if (size & ~size)
		return NULL;

	/* do a quick check whether the range is free in this libtpa instance */
	if (!port_range_is_free(start, size))
		return NULL;

	block = malloc(sizeof(struct port_block));
	if (!block)
		return NULL;

	for (i = 0; i < size; i++) {
		ports[i] = port_alloc(start + i);
		if (ports[i] == 0)
			goto fail;
	}

	block->start = start;
	block->end = start + size;
	block->size = size;
	block->mask = size - 1;
	block->port_mask = 0xffff & (~block->mask);
	block->worker = worker;
	block->refcnt = 0;
	offload_list_init(&block->offload_list);
	timer_init(&block->timer, &worker->timer_ctrl, port_block_timeout,
		   block, worker->ts_us);

	errno = 0;
	if (port_block_offload_create(block) < 0) {
		/* FIXME: choose a better error code? */
		errno = EBUSY;
		goto fail;
	}

	pac.nr_port_block += 1;

	return block;

fail:
	free(block);
	while (i-- > 0)
		port_free(ports[i]);

	return NULL;
}

static struct port_block *port_block_alloc(struct tpa_worker *worker, uint16_t port)
{
	struct port_block *block = NULL;
	uint16_t start;
	int nr_retry = 0;
	uint16_t min;
	uint16_t max;

	rte_spinlock_lock(&pac.lock);

	if (port) {
		block = do_port_block_alloc(worker, port & ~DEFAULT_PORT_BLOCK_MASK, DEFAULT_PORT_BLOCK_SIZE);
		goto out;
	}

	min = (pac.min + DEFAULT_PORT_BLOCK_MASK) & ~DEFAULT_PORT_BLOCK_MASK;
	max = (pac.max & ~DEFAULT_PORT_BLOCK_MASK);
	start = (((rte_rdtsc() >> 2) % PORT_COUNT) + min) & ~DEFAULT_PORT_BLOCK_MASK;
	while (nr_retry++ < (max - min) / DEFAULT_PORT_BLOCK_SIZE) {
		if (start >= max)
			start = min;

		debug_assert(start + DEFAULT_PORT_BLOCK_SIZE <= pac.max);
		block = do_port_block_alloc(worker, start, DEFAULT_PORT_BLOCK_SIZE);
		if (block || errno == EBUSY)
			break;

		start += DEFAULT_PORT_BLOCK_SIZE;
	}

out:
	rte_spinlock_unlock(&pac.lock);

	if (block)
		LOG("allocated port block %hu-%hu", block->start, block->end);

	return block;
}

/*
 * make sure the kernel and tpa local port doesn't conflict with each other
 */
static void reserve_local_port(void)
{
	int range[2];
	FILE *f;

	f = fopen("/proc/sys/net/ipv4/ip_local_port_range", "r+");
	if (f == NULL) {
		LOG_WARN("failed to open ip_local_port_range file: %s", strerror(errno));
		return;
	}

	if (fscanf(f, "%d %d", &range[0], &range[1]) != 2) {
		LOG_WARN("failed to get kernel local port range: %s", strerror(errno));
		goto out;
	}

	if (range[0] > PORT_MIN) {
		LOG_WARN("got abnormal kernel local port range: %d %d; skip",
			 range[0], range[1]);
		goto out;
	}

	if (range[1] != PORT_MIN - 1) {
		LOG("update kernel port range: %d %d -> %d %d",
		    range[0], range[1], range[0], PORT_MIN - 1);

		rewind(f);
		if (fprintf(f, "%d %d", range[0], PORT_MIN - 1) <= 0) {
			LOG_WARN("failed to update kernel local port range: %s",
				 strerror(errno));
		}
	}
out:
	LOG("tpa port range: %d %d", PORT_MIN, PORT_MAX);
	fclose(f);
}

int local_port_range_set(struct cfg_spec *spec, const char *val)
{
	int min;
	int max;

	if (sscanf(val, "%d %d", &min, &max) != 2) {
		LOG_WARN("invalid local port range: %s", val);
		return -1;
	}

	if (min < PORT_MIN || min >= PORT_MAX ||
	    max < PORT_MIN || max >= PORT_MAX) {
		LOG_WARN("local_port_range [%d %d] is out of range [%d %d]",
			 min, max, PORT_MIN, PORT_MAX);
		return -1;
	}

	if (min >= max) {
		LOG_WARN("invalid port range: min > max: %s", val);
		return -1;
	}

	pac.min = min;
	pac.max = max;

	return 0;
}

int local_port_range_get(struct cfg_spec *spec, char *val)
{
	tpa_snprintf(val, VAL_SIZE, "%hu %hu", pac.min, pac.max);

	return 0;
}

static void list_port(struct shell_buf *reply)
{
	uint16_t start = 0;
	uint16_t end = 0;
	int i;

	shell_append_reply(reply, "port allocated: ");

	for (i = 0; i < (1<<16); i++) {
		if (!port_allocated(i)) {
			if (start) {
				if (start == end)
					shell_append_reply(reply, "%hu ", start);
				else
					shell_append_reply(reply, "%hu-%hu ", start, end);

				start = 0;
			}

			continue;
		}

		if (start == 0) {
			start = i;
			end = i;
		} else {
			end += 1;
		}
	}

	shell_append_reply(reply, "\n");
}

static int cmd_port_alloc(struct shell_cmd_info *cmd)
{
	shell_append_reply(cmd->reply, "nr_port_allocated: %lu\n", pac.nr_port_allocated);
	shell_append_reply(cmd->reply, "nr_port_allocated_total: %lu\n", pac.nr_port_allocated_total);
	shell_append_reply(cmd->reply, "nr_socket_failure: %lu\n", pac.nr_socket_failure);
	shell_append_reply(cmd->reply, "nr_bind_failure: %lu\n", pac.nr_bind_failure);
	shell_append_reply(cmd->reply, "nr_port_block: %lu\n", pac.nr_port_block);

	if (cmd->argc == 1 && strcmp(cmd->argv[0], "-v") == 0)
		list_port(cmd->reply);

	return 0;
}

static const struct shell_cmd port_alloc_cmd = {
	.name    = "port_alloc",
	.handler = cmd_port_alloc,
};

void port_alloc_init(void)
{
	reserve_local_port();

	memset(pac.port_map, PORT_FREED, sizeof(pac.port_map));
	rte_spinlock_init(&pac.lock);

	shell_register_cmd(&port_alloc_cmd);
}



/*
 * Here goes the port bind stuff
 */
static uint16_t bind_from_port_block(struct port_block *block, struct tpa_worker *worker,
				     struct sock_key *key, struct tcp_sock *tsock)
{
	int nr_try = 0;
	int idx;

	if (!block)
		return 0;

	idx = ((rte_rdtsc() >> 2) % block->size);

	while (nr_try++ < block->size) {
		key->local_port = block->start + idx;
		if (sock_table_add(&worker->sock_table, key, tsock) == 0) {
			port_block_get(block);
			return key->local_port;
		}

		idx += 1;
		if (idx >= block->size)
			idx = 0;
	}

	return 0;
}

static struct port_block *worker_alloc_port_block(struct tpa_worker *worker, uint16_t port)
{
	struct port_block *block;

	if (worker->nr_port_block >= MAX_PORT_BLOCK_PER_WORKER)
		return NULL;

	block = port_block_alloc(worker, port);
	if (!block)
		return NULL;

	worker->port_blocks[worker->nr_port_block++] = block;

	return block;
}

static uint16_t port_bind_on_given_port(struct tpa_worker *worker, struct sock_key *key,
					struct tcp_sock *tsock)
{
	uint16_t port = key->local_port;
	struct port_block *block;

	debug_assert(port != 0);

	block = port_block_find(worker->port_blocks, worker->nr_port_block, port);
	if (!block) {
		block = worker_alloc_port_block(worker, port);

		if (!block)
			return 0;
	}

	debug_assert(port >= block->start && port < block->end);
	if (sock_table_add(&worker->sock_table, key, tsock) < 0)
		return 0;

	port_block_get(block);

	return port;
}

static uint16_t port_bind_on_random_port(struct tpa_worker *worker, struct sock_key *key,
					 struct tcp_sock *tsock)
{
	struct port_block *block;
	uint16_t port;
	int nr_try = 0;
	int idx;

	if (worker->nr_port_block == 0)
		goto alloc;

	idx = (rte_rdtsc() >> 2) % worker->nr_port_block;
	while (nr_try++ < worker->nr_port_block) {
		port = bind_from_port_block(worker->port_blocks[idx], worker, key, tsock);
		if (port > 0)
			return port;

		idx += 1;
		if (idx >= worker->nr_port_block)
			idx = 0;
	}

alloc:
	/* need allocate one more port block */
	block = worker_alloc_port_block(worker, 0);
	if (!block)
		return 0;

	port = bind_from_port_block(block, worker, key, tsock);
	debug_assert(port > 0);

	return port;
}

/* returns 0 on failure */
uint16_t port_bind(struct tpa_worker *worker, struct sock_key *key, struct tcp_sock *tsock)
{
	if (key->local_port)
		return port_bind_on_given_port(worker, key, tsock);
	else
		return port_bind_on_random_port(worker, key, tsock);
}

int port_unbind(struct tpa_worker *worker, struct sock_key *key)
{
	struct port_block *block;

	block = port_block_find(worker->port_blocks, worker->nr_port_block, key->local_port);
	if (!block)
		return -1;

	if (sock_table_del(&worker->sock_table, key) < 0)
		return -1;

	port_block_put(block);

	return 0;
}
