/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <sys/file.h>
#include <sys/types.h>
#include <fcntl.h>

#include "test_utils.h"
#include "port_alloc.h"

static struct tpa_ip default_remote_ip;
static struct tcp_sock dummy_tsock;

static void dump_bind_list_distribution(void)
{
	struct sock_entry *entry;
	uint64_t n;
	int i;

	for (i = 0; i < SOCK_TABLE_SIZE; i++) {
		n = 0;
		TAILQ_FOREACH(entry, &worker->sock_table.lists[i], node) {
			n += 1;
		}

		fprintf(stderr, "%d %lu\n", i, n);
	}
}

static void assert_port_block_refcnt(void)
{
	int i;

	for (i = 0; i < worker->nr_port_block; i++)
		assert(worker->port_blocks[i]->refcnt == 0);
}

static int reserve_port(uint16_t port)
{
	struct sockaddr_in6 addr;
	int fd;

	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (fd == -1)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_addr = in6addr_any;
	addr.sin6_port = htons(port);
	if ((bind(fd, (struct sockaddr *)&addr, sizeof(addr))) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

/* this should run first to make sure no port block is allocated */
static void test_port_alloc_all_fail(void)
{
	uint16_t *fds = malloc(sizeof(int) * (1<<16));
	struct sock_key key;
	int nr_fd = 0;
	int fd;
	int i;

	printf("testing %s ...\n", __func__);

	/*
	 * pollute the port range: we occupy one port for each port block
	 * in the local port range so that no port_block allocation would
	 * succeed.
	 */
	for (i = ut_port_min; i < ut_port_max; i += DEFAULT_PORT_BLOCK_SIZE) {
		fd = reserve_port(i);
		if (fd < 0) {
			printf("it seems port %hu is already taken?\n", i);
			continue;
		}

		fds[nr_fd++] = fd;
	}


	memset(&key, 0, sizeof(key));
	key.remote_ip = default_remote_ip;
	assert(port_bind(worker, &key, &dummy_tsock) == 0);

	for (i = 0; i < nr_fd; i++)
		close(fds[i]);

	assert_port_block_refcnt();
}

static void test_port_alloc_basic(void)
{
	struct sock_key key;
	uint16_t port;

	printf("testing %s ...\n", __func__);

	memset(&key, 0, sizeof(key));
	key.remote_ip = default_remote_ip;

	port = port_bind(worker, &key, &dummy_tsock);
	assert(port >= ut_port_min && port < ut_port_max);

	key.local_port = port;
	assert(port_unbind(worker, &key) == 0);

	assert_port_block_refcnt();
}

static void test_port_alloc_addrinuse(void)
{
	struct sock_key key;
	uint16_t port;

	printf("testing %s ...\n", __func__);

	memset(&key, 0, sizeof(key));
	key.remote_ip = default_remote_ip;

	port = port_bind(worker, &key, &dummy_tsock);
	assert(port >= ut_port_min && port < ut_port_max);

	key.port = port;
	assert(port_bind(worker, &key, &dummy_tsock) == 0);

	key.local_port = port;
	assert(port_unbind(worker, &key) == 0);

	assert_port_block_refcnt();
}

static void test_port_alloc_exhaust(void)
{
	uint16_t *ports = malloc(sizeof(uint16_t) * (1<<16));
	struct sock_key key;
	uint16_t port;
	int nr_port;
	int i;

	printf("testing %s ...\n", __func__);

	memset(&key, 0, sizeof(key));
	key.remote_ip = default_remote_ip;

	WHILE_NOT_TIME_UP() {
		nr_port = 0;

		while (1) {
			key.local_port = 0;
			port = port_bind(worker, &key, &dummy_tsock);
			if (port == 0)
				break;

			assert(port >= ut_port_min && port < ut_port_max);
			assert(nr_port <= ut_port_max - ut_port_min);

			ports[nr_port++] = port;
		}

		for (i = 0; i < nr_port; i++) {
			key.local_port = ports[i];
			assert(port_unbind(worker, &key) == 0);
		}
	}

	assert_port_block_refcnt();
}

static void test_port_alloc_exhaust_2remote_ip(void)
{
	uint16_t *ports = malloc(sizeof(uint16_t) * (1<<16));
	struct sock_key key;
	uint16_t port;
	int nr_port;
	int i;

	printf("testing %s ...\n", __func__);

	memset(&key, 0, sizeof(key));

	WHILE_NOT_TIME_UP() {
		nr_port = 0;

		tpa_ip_set_ipv4(&key.remote_ip, 0x0a000001);
		while (1) {
			key.local_port = 0;
			port = port_bind(worker, &key, &dummy_tsock);
			if (port == 0)
				break;

			assert(port >= ut_port_min && port < ut_port_max);
			assert(nr_port <= ut_port_max - ut_port_min);

			ports[nr_port++] = port;
		}

		tpa_ip_set_ipv4(&key.remote_ip, 0x0a000002);
		for (i = 0; i < nr_port; i++) {
			key.local_port = 0;
			port = port_bind(worker, &key, &dummy_tsock);
			assert(port >= ut_port_min && port < ut_port_max);
		}

		for (i = 0; i < nr_port; i++) {
			key.local_port = ports[i];

			tpa_ip_set_ipv4(&key.remote_ip, 0x0a000001);
			assert(port_unbind(worker, &key) == 0);

			tpa_ip_set_ipv4(&key.remote_ip, 0x0a000002);
			assert(port_unbind(worker, &key) == 0);
		}
	}

	assert_port_block_refcnt();
}

static void show_progress(uint64_t idx, uint64_t nr_test, const char *prompt)
{
	if (!getenv("VERBOSE"))
		return;

	if ((idx & 0xffff) == 0) {
		printf("\r %s %.2f%% ...", prompt, (double)idx * 100 / nr_test);
		fflush(stdout);

		if (strcmp(getenv("VERBOSE"), "vv") == 0)
			dump_bind_list_distribution();
	}
}

static void test_port_alloc_reuse(void)
{
	struct tpa_ip remote_ip;
	struct sock_key key;
	int nr_port = 1<<22;
	uint16_t *ports = malloc(sizeof(uint16_t) * nr_port);
	uint16_t port;
	int i;

	printf("testing %s ...\n", __func__);

	memset(&key, 0, sizeof(key));

	for (i = 0; i < nr_port; i++) {
		tpa_ip_set_ipv4(&remote_ip, i);
		key.remote_ip = remote_ip;

		port = port_bind(worker, &key, &dummy_tsock);
		assert(port >= ut_port_min && port < ut_port_max);

		ports[i] = port;

		show_progress(i, nr_port, "binding");
	}

	for (i = 0; i < nr_port; i++) {
		tpa_ip_set_ipv4(&remote_ip, i);
		key.remote_ip = remote_ip;

		key.local_port = ports[i];
		assert(port_unbind(worker, &key) == 0);

		show_progress(i, nr_port, "unbinding");
	}

	free(ports);

	assert_port_block_refcnt();
}

#define NR_OPEN_PORT		(1024 * 7)

static void test_port_alloc_stress(void)
{
	struct sock_key key;
	uint16_t ports[NR_OPEN_PORT];
	int port_idx = 0;
	uint16_t port;
	int i = 0;
	int j;

	printf("testing %s ...\n", __func__);

	memset(&key, 0, sizeof(key));
	key.remote_ip = default_remote_ip;

	while (i++ < (1<<24)) {
		key.local_port = 0;
		port = port_bind(worker, &key, &dummy_tsock);
		assert(port >= ut_port_min && port < ut_port_max);

		ports[port_idx++] = port;
		if (port_idx == NR_OPEN_PORT) {
			for (j = 0; j < port_idx; j++) {
				key.local_port = ports[j];
				assert(port_unbind(worker, &key) == 0);
			}

			port_idx = 0;
		}

		show_progress(i, (1<<24), "stress");
	}

	for (j = 0; j < port_idx; j++) {
		key.local_port = ports[j];
		assert(port_unbind(worker, &key) == 0);
	}

	assert_port_block_refcnt();
}

static void test_port_block_free(void)
{
	printf("testing %s ...\n", __func__);

	assert(worker->nr_port_block != 0);

	usleep(2e6 + tcp_cfg.time_wait);

	cycles_update_begin(worker);
	ut_timer_process(); {
		assert(worker->nr_port_block == 0);
	}
}

static void test_lock(void)
{
	int fd;

	fd = open("/tmp/port_alloc.flock", O_RDWR | O_CREAT, 0600);
	assert(fd >= 0);

	if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
		printf(":: failed to grab the lock; now quit\n");
		exit(0);
	}
}

int main(int argc, char *argv[])
{
	/*
	 * This test exhausts the port resource, therefore,
	 * it can not run parallely.
	 */
	test_lock();

	ut_init(argc, argv);
	tcp_cfg.time_wait = 2e3;

	tpa_ip_set_ipv4(&default_remote_ip, 0x0a000021);

	test_port_alloc_all_fail();
	test_port_alloc_basic();
	test_port_alloc_addrinuse();
	test_port_alloc_exhaust();
	test_port_alloc_exhaust_2remote_ip();

	test_port_alloc_reuse();
	test_port_alloc_stress();

	/* should be the last test */
	{
		int i;

		/* keep freeing and allocating port blocks */
		for (i = 0; i < 5; i++) {
			test_port_block_free();
			test_port_alloc_stress();
		}

		test_port_block_free();
	}

	return 0;
}
