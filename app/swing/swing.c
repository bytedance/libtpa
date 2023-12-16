/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/epoll.h>

#include <tpa.h>

static char *server;
static uint16_t port;

static int sid = -1;
static int connected;
static int epfd;
static int zero_copy_write;

static struct tpa_worker *worker;

static int watch_stdin(void)
{
	struct epoll_event event;

	epfd = epoll_create1(0);
	if (epfd < 0) {
		perror("epoll_create1");
		return -1;
	}

	event.events = EPOLLIN;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, 0, &event) < 0) {
		perror("epoll_ctl add stdin");
		return -1;
	}

	return 0;
}

#define BUF_TYPE_EXTERNAL		((void *)(uintptr_t)2)

static void zero_copy_write_done(void *iov_base, void *iov_param)
{
	assert(iov_param == BUF_TYPE_EXTERNAL);
}

#define PAGE_SIZE		4096
#define EXTBUF_SIZE		(1*PAGE_SIZE)

/* Note that it's basically a Mellanox only thing. */
static void *zwrite_extbuf_alloc(size_t size)
{
	static void *buf;

	if (!buf) {
		buf = aligned_alloc(PAGE_SIZE, EXTBUF_SIZE);
		assert(buf != NULL);

		if (tpa_extmem_register(buf, EXTBUF_SIZE, NULL, EXTBUF_SIZE / PAGE_SIZE, PAGE_SIZE) != 0) {
			fprintf(stderr, "failed to register external memory: %s\n", strerror(errno));
			exit(1);
		}
	}

	assert(size <= EXTBUF_SIZE);

	/*
	 * XXX: round-robin mode is assumed, that we have only one
	 * outstanding buf at a time. Therefore, we can re-use it
	 * safely here.
	 */
	return buf;
}

static int write_connection(char *line)
{
	ssize_t ret;

	if (zero_copy_write) {
		struct tpa_iovec iov;

		iov.iov_base = zwrite_extbuf_alloc(strlen(line));
		iov.iov_phys = 1;
		iov.iov_param = BUF_TYPE_EXTERNAL;
		iov.iov_len = strlen(line);
		iov.iov_write_done = zero_copy_write_done;

		/*
		 * it's not really zero copy write; we are just testing
		 * the zero copy write
		 */
		strcpy(iov.iov_base, line);
		ret = tpa_zwritev(sid, &iov, 1);
		if (ret < 0)
			iov.iov_write_done(iov.iov_base, iov.iov_param);
	} else {
		ret = tpa_write(sid, line, strlen(line));
	}

	if (ret == strlen(line))
		return 0;

	fprintf(stderr, "failed to send data: %s: sent=%zd: %s\n",
		line, ret, strerror(errno));
	return -1;
}

static int poll_stdin(void)
{
	struct epoll_event event;
	int has_input;
	char line[4096];

	if (!connected)
		return 0;

	has_input = epoll_wait(epfd, &event, 1, 0);
	if (!has_input)
		return 0;

	if (fgets(line, sizeof(line), stdin) == NULL)
		return -1;

	return write_connection(line);
}

static int watch_connection(void)
{
	struct tpa_event event;

	event.events = TPA_EVENT_IN | TPA_EVENT_OUT;
	return tpa_event_ctrl(sid, TPA_EVENT_CTRL_ADD, &event);
}

static int poll_connection(void)
{
	struct tpa_event event;
	struct tpa_iovec iov;
	int nr_event;
	ssize_t ret;

	nr_event = tpa_event_poll(worker, &event, 1);
	if (nr_event == 0)
		return 0;

	if (event.events & (TPA_EVENT_IN | TPA_EVENT_ERR | TPA_EVENT_HUP)) {
		ret = tpa_zreadv(sid, &iov, 1);
		if (ret < 0) {
			if (errno == EAGAIN)
				return 0;

			fprintf(stderr, "failed to read: %s", strerror(errno));
			return -1;
		}

		assert(connected != 0);
		if (ret == 0) {
			fprintf(stderr, "remote is closed\n");
			return -1;
		}

		((char *)iov.iov_base)[ret] = '\0';
		printf("< %s\n", (char *)iov.iov_base);
		iov.iov_read_done(iov.iov_base, iov.iov_param);

		printf("> ");
	}

	if (event.events & TPA_EVENT_OUT) {
		assert(connected == 0);

		connected = 1;
		printf(" [connected]\n");
		printf("> ");

		event.events = TPA_EVENT_IN;
		if (tpa_event_ctrl(sid, TPA_EVENT_CTRL_MOD, &event) < 0) {
			fprintf(stderr, "failed to mod tpa event: %s\n", strerror(errno));
			return -1;
		}
	}

	return 0;
}

static int loop(void)
{
	if (watch_stdin() < 0)
		return -1;

	if (watch_connection() < 0)
		return -1;

	while (1) {
		tpa_worker_run(worker);

		if (poll_stdin() < 0)
			return -1;

		if (poll_connection() < 0)
			return -1;

		usleep(1000);
	}

	return 0;
}

static void usage(void)
{
	fprintf(stderr,
		"usage: swing [options] server port\n"
		"\n"
		"Supported options are:\n"
		"  -z                    enable zero copy write\n");

	exit(1);
}

static void parse_args(int argc, char **argv)
{
	int opt;

	if (argc < 3)
		usage();

	while ((opt = getopt(argc, argv, "z")) != -1) {
		switch (opt) {
		case 'z':
			zero_copy_write = 1;
			break;
		}
	}

	if (argc - optind != 2)
		usage();

	server = argv[optind];
	port = atoi(argv[optind + 1]);
}

int main(int argc, char **argv)
{
	parse_args(argc, argv);

	if (tpa_init(1) < 0) {
		fprintf(stderr, "failed to init tpa: %s\n", strerror(errno));
		return -1;
	}

	setvbuf(stdout, NULL, _IONBF, 0);

	worker = tpa_worker_init();
	if (!worker) {
		fprintf(stderr, "failed to init worker: %s\n", strerror(errno));
		return -1;
	}

	printf(":: connecting to %s:%hu ...", server, port);
	sid = tpa_connect_to(server, port, NULL);
	if (sid < 0) {
		fprintf(stderr, "failed to connect: %s\n", strerror(errno));
		return -1;
	}

	return loop();
}
