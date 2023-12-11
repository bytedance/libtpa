/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <assert.h>
#include <errno.h>

#include <tpa.h>

struct connection {
	int sid;
};

static struct tpa_worker *worker;

static void register_connection(int sid)
{
	struct connection *conn = malloc(sizeof(struct connection));
	struct tpa_event event;

	conn->sid = sid;

	event.events = TPA_EVENT_IN;
	event.data = conn;
	assert(tpa_event_ctrl(sid, TPA_EVENT_CTRL_ADD, &event) == 0);
}

static void close_connection(struct connection *conn)
{
	tpa_close(conn->sid);
	free(conn);
}

static void echo(struct connection *conn)
{
	struct tpa_iovec iov;
	ssize_t ret;

	ret = tpa_zreadv(conn->sid, &iov, 1);
	if (ret <= 0) {
		if (ret < 0 && errno == EAGAIN)
			return;

		close_connection(conn);
		return;
	}

	/*
	 * Here we don't have to set iov_write_done; we simply reuse
	 * iov_read_done.
	 *
	 * TODO: handle write failure more properly
	 */
	if (tpa_zwritev(conn->sid, &iov, 1) != iov.iov_len) {
		printf("failed to catch up the read; terminating conn %d\n", conn->sid);
		iov.iov_read_done(iov.iov_base, iov.iov_param);
		close_connection(conn);
	}
}

static void poll_connection(void)
{
	struct tpa_event events[32];
	struct connection *conn;
	int nr_event;
	int i;

	nr_event = tpa_event_poll(worker, events, 32);
	for (i = 0; i < nr_event; i++) {
		conn = events[i].data;

		if (events[i].events & (TPA_EVENT_IN | TPA_EVENT_ERR | TPA_EVENT_HUP))
			echo(conn);
	}
}

int main(int argc, char **argv)
{
	uint16_t port = 5678;
	int sid;

	if (tpa_init(1) < 0) {
		perror("tpa_init");
		return -1;
	}

	if (argc == 2)
		port = atoi(argv[1]);

	worker = tpa_worker_init();
	if (!worker) {
		fprintf(stderr, "failed to init worker: %s\n", strerror(errno));
		return -1;
	}

	printf(":: listening on port %hu ...\n", port);
	if (tpa_listen_on(NULL, port, NULL) < 0) {
		fprintf(stderr, "failed to listen on port %hu: %s\n",
			port, strerror(errno));
		exit(1);
	}

	while (1) {
		tpa_worker_run(worker);

		if (tpa_accept_burst(worker, &sid, 1) == 1)
			register_connection(sid);

		poll_connection();
	}

	return 0;
}
