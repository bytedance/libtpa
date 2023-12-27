/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/prctl.h>
#include <signal.h>

#include "log.h"
#include "tpad.h"
#include "xdp_ctrl.h"

struct tpad tpad;

static int connect_to_tpad(const char *tpad_name)
{
	struct sockaddr_un addr;
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		LOG_WARN("failed to tpad socket: %s", strerror(errno));
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	addr.sun_path[0] = '\0';
	tpa_snprintf(&addr.sun_path[1], sizeof(addr.sun_path) - 1, "%s", tpad_name);

	if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		LOG_WARN("failed to connect to tpad socket: %s: %s\n",
			 tpad_name, strerror(errno));
		return -1;
	}

	return fd;
}

static int wait_for_tpa_app(int fd)
{
	char buf[4];
	int ret;

	if (fd < 0)
		return -1;

	/*
	 * If this read returns, it means the parent process (the libtpa
	 * APP) is dead; we should do some house-keeping works then.
	 *
	 * Well, we are cautious here: only treat it as dead when ECONNRESET
	 * is reported: the socket is not accepted after all.
	 */
	do {
		ret = read(fd, buf, sizeof(buf));
	} while (ret < 0 && (errno == EAGAIN || errno == EINTR));

	if (ret < 0 && errno == ECONNRESET)
		return 0;

	LOG_WARN("tpad sock read returns abnormally: %d: %s\n", ret, ret < 0 ? strerror(errno) : "");
	return -1;
}

static void ignore_sig(int ignored)
{
}

int main(int argc, char **argv)
{
	int fd;

	if (argc != 2) {
		/*
		 * you are not supposed to run this program directly;
		 * therefore, let's be vague here
		 */
		fprintf(stderr, "fatal: argc mismatch\n");
		return -1;
	}
	tpad.name = argv[1];

	tpad.sock_file = getenv("TPAD_SOCK_FILE");
	tpad.sock_trace_file = getenv("TPAD_SOCK_TRACE_FILE");
	tpad.eth_dev = getenv("TPAD_DEV_NAME");
	tpad.archive_dir = getenv("TPAD_ARCHIVE_DIR");

	if (tpad.sock_file == NULL || tpad.sock_trace_file == NULL ||
	    tpad.eth_dev == NULL || tpad.archive_dir == NULL) {
		/* ditto: be vague here */
		fprintf(stderr, "fatal: missing mandatory env\n");
		return -1;
	}

	LOG("tpad %s %d starts", tpad.name, getpid());

	/* we are the libtpa APP guarder; do not die easily */
	signal(SIGINT, ignore_sig);
	signal(SIGTERM, ignore_sig);

	fd = connect_to_tpad(tpad.name);
	if (wait_for_tpa_app(fd) == 0) {
		sock_termination();
		sock_archive();
	#ifdef WITH_XDP
		if (xdp_prog_id_query(tpad.eth_dev) > 0)
			xdp_prog_detach(tpad.eth_dev);
	#endif
	}

	LOG("tpad %s %d quits", tpad.name, getpid());

	return 0;
}
