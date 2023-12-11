/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _TSH_H_
#define _TSH_H_

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <linux/limits.h>

#include "shell.h"
#include "lib/utils.h"
#include "tpa.h"

struct tsh_args {
	int argc;
	char *argv[1024];
};

static inline void tsh_args_init(struct tsh_args *args)
{
	memset(args, 0, sizeof(*args));
}

static inline void tsh_args_push(struct tsh_args *args, char *val)
{
	assert(args->argc < 1024);

	args->argv[args->argc++] = val;
}

static inline void shell_path_get(char *buf, size_t size)
{
	const char *path = getenv("SHELL_PATH");

	if (path) {
		snprintf(buf, size, "%s", path);
		return;
	}

	snprintf(buf, size, "%s/%s", tpa_root_get(), "shell.socket");
}

static inline int shell_client_create(void)
{
	struct sockaddr_un addr;
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("failed to create unix socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	shell_path_get(addr.sun_path, sizeof(addr.sun_path));

	if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "failed to connect to unix socket: %s: %s\n",
			addr.sun_path, strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

static inline int shell_pack_message(struct shell_buf *cmd, const char *name,
				     int argc, char *argv[])
{
	int i;
	int n;
	int len = 0;

	snprintf(cmd->hdr.name, sizeof(cmd->hdr.name), "%s", name);

	for (i = 0; i < argc; i++) {
		n = snprintf(cmd->data + len, sizeof(cmd->data) - len, "%s", argv[i]);
		if (n < strlen(argv[i]))
			return -1;

		/* null is included */
		len += n + 1;
	}

	cmd->hdr.len = len + sizeof(struct shell_buf_hdr);

	return 0;
}


static inline int shell_client_exec(int fd, const char *name, int argc, char *argv[])
{
	struct shell_buf cmd;

	if (shell_pack_message(&cmd, name, argc, argv) < 0) {
		fprintf(stderr, "tvsh: %s: arg too long\n", name);
		return -1;
	}

	if (write(fd, &cmd, cmd.hdr.len) < cmd.hdr.len) {
		fprintf(stderr, "tvsh: %s: failed to exec: %s\n",
			name, strerror(errno));
		return -1;
	}

	if (read(fd, &cmd, sizeof(cmd)) < 0) {
		fprintf(stderr, "tvsh: %s: failed to read cmd result\n", name);
		return -1;
	}

	if (cmd.hdr.len > sizeof(struct shell_buf_hdr))
		printf("%s", cmd.data);

	return cmd.hdr.ret;
}

static inline int tsh_exec(const char *name, struct tsh_args *args)
{
	int fd = -1;

	fd = shell_client_create();
	if (fd < 0)
		return -1;

	return shell_client_exec(fd, name, args->argc, args->argv);
}


#endif
