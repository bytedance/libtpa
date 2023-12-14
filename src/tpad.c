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

#include "cfg.h"
#include "dev.h"
#include "log.h"
#include "tpa.h"
#include "mem_file.h"
#include "archive.h"

static char tpad_name[96];

static int tpad_socket_create(void)
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

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		LOG_WARN("failed to bind to tpad socket: %s: %s\n",
			 tpad_name, strerror(errno));
		return -1;
	}

	listen(fd, 1);

	return fd;
}

static char *make_env(const char *key, const char *val)
{
	int len = strlen(key) + strlen(val) + 2;
	char *env = malloc(len);

	if (env)
		tpa_snprintf(env, len, "%s=%s", key, val);

	return env;
}

#define NR_TPAD_ENV	16

void tpad_init(void)
{
	char name[64];
	char path[PATH_MAX];
	int fd;

	prctl(PR_GET_NAME, name, sizeof(name));
	tpa_snprintf(tpad_name, sizeof(tpad_name), "tpad-%s.%d", name, getpid());

	fd = tpad_socket_create();
	if (fd < 0)
		return;

	if (!tpa_path_resolve("tpad", path, sizeof(path))) {
		LOG_WARN("failed to find tpad");
		return;
	}

	LOG("executing tpad %s", tpad_name);

	switch (fork()) {
	case 0: {
		char *env[NR_TPAD_ENV];
		int idx = 0;

		close(fd);
		close(flock_fd);

		env[idx++] = make_env("TPAD_SOCK_FILE", tpa_cfg.sock_file);
		env[idx++] = make_env("TPAD_SOCK_TRACE_FILE", tpa_cfg.sock_trace_file);
		env[idx++] = make_env("TPAD_DEV_NAME", dev.name);
		env[idx++] = make_env("TPAD_ARCHIVE_DIR", tpa_log_root_get());

		/*
		 * besides the tpad arguments, here we also need pass
		 * some env vars the child cares.
		 */
		if (getenv("TPA_LOG_DISABLE"))
			env[idx++] = make_env("TPA_LOG_DISABLE", getenv("TPA_LOG_DISABLE"));

		env[idx++] = NULL;
		assert(idx <= NR_TPAD_ENV);

		execle(path, path, tpad_name, NULL, env);
		LOG_WARN("exec returns with error: %s\n", strerror(errno));
		_exit(1);
		break;
	}

	case -1:
		LOG_WARN("failed to spawn tpad process: %s: %s", name, strerror(errno));
		break;
	}
}
