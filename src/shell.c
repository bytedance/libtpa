/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>

#include "tpa.h"
#include "shell.h"
#include "lib/utils.h"
#include "log.h"
#include "ctrl.h"
#include "cfg.h"

#define MAX_CMDS		128
static const struct shell_cmd *cmds[MAX_CMDS];
static int nr_cmd;
static int shell_fd;
static char postinit_cmd[4096];

/*
 * NOTE: no locks (on purpose)
 */
static const struct shell_cmd *find_cmd(const char *name)
{
	int i;

	for (i = 0; i < nr_cmd; i++) {
		if (strcmp(cmds[i]->name, name) == 0)
			return cmds[i];
	}

	return NULL;
}

/*
 * No unregister (yet on purpose)
 */
int shell_register_cmd(const struct shell_cmd *cmd)
{
	if (find_cmd(cmd->name)) {
		fprintf(stderr, "register cmd error: %s: already exist\n", cmd->name);
		return -1;
	}

	assert(nr_cmd < MAX_CMDS);
	cmds[nr_cmd++] = cmd;

	return 0;
}


/* server as an example */
static int cmd_echo(struct shell_cmd_info *cmd)
{
	int i;

	for (i = 0; i < cmd->argc; i++)
		shell_append_reply(cmd->reply, "%s\n", cmd->argv[i]);

	return 0;
}

static const struct shell_cmd echo = {
	.name    = "echo",
	.handler = cmd_echo,
};

static void shell_path_get(char *buf, size_t size)
{
	if (getenv("SHELL_PATH")) {
		tpa_snprintf(buf, size, "%s", getenv("SHELL_PATH"));
		return;
	}

	tpa_snprintf(buf, size, "%s/%s", tpa_root_get(), "shell.socket");
}

static int shell_server_register(void)
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
	unlink(addr.sun_path);

	if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("failed to bind unix socket");
		close(fd);
		return -1;
	}

	listen(fd, 32);

	return fd;
}

static void shell_exec(struct shell_buf *cmd_buf, struct shell_buf *reply_buf)
{
	const struct shell_cmd *cmd;
	struct shell_cmd_info cmd_info;
	int argc = 0;
	char *argv[1024];	/* TODO: get rif of such limit */
	char *p;
	char *end;

	cmd = find_cmd(cmd_buf->hdr.name);
	if (!cmd) {
		fprintf(stderr, "%s: no such cmd\n", cmd_buf->hdr.name);
		return;
	}

	memset(argv, 0, sizeof(argv));
	p = cmd_buf->data;
	end = cmd_buf->data + cmd_buf->hdr.len - sizeof(struct shell_buf_hdr);
	while (p < end) {
		argv[argc++] = p;
		p += strlen(p) + 1;
	}

	memcpy(reply_buf, cmd_buf, sizeof(struct shell_buf_hdr));
	reply_buf->hdr.len = 0;

	cmd_info.argc  = argc;
	cmd_info.argv  = argv;
	cmd_info.reply = reply_buf;
	reply_buf->hdr.ret = cmd->handler(&cmd_info);
	reply_buf->hdr.len += sizeof(struct shell_buf_hdr);
}

static void *shell_cmd_process_one(struct ctrl_event *event)
{
	static struct shell_buf cmd_buf;
	static struct shell_buf reply_buf;
	int fd = (int)(uintptr_t)event->arg;
	int res;

	do {
		res = read(fd, &cmd_buf, sizeof(cmd_buf));
	} while (res == -1 && errno == EAGAIN);

	if (res < (int)sizeof(struct shell_buf_hdr)) {
		fprintf(stderr, "failed to read cmd\n");
		goto out;
	}

	shell_exec(&cmd_buf, &reply_buf);
	if (send(fd, &reply_buf, reply_buf.hdr.len, MSG_NOSIGNAL) < reply_buf.hdr.len) {
		LOG_WARN("shell cmd %s: failed to write reply (%u bytes): %s\n",
			 cmd_buf.hdr.name, reply_buf.hdr.len, strerror(errno));
	}

out:
	ctrl_event_destroy(event);
	close(fd);
	return NULL;
}

static void *shell_cmd_process(struct ctrl_event *event)
{
	static struct sockaddr_un addr;
	static socklen_t slen = sizeof(addr);
	int fd;

	if (shell_fd < 0)
		return NULL;

	fd = accept4(shell_fd, (struct sockaddr *)&addr, &slen, SOCK_NONBLOCK);
	if (fd < 0)
		return NULL;

	ctrl_event_create(fd, shell_cmd_process_one, (void *)(uintptr_t)fd, "shell-cmd");

	return NULL;
}

static void shell_exec_postinit_cmd(void)
{
	static struct shell_buf cmd_buf;
	static struct shell_buf reply_buf;
	char *p = strdup(postinit_cmd);
	char *end;
	int len;

	while (p && *p) {
		end = strchr(p, ';');
		if (end) {
			*end = '\0';
			end += 1;
		}

		LOG("executing postint cmd: %s", p);

		p = strtok(p, " ");
		tpa_snprintf(cmd_buf.hdr.name, sizeof(cmd_buf.hdr.name), "%s", p);

		len = 0;
		while (1) {
			p = strtok(NULL, " ");
			if (!p)
				break;

			len += tpa_snprintf(cmd_buf.data + len, sizeof(cmd_buf.data) - len, "%s", p);

			/* null is included */
			len += 1;
		}
		cmd_buf.hdr.len = len + sizeof(struct shell_buf_hdr);

		shell_exec(&cmd_buf, &reply_buf);
		if (reply_buf.hdr.ret)
			LOG_ERR(reply_buf.data);
		else
			LOG(reply_buf.data);

		p = end;
	}
}

static struct cfg_spec shell_cfg_specs[] = {
	{
		.name	= "shell.postinit_cmd",
		.type   = CFG_TYPE_STR,
		.flags  = CFG_FLAG_RDONLY,
		.data   = &postinit_cmd,
		.data_len = sizeof(postinit_cmd),
	},
};

int shell_init(void)
{
	cfg_spec_register(shell_cfg_specs, ARRAY_SIZE(shell_cfg_specs));
	cfg_section_parse("shell");

	shell_fd = shell_server_register();
	if (shell_fd < 0)
		return -1;

	shell_register_cmd(&echo);

	return 0;
}

int shell_start(void)
{
	shell_exec_postinit_cmd();

	ctrl_event_create(shell_fd, shell_cmd_process, NULL, "tpa-shell");

	return 0;
}
