/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _SHELL_H_
#define _SHELL_H_

#include <stdint.h>

#define SHELL_NAME_SIZE	64
#define SHELL_DATA_SIZE	(1<<20)

struct shell_buf_hdr {
	char name[SHELL_NAME_SIZE];
	int len;
	int ret;
} __attribute__((packed));

struct shell_buf {
	struct shell_buf_hdr hdr;
	char data[SHELL_DATA_SIZE - sizeof(struct shell_buf_hdr)];
} __attribute__((packed));

struct shell_cmd_info {
	int argc;
	char **argv;
	struct shell_buf *reply;
};

struct shell_cmd {
	const char *name;
	int (*handler)(struct shell_cmd_info *cmd);
};

#define shell_append_reply(r, ...)		\
	r->hdr.len += tpa_snprintf(r->data + r->hdr.len, sizeof(r->data) - r->hdr.len, \
			        __VA_ARGS__)

int shell_init(void);
int shell_start(void);
int shell_register_cmd(const struct shell_cmd *cmd);

#endif
