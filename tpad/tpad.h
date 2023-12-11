/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _TPAD_H_
#define _TPAD_H_

struct tpad {
	char *name;
	char *sock_file;
	char *sock_trace_file;
	char *eth_dev;
	char *archive_dir;
};

extern struct tpad tpad;
void sock_termination(void);
void sock_archive(void);

#endif
