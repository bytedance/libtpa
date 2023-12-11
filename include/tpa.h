/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _TPA_H_
#define _TPA_H_

#include <rte_mempool.h>
#include <rte_ring.h>

#include "api/tpa.h"
#include "shell.h"

extern char *__progname;
extern char *__progname_full;

extern int flock_fd;

const char *tpa_id_get(void);
const char *tpa_root_get(void);
const char *tpa_log_root_get(void);
void tpad_init(void);

void dpdk_init(int nr_queue);
void show_dpdk_mem_stats(struct shell_buf *reply, int verbose);

#endif
