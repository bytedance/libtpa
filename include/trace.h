/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _TRACE_R_H_
#define _TRACE_R_H_

/* a default cfg results to about 16M trace size */
#define NR_TRACE_DEFAULT	2048
#define TRACE_SIZE_DEFAULT	8192
#define TRACE_SIZE(s)		((s) + sizeof(struct tsock_trace))

struct trace_cfg {
	uint32_t enable_trace;
	uint32_t more_trace;
	uint32_t nr_trace;
	uint32_t trace_size;
	uint32_t no_wrap;
};

extern struct trace_cfg trace_cfg;

int trace_init(void);
const char *trace_root_get(void);

#endif
