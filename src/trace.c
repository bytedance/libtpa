/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "lib/utils.h"
#include "tpa.h"
#include "cfg.h"
#include "trace.h"
#include "trace_declare.h"

struct trace_cfg trace_cfg = {
	.enable_trace	= 1,
	.more_trace	= 0,
	.nr_trace	= NR_TRACE_DEFAULT,
	.trace_size	= TRACE_SIZE_DEFAULT,
	.no_wrap	= 0,
};

static struct cfg_spec trace_cfg_specs[] = {
	{
		.name	= "trace.enable",
		.type   = CFG_TYPE_UINT,
		.data   = &trace_cfg.enable_trace,
	}, {
		.name	= "trace.more_trace",	/* TODO: make trace event configurable */
		.type   = CFG_TYPE_UINT,
		.data   = &trace_cfg.more_trace,
	}, {
		.name	= "trace.trace_size",
		.type   = CFG_TYPE_SIZE,
		.data   = &trace_cfg.trace_size,
		.flags  = CFG_FLAG_HAS_MIN | CFG_FLAG_RDONLY | CFG_FLAG_POWEROF2,
		.min    = sizeof(struct tsock_trace) * 4,
	}, {
		.name	= "trace.nr_trace",
		.type   = CFG_TYPE_UINT,
		.data   = &trace_cfg.nr_trace,
		.flags  = CFG_FLAG_RDONLY,
	}, {
		.name	= "trace.no_wrap",
		.type   = CFG_TYPE_UINT,
		.data   = &trace_cfg.no_wrap,
		.flags  = CFG_FLAG_RDONLY,
	},
};

const char *trace_root_get(void)
{
	static char trace_root[PATH_MAX];

	if (trace_root[0])
		return trace_root;

	if (getenv("TRACE_ROOT")) {
		tpa_snprintf(trace_root, sizeof(trace_root), "%s", getenv("TRACE_ROOT"));
	} else {
		tpa_snprintf(trace_root, sizeof(trace_root), "%s/trace", tpa_root_get());
	}

	return trace_root;
}

int trace_init(void)
{
	cfg_spec_register(trace_cfg_specs, ARRAY_SIZE(trace_cfg_specs));
	cfg_section_parse("trace");

	return 0;
}
