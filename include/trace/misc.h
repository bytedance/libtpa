/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _TRACE_MISC_H_
#define _TRACE_MISC_H_

#include "trace_declare.h"

/*
 * ts only need be updated at few entrance
 */
DECLARE_TRACE(ts, 1,
	TRACE_ARGS(uint64_t ts_us),

	TRACE_RECORDS(
		TYPE_RECORD(TT_ts, R56_(ts_us));
	),

	TRACE_PARSER(
	)
)

DECLARE_TRACE(error, 1,
	TRACE_ARGS(int error),

	TRACE_RECORDS(
		TYPE_RECORD(TT_error, R32(error));
	),

	TRACE_PARSER(
		if (error < 0)
			error = -error;
		trace_printf("err => %s\n", stats_name(error));
	)
)

#endif
