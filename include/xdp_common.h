/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023, ByteDance Ltd. and/or its Affiliates
 * Author: Wenlong Luo <luowenlong.linl@bytedance.com>
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _XDP_COMMON_H_
#define _XDP_COMMON_H_

enum {
	XDP_STATS_PASS,
	XDP_STATS_REDIRECT,
	XDP_STATS_INVALID_PKT,
	XDP_STATS_NOT_IP,
	XDP_STATS_NOT_TCP,
	XDP_STATS_NO_XSKS,
	XDP_STATS_UNEXPECTED_ACTION,
	XDP_STATS_DST_PORT_MISMATCH,
	XDP_STATS_DST_IP_MISMATCH,
	XDP_STATS_MAX,
};

#endif