/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _TPA_LOG_H_
#define _TPA_LOG_H_

#include <stdlib.h>

#include "lib/utils.h"

enum {
	LOG_LEVEL_ERR = 0,
	LOG_LEVEL_WARN,
	LOG_LEVEL_INFO,
	LOG_LEVEL_DEBUG,
};

void log_init(void);
void tpa_log(int level, const char *fmt, ...);

#define LOG(fmt, args...)		tpa_log(LOG_LEVEL_INFO,  fmt, ##args)
#define LOG_ERR(fmt, args...)		tpa_log(LOG_LEVEL_ERR,   fmt, ##args)
#define LOG_WARN(fmt, args...)		tpa_log(LOG_LEVEL_WARN,  fmt, ##args)
#define LOG_DEBUG(fmt, args...)		tpa_log(LOG_LEVEL_DEBUG, fmt, ##args)

#define PANIC(fmt, args...)		do {		\
	tpa_log(LOG_LEVEL_ERR, fmt, ##args);		\
	abort();					\
} while (0)

#define PANIC_ON(cond, fmt, args...)	do {		\
	if (cond) {					\
		tpa_log(LOG_LEVEL_ERR, fmt, ##args);	\
		abort();				\
	}						\
} while (0)

#endif
