/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _REAL_UTILS_H_
#define _REAL_UTILS_H_

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <linux/limits.h>

/*
 * NOTEs on this header file:
 *
 * This header file should not include any thing (say a struct definition)
 * that depends on other header files (except few very generic standard
 * header files).
 */

#ifdef TPA_DEBUG
#define debug_assert		assert
#else
#define debug_assert(x)		do { } while (0)
#endif

#define IP_FMT                  "%u.%u.%u.%u"
#define IP_ARGS(ip)             ((ip) >> 0)  & 0xff, ((ip) >> 8)  & 0xff, \
				((ip) >> 16) & 0xff, ((ip) >> 24) & 0xff

#define MAC_FMT			"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx"
#define MAC_ARGS(mac)		(mac)[0], (mac)[1], (mac)[2], 	\
				(mac)[3], (mac)[4], (mac)[5]

#define ACCESS_ONCE(x)		(*(const volatile typeof(x) *)&(x))

#define ARRAY_SIZE(a)		(sizeof(a) / sizeof((a)[0]))

#define TS_DIFF(a, b)			({		\
	uint64_t __a = (a);				\
	uint64_t __b = (b);				\
	__a > __b ? __a - __b : 0;			\
})

#define TSC_TO_US(tsc)		((tsc) / (tpa_cfg.hz / (1000 * 1000)))

#define ROUND_UP(x, align)	(((x) + align - 1) & ~(align - 1))

enum {
	NUM_TYPE_NONE,
	NUM_TYPE_SIZE,
	NUM_TYPE_TIME,		/* in unit of seconds */
	NUM_TYPE_TIME_US,	/* in unit of micro-seconds */
};

int mkdir_p(const char *path);
int tpa_snprintf(char *str, int size, const char *format, ...);
int log2_ceil(uint32_t n);
uint64_t get_time_in_us(void);
char *time_to_duration(uint64_t sec);
char *str_time(uint64_t ts_us);
uint64_t tpa_parse_num(const char *val, int type);

static inline char *tpa_path_resolve(const char *bin, char *path, int size)
{
	char tpa_path[PATH_MAX/2];
	char *p;
	char *q;

	if (getenv("TPA_PATH"))
		tpa_snprintf(tpa_path, sizeof(tpa_path), "%s", getenv("TPA_PATH"));
	else
		tpa_snprintf(tpa_path, sizeof(tpa_path), "%s", "/usr/share/tpa");

	p = tpa_path;
	while (1) {
		q = strchr(p, ':');
		if (q)
			*q = '\0';

		tpa_snprintf(path, size, "%s/%s", p, bin);
		if (access(path, F_OK) == 0)
			return path;

		if (!q)
			break;
		p = q + 1;
	}

	return NULL;
}

#endif
