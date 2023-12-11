/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>

#include "lib/utils.h"

int mkdir_p(const char *path)
{
	mode_t mode = 0755;
	char str[PATH_MAX];
	int i;

	if (access(path, F_OK) == 0)
		return 0;

	tpa_snprintf(str, sizeof(str), "%s", path);
	for (i = 1; i < strlen(str); i++) {
		if (str[i] == '/') {
			str[i] = '\0';

			if (access(str, F_OK) != 0 && mkdir(str, mode) == -1)
				return -1;

			str[i] = '/';
		}
	}

	if (str[i - 1] == '/')
		return 0;

	return mkdir(str, mode);
}

/*
 * A safer version of snprintf.
 *
 * snprintf might return a value bigger than the bytes acutally written
 * (when it's going to be truncated), which may result to an overflow issue
 * if the caller uses the return value directly with the following pattern:
 *      len += snprintf(buf + len, sizeof(buf) - len, ....);
 *
 * It's a pattern that libtpa uses a lot. Fixing it by doing an extra
 * return value validation messes the code. Therefore, here we introduce
 * a safe wrapper.
 */
int tpa_snprintf(char *str, int size, const char *format, ...)
{
	va_list arg_list;
	int ret;

	if (size <= 0)
		return 0;

	va_start(arg_list, format);
	ret = vsnprintf(str, size, format, arg_list);
	va_end(arg_list);

	if (ret >= size)
		return size - 1;

	return ret;
}

int log2_ceil(uint32_t n)
{
	int shift = 1;

	while ((1 << shift) < n)
		shift += 1;

	return shift;
}

uint64_t get_time_in_us(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000 * 1000 + tv.tv_usec;
}

char *time_to_duration(uint64_t sec)
{
	static char buf[64];
	int len = 0;

	if (sec > 24 * 3600) {
		len += tpa_snprintf(buf + len, sizeof(buf) - len, "%ld days ", sec / (24 * 3600));
		sec %= 24 * 3600;
	}

	if (sec > 3600) {
		len += tpa_snprintf(buf + len, sizeof(buf) - len, "%ldh ", sec / 3600);
		sec %= 3600;
	}

	if (sec > 60) {
		len += tpa_snprintf(buf + len, sizeof(buf) - len, "%ldm ", sec / 60);
		sec %= 60;
	}

	tpa_snprintf(buf + len, sizeof(buf) - len, "%lds", sec);

	return buf;
}

char *str_time(uint64_t ts_us)
{
	static char buf[64];
	time_t time = ts_us / 1000000;
	int len;

	len = strftime(buf, sizeof(buf), "%Y-%m-%d.%T", localtime(&time));
	snprintf(buf + len, sizeof(buf) - len, ".%06lu", ts_us % 1000000);

	return buf;
}

#define IS_DIGIT(x)			((x) >= '0' && (x) <= '9')
#define _MATCHES2(x, a, b)              (strcmp((x), (a)) == 0 || strcmp((x), (b)) == 0)
#define _MATCHES4(x, a, b, c, d)        (_MATCHES2((x), (a), (b)) || _MATCHES2((x), (c), (d)))

static uint64_t get_base(const char *val, int *unit_off)
{
	char base[32];
	int len;
	int i;

	len = strlen(val);
	if (len >= sizeof(base)) {
		errno = EINVAL;
		return UINT64_MAX;
	}

	for (i = 0; i < strlen(val); i++) {
		if (!IS_DIGIT(val[i]))
			break;
		base[i] = val[i];
	}

	base[i] = '\0';
	*unit_off = i;

	errno = 0;
	return strtoul(base, NULL, 10);
}

uint64_t tpa_parse_num(const char *val, int type)
{
	uint64_t num;
	char *unit;
	int off;

	num = get_base(val, &off);
	if (errno)
		return UINT64_MAX;

	unit = (char *)(uintptr_t)&val[off];
	if (strlen(unit) == 0)
		return num;

	switch (type) {
	case NUM_TYPE_SIZE:
		if (_MATCHES4(unit, "G", "g", "GB", "gb"))
			num *= 1024 * 1024 * 1024ull;
		else if (_MATCHES4(unit, "M", "m", "MB", "mb"))
			num *= 1024 * 1024ull;
		else if (_MATCHES4(unit, "K", "k", "KB", "kb"))
			num *= 1024ull;
		else if (_MATCHES2(unit, "B", "b"))
			;
		else
			errno = EINVAL;
		break;

	case NUM_TYPE_TIME:
		if (_MATCHES2(unit, "h", "H"))
			num *= 60 * 60ull;
		else if (_MATCHES2(unit, "m", "M"))
			num *= 60ull;
		else if (_MATCHES2(unit, "s", "S"))
			;
		else
			errno = EINVAL;
		break;

	case NUM_TYPE_TIME_US:
		if (_MATCHES2(unit, "h", "H"))
			num *= 60 * 60 * 1000 * 1000ull;
		else if (_MATCHES2(unit, "m", "M"))
			num *= 60 * 1000 * 1000ull;
		else if (_MATCHES2(unit, "s", "S"))
			num *= 1000 * 1000ull;
		else if (_MATCHES2(unit, "ms", "MS"))
			num *= 1000ull;
		else if (_MATCHES2(unit, "us", "US"))
			;
		else
			errno = EINVAL;
		break;

	default:
		errno = EINVAL;
		break;
	}

	if (errno)
		return UINT64_MAX;

	return num;
}
