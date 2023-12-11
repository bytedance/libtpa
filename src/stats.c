/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>

#include "stats.h"

struct stats {
	int stats;
	const char *name;
	const char *desc;
};

#undef  __STATS
#define __STATS(stats, desc)	{ stats, #stats, desc },

static struct stats errors[] = {
#include "stats_code.h"
};

uint8_t vstats_reset_seq;

const char *stats_desc(int stats)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(errors); i++) {
		if (errors[i].stats == stats)
			return errors[i].desc;
	}

	return "unknown-stats";
}

const char *stats_name(int stats)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(errors); i++) {
		if (errors[i].stats == stats)
			return errors[i].name;
	}

	return "unknown-stats";
}
