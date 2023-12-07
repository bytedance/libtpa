/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _TPA_CFG_H_
#define _TPA_CFG_H_
#include <stdint.h>
#include <limits.h>

enum {
	CFG_TYPE_MIN,
	CFG_TYPE_UINT,
	CFG_TYPE_STR,
	CFG_TYPE_CHAR,
	CFG_TYPE_IPV4,
	CFG_TYPE_MASK,
	CFG_TYPE_IPV6,
	CFG_TYPE_MAC,
	CFG_TYPE_SIZE,
	CFG_TYPE_TIME,
	CFG_TYPE_MAX,
};

enum {
	CFG_FLAG_RDONLY  = 0x01,
	CFG_FLAG_HAS_MIN = 0x02,
	CFG_FLAG_HAS_MAX = 0x04,
	CFG_FLAG_POWEROF2 = 0x08,
};

#define VAL_SIZE	1024

struct cfg_spec {
	const char *name;
	int type;
	void *data;
	int data_len;
	uint32_t flags;
	int min;
	int max;
	int (*set)(struct cfg_spec *spec, const char *val);
	int (*get)(struct cfg_spec *spec, char *val);
};

#define NAME_SIZE		256
struct cfg_opt {
	char name[NAME_SIZE];
	char val[NAME_SIZE];

	struct cfg_opt *next;
};

struct cfg_section {
	char name[NAME_SIZE];
	struct cfg_opt *opts;

	struct cfg_section *next;
};

#define CFG_SPECS_SIZE		1024

struct tpa_cfg {
	uint64_t hz;
	uint32_t nr_worker;
	uint32_t nr_worker_shift;
	uint32_t nr_worker_mask;
	uint32_t preferred_numa;

	int nr_dpdk_port;

	char *sock_file;
	char *sock_trace_file;

	size_t nr_spec;
	struct cfg_spec    *cfg_specs[CFG_SPECS_SIZE];
	struct cfg_section *cfg_sections;
};

#define CFG_SECTION_FOREACH(section)		\
	for (section = tpa_cfg.cfg_sections; section != NULL; section = section->next)

int cfg_init(void);
int cfg_file_parse(FILE *file);
const char *cfg_file_opt_get(const char *name);
void cfg_reset(void);

int cfg_section_parse(const char *section);
int cfg_spec_register(struct cfg_spec *specs, int nr_spec);
void cfg_dump_unknown_opts(void);

int cfg_spec_set_num(struct cfg_spec *spec, const char *val);

extern struct tpa_cfg tpa_cfg;

#endif
