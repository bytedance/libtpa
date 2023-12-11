/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Wenlong Luo <luowenlong@bytedance.com>
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include "cfg.h"
#include "shell.h"
#include "test_utils.h"

#define MAX_OPT_ASSERT			16

struct cfg {
	char buf[1<<20];
	size_t size;
	int ret;

	int nr_opt_assert;
	char *opt_asserts[MAX_OPT_ASSERT];

	int syntax_test;
	int nr_failure;
};

static void opt_assert_push(struct cfg *cfg, void *opt_assert)
{
	assert(cfg->nr_opt_assert < MAX_OPT_ASSERT);

	cfg->opt_asserts[cfg->nr_opt_assert++] = opt_assert;
}

static void opt_assert_validate(struct cfg *cfg)
{
	char *name;
	char *val;
	int i;

	for (i = 0; i < cfg->nr_opt_assert; i++) {
		name = strtok(cfg->opt_asserts[i], " ");
		strtok(NULL, " ");
		val = strtok(NULL, "\n");

		if (strcmp(val, "N/A") == 0) {
			assert(cfg_file_opt_get(name) == NULL);
		} else {
			assert(cfg_file_opt_get(name) != NULL);
			assert(strcmp(cfg_file_opt_get(name), val) == 0);
		}
	}
}

static void parse_one_cfg_file(struct cfg *cfg)
{
	FILE *f = tmpfile();
	int expected_ret;
	int ret;

	assert(f != NULL);
	fwrite(cfg->buf, cfg->size, 1, f);
	fflush(f);
	fseek(f, 0, SEEK_SET);

	ret = cfg_file_parse(f);

	expected_ret = cfg->syntax_test ? cfg->ret : 0;
	if (ret != expected_ret) {
		fprintf(stderr, "failed to parse cfg file: expect ret %d, but got %d:\n%s\n",
			expected_ret, ret, cfg->buf);
		cfg->nr_failure += 1;
	}

	opt_assert_validate(cfg);

	/* reset cfg buf */
	cfg->size = 0;
	cfg->nr_opt_assert = 0;
	fclose(f);
}

static void parse_cfg_test_file(const char *path, void (*func)(struct cfg *cfg))
{
	struct cfg cfg;
	char line[1024];
	char *p;
	FILE *f;

	f = fopen(path, "r");
	assert(f != NULL);

	memset(&cfg, 0, sizeof(cfg));
	while (fgets(line, sizeof(line), f)) {
		if (strcmp(line, "### valid\n") == 0) {
			cfg.ret = 0;
			continue;
		}

		if (strcmp(line, "### invalid\n") == 0) {
			cfg.ret = -1;
			continue;
		}

		if (strcmp(line, "#---\n") == 0) {
			func(&cfg);
			continue;
		}

		p = cfg.buf + cfg.size;
		cfg.size += tpa_snprintf(p, sizeof(cfg.buf) - cfg.size, "%s", line);

		if (strncmp(line, "#=>", 3) == 0)
			opt_assert_push(&cfg, p + 3);
	}

	func(&cfg);

	assert(cfg.nr_failure == 0);
}

static void do_test_cfg_file_syntax(struct cfg *cfg)
{
	cfg->syntax_test = 1;
	parse_one_cfg_file(cfg);
	cfg_reset();
}

static void test_cfg_file_syntax(void)
{
	parse_cfg_test_file("cfg-syntax", do_test_cfg_file_syntax);
}

static void do_test_cfg_file_option(struct cfg *cfg)
{
	struct cfg_section *section;
	int ret = 0;

	cfg->syntax_test = 0;
	parse_one_cfg_file(cfg);

	CFG_SECTION_FOREACH(section) {
		ret |= cfg_section_parse(section->name);
	}
	if (ret != cfg->ret) {
		fprintf(stderr, "failed to parse cfg option: expect ret %d, but got %d:\n%s\n",
			cfg->ret, ret, cfg->buf);
		cfg->nr_failure += 1;
	}

	cfg_reset();
}

static void test_cfg_file_option(void)
{
	parse_cfg_test_file("cfg-option", do_test_cfg_file_option);
}

extern int cmd_cfg(struct shell_cmd_info *cmd);

static int cmd(const char *op)
{
	char *p;
	static char *argv[10];
	static char buff[PATH_MAX];
	struct shell_cmd_info cmd_info;
	struct shell_buf buffer;


	cmd_info.argc = 0;
	cmd_info.argv = argv;
	cmd_info.reply = &buffer;
	cmd_info.reply->hdr.len = 0;

	tpa_snprintf(buff, PATH_MAX, "%s", op);

	p = strtok(buff, " ");
	while (p != NULL) {
		argv[cmd_info.argc++] = p;
		p = strtok(NULL, " ");
	}

	return !cmd_cfg(&cmd_info);
}

static void test_cmd_cfg(void)
{
	assert(cmd("set tcp.tso 1"));
	assert(cmd("set tcp.tso 2"));
	assert(!cmd("set tcp.tso -1"));

	assert(cmd("list"));

	assert(!cmd("set net.ip 192.168.0.1"));

	assert(cmd("set tcp.retries 1"));
	assert(!cmd("set tcp.retries -1"));

	assert(cmd("set tcp.syn_retries 1"));

	assert(cmd("set tcp.time_wait 400000"));

	assert(cmd("set dpdk.socket-mem 1024,1024"));
	assert(!cmd("set dpdk.pci 0000:00:05.0"));
	assert(cmd("set dpdk.mbuf_mem_size 2176MB"));
}

int main(int argc, char **argv)
{
	ut_init(argc, argv);

	test_cfg_file_syntax();
	test_cfg_file_option();
	test_cmd_cfg();

	return 0;
}
