/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 * Author: Wenlong Luo <luowenlong@bytedance.com>
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <rte_cycles.h>

#include "lib/utils.h"
#include "version.h"
#include "cfg.h"
#include "shell.h"
#include "log.h"
#include "ip.h"
#include "dev.h"

struct cfg_ctx {
	FILE *file;

	int token;

	int idx;
	char token_name[NAME_SIZE];

	struct cfg_section *section;
	struct cfg_opt *opt;
};

struct tpa_cfg tpa_cfg;

enum {
	TOKEN_NONE,
	TOKEN_BRACE_LEFT,
	TOKEN_BRACE_RIGHT,
	TOKEN_STRING,
	TOKEN_EQUAL,
	TOKEN_OPT_END,
	TOKEN_BAD,
	TOKEN_CONSUMED
};

static int is_valid_char(char c)
{
	char *reserved_chars = "\t\n{}= ;";

	return strchr(reserved_chars, c) == NULL;
}

static int token_put_char(struct cfg_ctx *ctx, char c)
{
	if (ctx->idx >= sizeof(ctx->token_name) - 1) {
		LOG_WARN("token too long: %s", ctx->token_name);
		return -1;
	}

	ctx->token_name[ctx->idx++] = c;
	return 0;
}

static int match_quoted_string(struct cfg_ctx *ctx)
{
	char c;

	while (1) {
		c = fgetc(ctx->file);
		if (c == EOF) {
			LOG_WARN("missing end quotation mark for token: %s",  ctx->token_name);
			return -1;
		}

		if (c == '"')
			break;

		if (token_put_char(ctx, c) < 0)
			return -1;
	}

	return 0;
}

static int get_string_token(struct cfg_ctx *ctx, char c)
{
	int token = TOKEN_BAD;
	int ret;

	if (!is_valid_char(c))
		return TOKEN_BAD;

	ctx->idx = 0;
	while (1) {
		if (c == '"')
			ret = match_quoted_string(ctx);
		else
			ret = token_put_char(ctx, c);
		if (ret < 0)
			return TOKEN_BAD;

		c = fgetc(ctx->file);
		if (c == EOF)
			break;

		if (!is_valid_char(c)) {
			ungetc(c, ctx->file);
			break;
		}
	}

	if (ctx->idx)
		token = TOKEN_STRING;

	return token;
}

static int token_do_peek_type(struct cfg_ctx *ctx, int count_nl)
{
	int token;
	char c;

	/* last token is not consumed yet */
	if (ctx->token != TOKEN_CONSUMED)
		return ctx->token;

	token = TOKEN_NONE;
	memset(ctx->token_name, 0, sizeof(ctx->token_name));
	while ((c = fgetc(ctx->file)) != EOF) {
		switch (c) {
		case ' ':
		case '\t':
			break;

		case '\n':
			if (count_nl)
				token = TOKEN_OPT_END;
			break;
		case ';':
			token = TOKEN_OPT_END;
			break;

		case '#':
			while (c != '\n')
				c = fgetc(ctx->file);
			if (count_nl)
				ungetc(c, ctx->file);
			break;

		case '{':
			ctx->token_name[0] = c;
			token = TOKEN_BRACE_LEFT;
			break;

		case '}':
			ctx->token_name[0] = c;
			token = TOKEN_BRACE_RIGHT;
			break;

		case '=':
			ctx->token_name[0] = c;
			token = TOKEN_EQUAL;
			break;

		default:
			token = get_string_token(ctx, c);
			break;
		}

		if (token != TOKEN_NONE)
			break;
	}

	ctx->token = token;

	return token;
}

static int token_peek_type(struct cfg_ctx *ctx)
{
	return token_do_peek_type(ctx, 0);
}

static int token_do_get_type(struct cfg_ctx *ctx, int count_nl)
{
	int token;

	token = token_do_peek_type(ctx, count_nl);
	ctx->token = TOKEN_CONSUMED;

	return token;
}

static int token_get_type(struct cfg_ctx *ctx)
{
	return token_do_get_type(ctx, 0);
}

static char *token_get_name(struct cfg_ctx *ctx)
{
	return ctx->token_name;
}

static struct cfg_section *cfg_section_find(const char *name)
{
	struct cfg_section *sect = tpa_cfg.cfg_sections;

	while (sect != NULL) {
		if (strcmp(sect->name, name) == 0)
			return sect;

		sect = sect->next;
	}

	return NULL;
}

static int cfg_file_match_section_name(struct cfg_ctx *ctx)
{
	struct cfg_section *section = ctx->section;

	if (token_get_type(ctx) != TOKEN_STRING) {
		LOG_WARN("cfg: '%s' is not a valid section name", token_get_name(ctx));
		return -1;
	}

	/* TODO: do sanity check for section name here */
	tpa_snprintf(section->name, sizeof(section->name), "%s", token_get_name(ctx));

	return 0;
}

static int cfg_file_match_brace(struct cfg_ctx *ctx, int type)
{
	if (token_get_type(ctx) != type) {
		LOG_WARN("cfg: expected '%c', while got '%s'",
			 type == TOKEN_BRACE_LEFT ? '{' : '}', token_get_name(ctx));
		return -1;
	}

	return 0;
}

static int cfg_file_match_opt_name(struct cfg_ctx *ctx)
{
	if (token_get_type(ctx) != TOKEN_STRING) {
		LOG_WARN("cfg: '%s' is not a valid option name", token_get_name(ctx));
		return -1;
	}

	tpa_snprintf(ctx->opt->name, sizeof(ctx->opt->name), "%s", token_get_name(ctx));

	return 0;
}

static int cfg_file_match_equal(struct cfg_ctx *ctx)
{
	if (token_get_type(ctx) != TOKEN_EQUAL) {
		LOG_WARN("cfg: opt=%s.%s: expected '=', while got '%s'",
			 ctx->section->name, ctx->opt->name, token_get_name(ctx));
		return -1;
	}

	return 0;
}

static int cfg_file_match_opt_val(struct cfg_ctx *ctx)
{
	struct cfg_opt *opt = ctx->opt;
	int len = 0;
	int token;

	while (1) {
		token = token_do_get_type(ctx, 1);
		if (token == TOKEN_OPT_END)
			break;

		if (token != TOKEN_STRING) {
			LOG_WARN("cfg: opt %s.%s has invalid value: '%s'",
				 ctx->section->name, opt->name, token_get_name(ctx));
			return -1;
		}

		len += tpa_snprintf(opt->val + len, sizeof(opt->val) - len, "%s ", token_get_name(ctx));
	}

	if (len == 0) {
		LOG_WARN("cfg: opt %s.%s has no value", ctx->section->name, opt->name);
		return -1;
	}

	/* remove tailing ' ' */
	opt->val[len-1] = '\0';

	return 0;
}

#define INSERT(head, node)			do {	\
	node->next = head;				\
	head = node;					\
} while (0)

static struct cfg_opt *cfg_opt_find(struct cfg_section *section, const char *name)
{
	struct cfg_opt *opt;

	opt = section->opts;
	while (opt) {
		if (strcmp(opt->name, name) == 0)
			return opt;

		opt = opt->next;
	}

	return opt;
}

static void cfg_opt_insert(struct cfg_section *section, struct cfg_opt *new_opt)
{
	struct cfg_opt *opt;

	opt = cfg_opt_find(section, new_opt->name);
	if (opt == NULL) {
		INSERT(section->opts, new_opt);
		return;
	}

	tpa_snprintf(opt->val, sizeof(opt->val), "%s", new_opt->val);
	free(new_opt);
}

static int cfg_file_match_options(struct cfg_ctx *ctx)
{
	struct cfg_opt *opt;

	while (1) {
		/* end of section */
		if (token_peek_type(ctx) == TOKEN_BRACE_RIGHT)
			break;

		opt = malloc(sizeof(struct cfg_opt));
		if (!opt)
			return -1;

		memset(opt, 0, sizeof(*opt));
		ctx->opt = opt;

		if (cfg_file_match_opt_name(ctx) < 0 ||
		    cfg_file_match_equal(ctx) < 0    ||
		    cfg_file_match_opt_val(ctx) < 0) {
			free(opt);
			return -1;
		}

		LOG("detected cfg opt [%s.%s=%s]", ctx->section->name, opt->name, opt->val);
		cfg_opt_insert(ctx->section, opt);
	}

	return 0;
}

static void cfg_section_insert(struct cfg_section *new_section)
{
	struct cfg_section *section;
	struct cfg_opt *opt;
	struct cfg_opt *next;

	section = cfg_section_find(new_section->name);
	if (section == NULL) {
		INSERT(tpa_cfg.cfg_sections, new_section);
		return;
	}

	opt = new_section->opts;
	while (opt) {
		next = opt->next;
		cfg_opt_insert(section, opt);

		opt = next;
	}

	free(new_section);
}

static int cfg_file_match_section(struct cfg_ctx *ctx)
{
	struct cfg_section *section;
	int ret = 0;

	section = malloc(sizeof(struct cfg_section));
	if (!section)
		return -1;

	memset(section, 0, sizeof(*section));
	ctx->section = section;

	if (cfg_file_match_section_name(ctx) < 0            ||
	    cfg_file_match_brace(ctx, TOKEN_BRACE_LEFT) < 0 ||
	    cfg_file_match_options(ctx)  < 0                ||
	    cfg_file_match_brace(ctx, TOKEN_BRACE_RIGHT) < 0) {
		ret = -1;
	}

	/*
	 * be tolerant here: we accept all valid options before
	 * a bad one is met.
	 */
	if (section->opts)
		cfg_section_insert(section);
	else
		free(section);

	return ret;
}

int cfg_file_parse(FILE *f)
{
	struct cfg_ctx ctx = {
		.file = f,
		.token = TOKEN_CONSUMED,
	};

	while (1) {
		/* end of cfg file */
		if (token_peek_type(&ctx) == TOKEN_NONE)
			break;

		if (cfg_file_match_section(&ctx) < 0)
			return -1;
	}

	return 0;
}

const char *cfg_file_opt_get(const char *name)
{
	struct cfg_section *section;
	struct cfg_opt *opt;
	char section_name[NAME_SIZE];
	char *opt_name;
	char *dot;

	dot = strchr(name, '.');
	if (!dot)
		return NULL;

	tpa_snprintf(section_name, sizeof(section_name), "%s", name);
	section_name[dot - name] = '\0';
	opt_name = dot + 1;

	CFG_SECTION_FOREACH(section) {
		if (strcmp(section->name, section_name))
			continue;

		for (opt = section->opts; opt != NULL; opt = opt->next) {
			if (strcmp(opt->name, opt_name) == 0)
				return opt->val;
		}
	}

	return NULL;
}

static int cmd_version(struct shell_cmd_info *cmd)
{
	shell_append_reply(cmd->reply, "%s\n", TPA_VERSION);
	return 0;
}

static long int cfg_parse_num(const char *val, int type)
{
	uint64_t n;

	if (type == CFG_TYPE_SIZE)
		type = NUM_TYPE_SIZE;
	else if (type == CFG_TYPE_TIME)
		type = NUM_TYPE_TIME_US;
	else
		type = NUM_TYPE_NONE;

	n = tpa_parse_num(val, type);
	if (errno)
		return -1;

	return n;
}

int cfg_spec_set_num(struct cfg_spec *spec, const char *val)
{
	long int num;

	num = cfg_parse_num(val, spec->type);
	if (num < 0) {
		LOG_WARN("set %s fail, %s is not a valid cfg value", spec->name, val);
		return -1;
	}

	if ((spec->flags & CFG_FLAG_HAS_MIN) && num < spec->min) {
		LOG_WARN("set %s fail, %s is less than cfg_spec min: %u",
			 spec->name, val, spec->min);
		return -1;
	}

	if ((spec->flags & CFG_FLAG_HAS_MAX) && num > spec->max) {
		LOG_WARN("set %s fail, %s is larger than cfg_spec max: %u",
			 spec->name, val, spec->max);
		return -1;
	}

	if ((spec->flags & CFG_FLAG_POWEROF2) && ((num & (num - 1)) != 0)) {
		LOG_WARN("set %s fail, %s is not power of 2", spec->name, val);
		return -1;
	}

	*(uint32_t *)spec->data = num;

	return 0;
}

static int cfg_spec_set_str(struct cfg_spec *spec, const char *val)
{
	tpa_snprintf(spec->data, spec->data_len, "%s", val);

	return 0;
}

static in_addr_t cfg_parse_ipv4(const char *val)
{
	const char *p = val;
	int nr_dot = 0;

	/*
	 * inet_addr treat a, a.b, a.b.c as valid ip; while in our case,
	 * they are not. Therefore, an extra sanity check is needed.
	 */
	while ((p = strchr(p, '.'))) {
		nr_dot += 1;
		p += 1;
	}
	if (nr_dot != 3)
		return INADDR_NONE;

	return inet_addr(val);
}

static int cfg_spec_set_ipv4(struct cfg_spec *spec, const char *val)
{
	in_addr_t ip = cfg_parse_ipv4(val);

	if (ip == INADDR_NONE)
		return -1;

	*(in_addr_t *)spec->data = ip;

	return 0;
}

static int cfg_spec_set_ipv6(struct cfg_spec *spec, const char *val)
{
	struct dev_ip dev_ip;
	int prefixlen = 0;
	char buf[120];
	char *p;

	tpa_snprintf(buf, sizeof(buf), "%s", val);

	p = strchr(buf, '/');
	if (p) {
		*p = '\0';

		prefixlen = atoi(p + 1);
		if (prefixlen <= 0 || prefixlen > 128) {
			LOG_ERR("invalid ipv6 prefix len: %s\n", p);
			return -1;
		}
	}

	dev_ip.prefixlen = prefixlen;
	if (tpa_ip_from_str(&dev_ip.ip, buf) == NULL) {
		LOG_ERR("invalid ipv6 format: %s", buf);
		return -1;
	}

	if (tpa_ip_is_ipv4(&dev_ip.ip)) {
		LOG_ERR("ipv4 is given while ipv6 is expected: %s", buf);
		return -1;
	}

	*(struct dev_ip *)spec->data = dev_ip;

	return 0;
}

static int cfg_spec_set_mac(struct cfg_spec *spec, const char *val)
{
	struct ether_addr ethaddr;

	if (sscanf(val, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			&ethaddr.ether_addr_octet[0], &ethaddr.ether_addr_octet[1],
			&ethaddr.ether_addr_octet[2], &ethaddr.ether_addr_octet[3],
			&ethaddr.ether_addr_octet[4], &ethaddr.ether_addr_octet[5]) != 6) {
		LOG_ERR("invalid mac format: %s", val);
		return -1;
	}

	*(struct ether_addr *)spec->data = ethaddr;

	return 0;
}

static int is_invalid_mask(uint32_t mask)
{
	mask = ~htonl(mask);

	return (mask & (mask + 1)) != 0;
}

static int cfg_spec_set_mask(struct cfg_spec *spec, const char *val)
{
	in_addr_t mask = cfg_parse_ipv4(val);

	if (is_invalid_mask(mask))
		return -1;

	*(in_addr_t *)spec->data = mask;

	return 0;
}

static int cfg_spec_set(struct cfg_spec *spec, const char *val, int init)
{
	if ((spec->flags & CFG_FLAG_RDONLY) && init == 0)
		return -1;

	if (spec->set)
		return spec->set(spec, val);

	switch (spec->type) {
	case CFG_TYPE_SIZE:
	case CFG_TYPE_TIME:
	case CFG_TYPE_UINT:
		return cfg_spec_set_num(spec, val);

	case CFG_TYPE_STR:
		return cfg_spec_set_str(spec, val);

	case CFG_TYPE_IPV4:
		return cfg_spec_set_ipv4(spec, val);

	case CFG_TYPE_IPV6:
		return cfg_spec_set_ipv6(spec, val);

	case CFG_TYPE_MAC:
		return cfg_spec_set_mac(spec, val);

	case CFG_TYPE_MASK:
		return cfg_spec_set_mask(spec, val);
	}

	return -1;
}

static struct cfg_spec *cfg_spec_find(const char *name)
{
	struct cfg_spec *spec;
	int i;

	for (i = 0; i < tpa_cfg.nr_spec; ++i) {
		spec = tpa_cfg.cfg_specs[i];

		if (strcmp(name, spec->name) == 0)
			return spec;
	}

	return NULL;
}

#define _SEC(s)			((s) * 1000000)

static int cfg_spec_get_num(struct cfg_spec *spec, char *val)
{
	uint32_t num = *(uint32_t *)spec->data;

	if (spec->type == CFG_TYPE_SIZE && num) {
		if (num % (1<<30) == 0)
			tpa_snprintf(val, VAL_SIZE, "%uGB", num / (1<<30));
		else if (num % (1<<20) == 0)
			tpa_snprintf(val, VAL_SIZE, "%uMB", num / (1<<20));
		else if (num % (1<<10) == 0)
			tpa_snprintf(val, VAL_SIZE, "%uKB", num / (1<<10));
		else
			tpa_snprintf(val, VAL_SIZE, "%u", num);

		return 0;
	}

	if (spec->type == CFG_TYPE_TIME && num) {
		if (num % _SEC(60) == 0)
			tpa_snprintf(val, VAL_SIZE, "%um", num / _SEC(60));
		else if (num % _SEC(1) == 0)
			tpa_snprintf(val, VAL_SIZE, "%us", num / _SEC(1));
		else if (num % 1000 == 0)
			tpa_snprintf(val, VAL_SIZE, "%ums", num / 1000);
		else
			tpa_snprintf(val, VAL_SIZE, "%uus", num / 1000);

		return 0;
	}

	tpa_snprintf(val, VAL_SIZE, "%u", *(uint32_t *)spec->data);
	return 0;
}

static int cfg_spec_get_str(struct cfg_spec *spec, char *val)
{
	tpa_snprintf(val, VAL_SIZE, "%s", (char *)spec->data);

	return 0;
}

static int cfg_spec_get_ipv4(struct cfg_spec *spec, char *val)
{
	tpa_snprintf(val, VAL_SIZE, "%s", inet_ntoa(*(struct in_addr*)spec->data));

	return 0;
}

static int cfg_spec_get_ipv6(struct cfg_spec *spec, char *val)
{
	struct dev_ip *dev_ip = (struct dev_ip *)spec->data;
	char addr[INET6_ADDRSTRLEN];
	int len;

	tpa_ip_to_str(&dev_ip->ip, addr, sizeof(addr));

	len = tpa_snprintf(val, VAL_SIZE, "%s", addr);
	if (dev_ip->prefixlen)
		tpa_snprintf(val + len, VAL_SIZE - len, "/%d", dev_ip->prefixlen);

	return 0;
}

static int cfg_spec_get_mac(struct cfg_spec *spec, char *val)
{
	struct ether_addr *ethaddr = (struct ether_addr *)spec->data;

	tpa_snprintf(val, VAL_SIZE, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		 ethaddr->ether_addr_octet[0], ethaddr->ether_addr_octet[1],
		 ethaddr->ether_addr_octet[2], ethaddr->ether_addr_octet[3],
		 ethaddr->ether_addr_octet[4], ethaddr->ether_addr_octet[5]);

	return 0;
}

static int cfg_spec_get_val(struct cfg_spec *spec, char *val)
{
	if (spec->get)
		return spec->get(spec, val);

	switch (spec->type) {
	case CFG_TYPE_UINT:
	case CFG_TYPE_SIZE:
	case CFG_TYPE_TIME:
		return cfg_spec_get_num(spec, val);

	case CFG_TYPE_STR:
		return cfg_spec_get_str(spec, val);

	case CFG_TYPE_IPV4:
		return cfg_spec_get_ipv4(spec, val);

	case CFG_TYPE_IPV6:
		return cfg_spec_get_ipv6(spec, val);

	case CFG_TYPE_MAC:
		return cfg_spec_get_mac(spec, val);

	case CFG_TYPE_MASK:
		return cfg_spec_get_ipv4(spec, val);
	}

	return -1;
}

static void usage(struct shell_cmd_info *cmd)
{
	shell_append_reply(cmd->reply,
			   "usage: cfg cmd [opts]\n"
			   "           set opt val      set config option\n"
			   "           list             list available options and their values\n");
}

static void cfg_list(struct shell_cmd_info *cmd)
{
	struct cfg_spec *spec;
	char val[VAL_SIZE];
	int i;

	for (i = 0; i < tpa_cfg.nr_spec; ++i) {
		spec = tpa_cfg.cfg_specs[i];

		val[0] = '\0';
		cfg_spec_get_val(spec, val);

		shell_append_reply(cmd->reply, "%-24s %s\n", spec->name,
				   strlen(val) ? val: "N/A");
	}
}

static inline int match(struct shell_cmd_info *cmd, const char *str)
{
	return strcmp(str, cmd->argv[0]) == 0;
}

static int cfg_set(struct shell_cmd_info *cmd)
{
	struct cfg_spec *spec;
	char *opt_name;
	char *opt_val;
	char *error;

	if (cmd->argc != 3) {
		usage(cmd);
		return -1;
	}

	opt_name = cmd->argv[1];
	opt_val = cmd->argv[2];
	spec = cfg_spec_find(opt_name);
	if (spec == NULL) {
		shell_append_reply(cmd->reply,
				   "error: invalid option name: %s\n", opt_name);
		return -1;
	}

	if (cfg_spec_set(spec, opt_val, 0) == -1) {
		if (spec->flags & CFG_FLAG_RDONLY)
			error = "try to set a readonly option";
		else
			error = "invalid option value";

		shell_append_reply(cmd->reply, "failed to set cfg opt: %s: %s\n",
				   spec->name, error);

		return -1;
	}

	return 0;
}

int cmd_cfg(struct shell_cmd_info *cmd)
{
	if (cmd->argc == 0) {
		usage(cmd);
	} else if (match(cmd, "set")) {
		return cfg_set(cmd);
	} else if (match(cmd, "list")) {
		cfg_list(cmd);
	} else {
		shell_append_reply(cmd->reply, "error: invalid cmd: %s\n", cmd->argv[0]);
		usage(cmd);
		return -1;
	}

	return 0;
}

static const struct shell_cmd version = {
	.name    = "version",
	.handler = cmd_version,
};

static const struct shell_cmd cfg = {
	.name    = "cfg",
	.handler = cmd_cfg,
};

static char *cfg_file_find(void)
{
	static char path[PATH_MAX];
	char *dir[] = {
		".",
		"/etc",
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(dir); i++) {
		tpa_snprintf(path, PATH_MAX, "%s/tpa.cfg", dir[i]);
		if (access(path, F_OK) == 0)
			return path;
	}

	return NULL;
}

static void cfg_file_load(void)
{
	FILE *file;
	char *path;

	path = cfg_file_find();
	if (!path)
		return;

	LOG("loading cfg file %s", path);

	file = fopen(path, "r");
	if (!file) {
		LOG_ERR("failed to open cfg file %s: %s", path, strerror(errno));
		return;
	}

	cfg_file_parse(file);

	fclose(file);
}

static void cfg_load_from_env_var(void)
{
	char *cfg = getenv("TPA_CFG");
	FILE *f;

	if (!cfg)
		return;

	LOG("loading cfg options from env var: %s", cfg);

	f = tmpfile();
	if (!f) {
		LOG_ERR("cfg: failed to create tmpfile: %s\n", strerror(errno));
		return;
	}

	/*
	 * XXX: we rely on fgetc for cfg file parsing; therefore,
	 * we need flush the env to a file first
	 */
	fwrite(cfg, strlen(cfg), 1, f);
	fflush(f);
	fseek(f, 0, SEEK_SET);

	cfg_file_parse(f);

	fclose(f);
}

int cfg_init(void)
{
	memset(&tpa_cfg, 0, sizeof(tpa_cfg));

	shell_register_cmd(&version);
	shell_register_cmd(&cfg);

	cfg_file_load();
	cfg_load_from_env_var();

	return 0;
}

int cfg_section_parse(const char *section_name)
{
	struct cfg_section *sect;
	struct cfg_spec *spec;
	struct cfg_opt *opt;
	char name[(NAME_SIZE + 1) * 2];
	int ret = 0;

	sect = cfg_section_find(section_name);
	if (sect == NULL)
		return -1;

	opt = sect->opts;
	while (opt != NULL) {
		tpa_snprintf(name, sizeof(name), "%s.%s", section_name, opt->name);
		spec = cfg_spec_find(name);
		if (spec)
			ret |= cfg_spec_set(spec, opt->val, 1);

		opt = opt->next;
	}

	return ret;
}

static int cfg_spec_register_one(struct cfg_spec *spec)
{
	if (tpa_cfg.nr_spec >= CFG_SPECS_SIZE)
		return -1;

	if (cfg_spec_find(spec->name)) {
		LOG_WARN("failed to register cfg spec %s: already registered",
			 spec->name);
		return -1;
	}

	if (spec->type <= CFG_TYPE_MIN || spec->type >= CFG_TYPE_MAX) {
		LOG_WARN("failed to register cfg spec %s: invaild type: %d",
			 spec->name, spec->type);
		return -1;
	}

	tpa_cfg.cfg_specs[tpa_cfg.nr_spec++] = spec;

	return 0;
}

int cfg_spec_register(struct cfg_spec *specs, int nr_spec)
{
	int i;

	for (i = 0; i < nr_spec; i++)
		cfg_spec_register_one(&specs[i]);

	return 0;
}

void cfg_dump_unknown_opts(void)
{
	struct cfg_section *sect;
	struct cfg_opt *opt;
	char name[(NAME_SIZE + 1) * 2];

	CFG_SECTION_FOREACH(sect) {
		for (opt = sect->opts; opt != NULL; opt = opt->next) {
			tpa_snprintf(name, sizeof(name), "%s.%s", sect->name, opt->name);
			if (cfg_spec_find(name) == NULL)
				LOG_WARN("unknown opt: %s.%s", sect->name, opt->name);
		}
	}
}

void cfg_reset(void)
{
	struct cfg_section *sect;
	struct cfg_section *sect_next;
	struct cfg_opt *opt;
	struct cfg_opt *opt_next;

	sect = tpa_cfg.cfg_sections;
	tpa_cfg.cfg_sections = NULL;

	while (sect) {
		sect_next = sect->next;

		opt = sect->opts;
		while (opt) {
			opt_next = opt->next;
			free(opt);

			opt = opt_next;
		}

		free(sect);
		sect = sect_next;
	}
}
