/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022, ByteDance Ltd. and/or its Affiliates
 * Author: Wenlong Luo <luowenlong.linl@bytedance.com>
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>

#include "lib/utils.h"
#include "mem_file.h"

static char dump_path[PATH_MAX];

static inline void usage(void)
{
	fprintf(stderr, "usage: mem-file $parser mem-file [options]\n");
	fprintf(stderr, "       mem-file -i mem-file\n");

	exit(1);
}

static void rm_parser(void)
{
	unlink(dump_path);
}

static int do_dump_parser(struct mem_file *mem_file, const char *parser_name)
{
	FILE *file;
	void *parser;
	size_t size;

	snprintf(dump_path, sizeof(dump_path), "/tmp/%s-parser-%d", parser_name, getpid());
	file = fopen(dump_path, "w");
	if (!file) {
		fprintf(stderr, "failed to create parser file: %s: %s\n",
			dump_path, strerror(errno));
		return -1;
	}
	atexit(rm_parser);

	parser = mem_file_parser(mem_file);
	size = mem_file_parser_size(mem_file);
	if (size == 0 || fwrite(parser, size, 1, file) != 1) {
		if (size) {
			fprintf(stderr, "failed to dump parser: %s: %s\n",
				dump_path, strerror(errno));
		}

		fclose(file);
		return -1;
	}

	fclose(file);
	chmod(dump_path, 0755);

	return 0;
}

static char *parser_dump(const char *parser_name, const char *mem_file_path)
{
	struct mem_file *mem_file;
	static char path[PATH_MAX];

	if (!getenv("TPA_USE_SYSTEM_PARSER")) {
		mem_file = mem_file_map(mem_file_path, NULL, MEM_FILE_READ);
		if (mem_file == NULL)
			return NULL;

		if (do_dump_parser(mem_file, parser_name) == 0)
			return dump_path;
	}

	return parser_path_resolve(parser_name, path, sizeof(path));
}

static int parser_exec(int argc, char **argv, const char *parser_path)
{
	char cmd[4096];
	int i;
	int len;

	len = snprintf(cmd, sizeof(cmd), "%s ", parser_path);
	for (i = 0; i < argc; i++)
		len += snprintf(cmd + len, sizeof(cmd) - len, "%s ", argv[i]);

	if (system(cmd) == -1) {
		fprintf(stderr, "failed to exec: %s: %s\n", cmd, strerror(errno));
		return -1;
	}

	return 0;
}

static int show_mem_file_info(const char *path)
{
	struct mem_file *mem_file;

	mem_file = mem_file_map(path, NULL, MEM_FILE_READ);
	if (!mem_file)
		return -1;

	printf("%s:\n"
	       "  data_off    %lu\n"
	       "  data_size   %lu\n"
	       "  parser_off  %lu\n"
	       "  parser_size %lu\n"
	       "  name        %s\n",
	       path,
	       mem_file->hdr->data_offset,   mem_file_data_size(mem_file),
	       mem_file->hdr->parser_offset, mem_file_parser_size(mem_file),
	       mem_file->hdr->name);

	return 0;
}

int main(int argc, char **argv)
{
	char *parser_path;

	if (argc < 3)
		usage();

	if (strcmp(argv[1], "-i") == 0)
		return show_mem_file_info(argv[2]);

	parser_path = parser_dump(argv[1], argv[2]);
	if (!parser_path) {
		fprintf(stderr, "failed to locate parser %s\n", argv[1]);
		return -1;
	}

	return parser_exec(argc - 3, &argv[3], parser_path);
}
