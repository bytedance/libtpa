/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include "tsh.h"

int main(int argc, char *argv[])
{
	int fd;
	int ret;

	if (argc < 2)
		return 0;

	fd = shell_client_create();
	if (fd < 0)
		return -1;

	ret = shell_client_exec(fd, argv[1], argc - 2, argv + 2);

	close(fd);

	return ret;
}

