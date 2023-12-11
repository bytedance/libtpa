/**
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Wenlong Luo <luowenlong@bytedance.com>
 */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "lib/utils.h"

static void test_mkdir(void)
{
	assert(mkdir_p("/tmp/tpa-mkdir-test/world") == 0);
	assert(mkdir_p("///tmp/tpa-mkdir-test///world///") == 0);

	assert(mkdir_p("./test_mkdir/A/B/") == 0);
	assert(mkdir_p("./test_mkdir/A/../C") == 0);
	assert(mkdir_p("test_mkdir/D/") == 0);
	assert(mkdir_p("./test_mkdir/A/H//") == 0);

	system("rm -r ./test_mkdir");
	system("rm -r /tmp/tpa-mkdir-test");
}

int main(void)
{
	test_mkdir();

	return 0;
}
