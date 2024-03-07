#!/bin/bash
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023, ByteDance Ltd. and/or its Affiliates
# Author: Tao Liu <liutao.xyz@bytedance.com>

REDIS_DIR=redis
REDIS_REPO=${REDIS_REPO:-https://github.com/redis/redis.git}
REDIS_BRANCH="7.0.0"

get_repo()
{
	[ -d "$REDIS_DIR" ] && return

	git clone $REDIS_REPO -b $REDIS_BRANCH $REDIS_DIR || exit 1
	(cd $REDIS_DIR && git apply ../accelerate-with-libtpa.patch) || exit 1
}

build()
{
	get_repo

	pkg-config --cflags libtpa >/dev/null 2>&1 || {
		echo "error: you should install Libtpa first by 'make install'"
		exit 1
	}

	cd $REDIS_DIR
	make clean
	make -j$(nproc)
}

build
