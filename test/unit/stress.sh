#!/bin/bash
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
# Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>

ulimit -c unlimited
ulimit -s unlimited
echo 0x7b > /proc/self/coredump_filter

export TPA_LOG_DISABLE="yes"

./run.rb -t 0 -j "$(grep -c processor /proc/cpuinfo)" -p $@
