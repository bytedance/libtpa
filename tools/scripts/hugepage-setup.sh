#!/bin/bash
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
# Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>

hp_file="/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages"
nr_huge=1024

if [ "$(cat $hp_file)" -lt $nr_huge ]; then
	echo ":: allocating $nr_huge huge pages"
	echo $nr_huge > $hp_file

	[ "$(cat $hp_file)" -lt $nr_huge ] && {
		echo ":: warning: short of huge pages"
		exit 1
	}
else
	echo ":: hugepage was already setup"
fi
