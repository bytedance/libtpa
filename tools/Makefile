# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
# Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>

SUBDIRS := mem-file
SUBDIRS += sock-list
SUBDIRS += sock-trace
SUBDIRS += sock-trace-list
SUBDIRS += scripts
SUBDIRS += tsh

.PHONY: all $(SUBDIRS)

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@
