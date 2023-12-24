# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023, ByteDance Ltd. and/or its Affiliates
# Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>

include $(RTE_SDK)/mk/rte.vars.mk

.PHONY: cflags

cflags:
	@echo $(CFLAGS)
