# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
# Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>

SCRIPTS := run
SCRIPTS += nic_iavf.sh
SCRIPTS += nic_mlnx.sh
SCRIPTS += iavf-bind
SCRIPTS += hugepage-setup.sh
SCRIPTS += sock-stats
SCRIPTS += tpa
SCRIPTS += worker-stats
SCRIPTS += diag

BIN_DIR = $(BIN_ROOT)/tools

all: $(SCRIPTS)
	$(Q)mkdir -p $(BIN_DIR)
	$(Q)cp -d $^ $(BIN_DIR)
