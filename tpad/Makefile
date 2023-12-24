# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2022, ByteDance Ltd. and/or its Affiliates
# Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>

CFLAGS += -Wno-format-truncation
CFLAGS += -I$(SRC_ROOT)/include -I$(RTE_SDK)/$(RTE_TARGET)/include
CFLAGS += $(shell $(SRC_ROOT)/buildtools/dpdk-pkg-config --cflags)

LDFLAGS += $(shell $(SRC_ROOT)/buildtools/dpdk-pkg-config --ldflags)

SRCS := tpad.c
SRCS += tpad_sock.c

OBJ_DIR = $(OBJ_ROOT)/tpad
BIN_DIR = $(BIN_ROOT)/tpad
OBJS = $(SRCS:%.c=$(OBJ_DIR)/%.o)
DEPS = $(SRCS:%.c=$(OBJ_DIR)/%.d)

BIN = $(BIN_DIR)/tpad

all: $(BIN)

$(BIN): $(OBJS) $(LIBTPA_A) | OUT_DIRS
	$(Q)echo "  LD $(notdir $@)"
	$(Q)$(CC) $^ -o $@ $(LDFLAGS)

$(OBJS): $(OBJ_DIR)/%.o: %.c | OUT_DIRS
	$(Q)echo "  CC $(notdir $@)"
	$(Q)$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

OUT_DIRS:
	$(Q)mkdir -p $(OBJ_DIR) $(BIN_DIR)
