# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
# Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>

ifeq ($(OBJ_ROOT),)
$(error "you should not execute make directly in this dir")
endif

CFLAGS += -I$(SRC_ROOT)/include

SRCS := utils.c

OBJ_DIR = $(OBJ_ROOT)/lib
OBJS = $(SRCS:%.c=$(OBJ_DIR)/%.o)
DEPS = $(SRCS:%.c=$(OBJ_DIR)/%.d)

.PHONY: all

LIB = $(OBJ_DIR)/tpa-lib.a

all: $(LIB)

$(LIB): $(OBJS)
	$(Q)echo "  AR $(notdir $@)"
	$(Q)rm -f $@
	$(Q)ar crDs $@ $^

$(OBJS): $(OBJ_DIR)/%.o: %.c | src_objs
	$(Q)echo "  CC $(notdir $@)"
	$(Q)$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

src_objs:
	$(Q)mkdir -p $(OBJ_DIR)

-include $(DEPS)
