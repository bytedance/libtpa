# SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause)
# Copyright (c) 2024, ByteDance Ltd. and/or its Affiliates
# Author: Wenlong Luo <luowenlong.linl@bytedance.com>

LLC ?= llc
CLANG ?= clang

BPF_CFLAGS := -Wall -Werror
BPF_CFLAGS += -O2 -emit-llvm -c -g
BPF_CFLAGS += -I$(SRC_ROOT)/include

SRCS += xdp_flow_steering.c

OBJ_DIR = $(OBJ_ROOT)/bpf
OBJS = $(SRCS:%.c=$(OBJ_DIR)/%.o)
DEPS = $(SRCS:%.c=$(OBJ_DIR)/%.d)

all: $(OBJS)

$(OBJS): $(OBJ_DIR)/%.o: %.c | bpf_objs_dir
	$(Q)echo "  CC-BPF $(notdir $@)"
	$(Q)$(CLANG) -S -target bpf -D __BPF_TRACING__ $(BPF_CFLAGS) -o ${@:.o=.ll} $<
	$(Q)$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

bpf_objs_dir:
	$(Q)mkdir -p $(OBJ_DIR)