# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
# Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>

ifeq ($(RTE_SDK),)
$(error "no RTE_SDK defined")
endif

CFLAGS += $(shell $(SRC_ROOT)/buildtools/dpdk-pkg-config --cflags)
CFLAGS += -I$(SRC_ROOT)/include
CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += -DTPA_DEBUG

old_version = $(shell awk '{print $$3}' $(SRC_ROOT)/include/version.h 2>/dev/null| tr -d '"')
cur_version = $(shell ../buildtools/get-ver.sh)
ifneq ($(old_version),$(cur_version))
$(shell rm -f $(SRC_ROOT)/include/version.h)
endif

SRCS += trace.c
SRCS += log.c
SRCS += shell.c
SRCS += worker.c
SRCS += cfg.c
SRCS += stats.c
SRCS += event.c
SRCS += mem_file.c
SRCS += archive.c
SRCS += ctrl.c
SRCS += port_alloc.c

SRCS += sock.c
SRCS += offload.c
SRCS += dev.c
SRCS += dpdk.c
SRCS += tpa.c
SRCS += tpad.c
SRCS += neigh.c
SRCS += arp.c
SRCS += ndp.c

VPATH += ./tcp
SRCS += tcp_input.c
SRCS += tcp_output.c
SRCS += tcp_timeout.c

VPATH += ./pktfuzz
SRCS += pktfuzz.c
SRCS += fuzzer_cut.c
SRCS += fuzzer_delay.c
SRCS += fuzzer_drop.c
SRCS += fuzzer_dup.c
SRCS += fuzzer_reorder.c

OBJ_DIR = $(OBJ_ROOT)/src
OBJS = $(SRCS:%.c=$(OBJ_DIR)/%.o)
DEPS = $(SRCS:%.c=$(OBJ_DIR)/%.d)

.PHONY: all

all: $(OBJ_DIR)/tpa-core.a

$(OBJ_DIR)/tpa-core.a: $(OBJS)
	$(Q)echo "  AR $(notdir $@)"
	$(Q)rm -f $@
	$(Q)ar crDs $@ $^

$(OBJS): $(OBJ_DIR)/%.o: %.c | src_objs
	$(Q)echo "  CC $(notdir $@)"
	$(Q)$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

src_objs:
	$(Q)mkdir -p $(OBJ_DIR)

$(OBJ_DIR)/cfg.o: $(SRC_ROOT)/include/version.h
$(OBJ_DIR)/tpa.o: $(SRC_ROOT)/include/build-info.h

$(SRC_ROOT)/include/version.h:
	$(Q)echo "  VER $(cur_version)"
	$(Q)echo "#define TPA_VERSION	\"$(cur_version)\"" > $@

$(SRC_ROOT)/include/build-info.h: $(SRCS)
	$(Q)echo "  GEN build-info.h"
	$(Q)echo "#define BUILD_MODE	\"$(BUILD_MODE)\"" > $(SRC_ROOT)/include/build-info.h
	$(Q)echo "#define BUILD_COMPILER	\"$(shell $(CC) -v 2>&1 | grep -w version)\"" >> $(SRC_ROOT)/include/build-info.h
	$(Q)echo "#define BUILD_BOX	\"$(shell hostname)\"" >> $(SRC_ROOT)/include/build-info.h
	$(Q)echo "#define BUILD_DATE	\"$(shell date)\"" >> $(SRC_ROOT)/include/build-info.h

-include $(DEPS)
