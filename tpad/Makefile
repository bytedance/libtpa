# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2022, ByteDance Ltd. and/or its Affiliates
# Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>

CFLAGS += -Wno-format-truncation
CFLAGS += -I$(SRC_ROOT)/include -I$(RTE_SDK)/$(RTE_TARGET)/include
CFLAGS += $(shell $(SRC_ROOT)/buildtools/dpdk-pkg-config --cflags)

LIBS  = $(OBJ_ROOT)/src/tpa-core.a
LIBS += $(OBJ_ROOT)/lib/tpa-lib.a
LIBS += $(DPDK_LD_PATH)/librte_eal.a
LIBS += $(DPDK_LD_PATH)/librte_ethdev.a
LIBS += $(DPDK_LD_PATH)/librte_kvargs.a
LIBS += $(DPDK_LD_PATH)/librte_mbuf.a
LIBS += $(DPDK_LD_PATH)/librte_mempool.a
LIBS += $(DPDK_LD_PATH)/librte_mempool_ring.a
LIBS += $(DPDK_LD_PATH)/librte_net.a
LIBS += $(DPDK_LD_PATH)/librte_ring.a
LIBS += $(DPDK_LD_PATH)/librte_hash.a
LIBS += $(DPDK_LD_PATH)/librte_rcu.a

ifneq ($(filter v20.11% v22.11%, $(DPDK_VERSION)),)
LIBS += $(DPDK_LD_PATH)/librte_telemetry.a
endif

LDFLAGS += -Wl,--whole-archive $(LIBS) -Wl,--no-whole-archive
LDFLAGS += $(shell $(SRC_ROOT)/buildtools/dpdk-pkg-config --ldflags)

SRCS := tpad.c
SRCS += tpad_sock.c

OBJ_DIR = $(OBJ_ROOT)/tpad
BIN_DIR = $(BIN_ROOT)/tpad
OBJS = $(SRCS:%.c=$(OBJ_DIR)/%.o)
DEPS = $(SRCS:%.c=$(OBJ_DIR)/%.d)

BIN = $(BIN_DIR)/tpad

all: $(BIN)

$(BIN): $(OBJS) | OUT_DIRS
	$(Q)echo "  LD $(notdir $@)"
	$(Q)$(CC) $^ -o $@ $(LDFLAGS)

$(OBJS): $(OBJ_DIR)/%.o: %.c | OUT_DIRS
	$(Q)echo "  CC $(notdir $@)"
	$(Q)$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

OUT_DIRS:
	$(Q)mkdir -p $(OBJ_DIR) $(BIN_DIR)
