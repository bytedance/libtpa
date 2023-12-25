# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
# Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>

ifeq ($(RTE_SDK),)
$(error "no RTE_SDK defined")
endif

CFLAGS += -I$(SRC_ROOT)/include
CFLAGS += -DALLOW_EXPERIMENTAL_API -DTPA_DEBUG
CFLAGS += -Wno-unused-function
CFLAGS += -Wno-unused-result
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

ifneq ($(wildcard $(DPDK_LD_PATH)/librte_telemetry.a),)
LIBS += $(DPDK_LD_PATH)/librte_telemetry.a
endif

LDFLAGS += -Wl,--whole-archive $(LIBS) -Wl,--no-whole-archive
LDFLAGS += $(shell $(SRC_ROOT)/buildtools/dpdk-pkg-config --ldflags)

BINS  = port_alloc
BINS += isn_gen
BINS += rtt_measure
BINS += mkdir_p
BINS += timer
BINS += extmem
BINS += tsock_txq
BINS += cfg
BINS += ipv6
BINS += misc
BINS += dev
BINS += ctrl
BINS += flex_fifo
BINS += archive
BINS += utils

BINS += arp
BINS += garp
BINS += ndp

BINS += sock-offload

BINS += tcp_connect
BINS += tcp_connect_retry
BINS += tcp_connect_crr
BINS += tcp_listen

BINS += tcp_input
BINS += tcp_input_fastpath
BINS += tcp_input_ooo
BINS += tcp_input_wnd
BINS += tcp_input_seq
BINS += tcp_input_fin
BINS += tcp_input_rst
BINS += tcp_input_bench
BINS += tcp_input_merge

BINS += tcp_output
BINS += tcp_output_seq
BINS += tcp_output_fastpath
BINS += tcp_output_partial_ack
BINS += tcp_output_invalid_ack
BINS += tcp_output_fast_retrans
BINS += tcp_output_fast_retrans_with_partial_ack
BINS += tcp_output_chain
BINS += tcp_output_wnd
BINS += tcp_output_tcp_txq_full
#BINS += tcp_output_dev_txq_full    # XXX: need rework
BINS += tcp_output_bench
BINS += tcp_output_fast_retrans_bench

BINS += tcp_timeout_rto

BINS += tcp_close
BINS += tcp_ts
BINS += tcp_zwritev
BINS += tcp_zreadv_chain
BINS += tcp_keepalive
BINS += tcp_sack_gen
BINS += tcp_sack_rcv
BINS += tcp_delayed_ack

BINS += tsock_trace
BINS += tsock_info
BINS += tsock_table
BINS += event_poll
BINS += mem_file

SRCS = test_utils.c $(BINS:=.c)

OBJ_DIR = $(OBJ_ROOT)/test/unit
BIN_DIR = $(BIN_ROOT)/test/unit
OBJS = $(SRCS:%.c=$(OBJ_DIR)/%.o)
DEPS = $(SRCS:%.c=$(OBJ_DIR)/%.d)

BINS_WITH_ABS_PATH = $(BINS:%=$(BIN_DIR)/%)

.PHONY: ALL dump_bins

ALL: $(BINS_WITH_ABS_PATH) dump_bins

.SECONDEXPANSION:
$(BINS_WITH_ABS_PATH): %: $(OBJ_DIR)/$$(notdir %.o) $(OBJ_DIR)/test_utils.o $(LIBS) | OUT_DIRS
	$(Q)echo "  LD $(notdir $@)"
	$(Q)$(CC) $< $(OBJ_DIR)/test_utils.o -o $@ $(LDFLAGS)

$(OBJS): $(OBJ_DIR)/%.o: %.c | OUT_DIRS
	$(Q)echo "  CC $(notdir $@)"
	$(Q)$(CC) $(CFLAGS) -MMD -MP -o $@ -c $<

OUT_DIRS:
	$(Q)mkdir -p $(OBJ_DIR) $(BIN_DIR)

dump_bins: $(BINS_WITH_ABS_PATH)
	$(Q)echo $(BINS) | tr ' ' '\n' | grep -v time-bias > $(BIN_DIR)/.bins.list

-include $(DEPS)
