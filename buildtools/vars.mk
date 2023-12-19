# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
# Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>

export SRC_ROOT   = $(shell pwd)
export BUILD_ROOT = $(SRC_ROOT)/build
export CONFIG_MK  = $(BUILD_ROOT)/config.mk
export OBJ_ROOT   = $(BUILD_ROOT)/objs
export BIN_ROOT   = $(BUILD_ROOT)/bin
export LIBTPA_A   = $(BUILD_ROOT)/libtpa.a
export LIBTPA_SO  = $(BUILD_ROOT)/libtpa.so
export INSTALL_ROOT = /usr/share/tpa

export CC ?= gcc

ARCH ?= $(shell uname -m)
OS    = $(shell uname -o)

ifneq ($(MAKECMDGOALS),gtags)
ifneq ($(OS),GNU/Linux)
$(error libtpa builds only in GNU/Linux OS)
endif

ifeq ($(wildcard $(CONFIG_MK)),)
$(error missing config; please run ./configure first)
endif
include $(CONFIG_MK)
endif

export RTE_SDK    = $(BUILD_ROOT)/dpdk/$(DPDK_VERSION)

ifneq ($(V),)
export Q=
else
export Q=@
endif

ifeq ($(ARCH),x86_64)
export RTE_TARGET = x86_64-native-linuxapp-gcc
else
export RTE_TARGET = arm64-bluefield-linux-gcc
endif

EXTRA_CFLAGS := -fPIC
ifeq ($(BUILD_MODE),release)
EXTRA_CFLAGS += -g -fno-omit-frame-pointer
else
EXTRA_CFLAGS += -g3 -O0
endif

CFLAGS := -O2 $(EXTRA_CFLAGS)
CFLAGS += -Wall -Werror -Wno-packed-not-aligned -Wno-format-truncation
CFLAGS += -Wno-address-of-packed-member

LDFLAGS := $(EXTRA_LDFLAGS)
LDFLAGS += -lpthread -lnuma

ifeq ($(BUILD_MODE),asan)
CFLAGS  += -fsanitize=address
LDFLAGS += -fsanitize=address
endif

export EXTRA_CFLAGS
export EXTRA_LDFLAGS
export CFLAGS
export LDFLAGS

ifneq ($(filter v20.11% v22.11%, $(DPDK_VERSION)),)
ifeq ($(ARCH), x86_64)
export DPDK_LD_PATH = $(RTE_SDK)/$(RTE_TARGET)/lib/x86_64-linux-gnu
else
export DPDK_LD_PATH = $(RTE_SDK)/$(RTE_TARGET)/lib
endif
else
export DPDK_LD_PATH = $(RTE_SDK)/$(RTE_TARGET)/lib
endif
