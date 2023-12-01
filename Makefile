# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
# Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>

MAKEFLAGS += --no-print-directory

export TPA_VERSION = 1.0-rc0

include buildtools/vars.mk

SUBDIRS = lib src tools tpad app
ifneq ($(DISABLE_TEST),yes)
SUBDIRS += test
endif

ifeq ($(WITH_XDP), yes)
SUBDIRS += bpf
endif

.PHONY: all install clean distclean $(SUBDIRS) dpdk gtags scan-build so summary

all: summary $(SUBDIRS)

$(SUBDIRS): $(CONFIG_MK)
	$(MAKE) -C $@

test: lib src
test lib src: dpdk
tpad tools app: $(LIBTPA_A)

dpdk:
	$(Q)bash ./buildtools/build-dpdk.sh

$(LIBTPA_SO): $(TPA_LIBS)
	$(Q)echo "  LD $(notdir $@)"
	$(Q)$(CC) -shared -o $@					\
	     -Wl,--whole-archive $^ $(DPDK_LD_PATH)/librte_*.a -Wl,--no-whole-archive \
	     $(LDFLAGS)
	$(Q)bash ./buildtools/gen-pkg-config-file

so: $(LIBTPA_SO)

$(TPA_LIBS): src lib

$(LIBTPA_A): $(TPA_LIBS)
	$(Q)echo "  AR libtpa.a"
	$(Q)echo create $(LIBTPA_A)		   >  /tmp/tpa.mri
	$(Q)for i in $^ $(DPDK_LD_PATH)/librte_*.a; do \
		echo addlib $$i			   >> /tmp/tpa.mri; \
	done
	$(Q)echo save				   >> /tmp/tpa.mri
	$(Q)ar -M < /tmp/tpa.mri
	$(Q)bash ./buildtools/gen-pkg-config-file

summary: $(SUBDIRS) $(LIBTPA_A)
	$(Q)echo ":: built $(shell buildtools/get-ver.sh): mode=$(BUILD_MODE) dpdk=$(DPDK_VERSION)"

install: $(SUBDIRS) $(LIBTPA_A)
	$(Q)echo "  INSTALL -> $(INSTALL_ROOT)"
	$(Q)mkdir -p $(INSTALL_ROOT)
	$(Q)echo $(shell buildtools/get-ver.sh) > $(INSTALL_ROOT)/version
	$(Q)install $(BUILD_ROOT)/libtpa*         $(INSTALL_ROOT)
	$(Q)install $(BIN_ROOT)/app/*             $(INSTALL_ROOT)
	$(Q)install $(BIN_ROOT)/tpad/*            $(INSTALL_ROOT)
	$(Q)install $(BIN_ROOT)/tools/*           $(INSTALL_ROOT)
ifeq ($(WITH_XDP), yes)
	$(Q)install $(OBJ_ROOT)/bpf/*.o		  $(INSTALL_ROOT)
endif
	$(Q)install $(SRC_ROOT)/include/api/*     $(INSTALL_ROOT)
	$(Q)install $(BIN_ROOT)/tools/tpa         /usr/bin
	$(Q)install $(BIN_ROOT)/app/*             /usr/bin
	$(Q)install $(BUILD_ROOT)/libtpa.pc       /usr/share/pkgconfig

scan-build: clean
	scan-build make

gtags:
	git ls-files | gtags -f -

html:
	sphinx-build doc build/html

html_pub:
	sphinx-build doc /var/www/html/libtpa-doc

clean:
	rm -rf $(BIN_ROOT) $(OBJ_ROOT) $(LIBTPA_A) $(LIBTPA_SO)

dpdkclean:
	rm -rf $(BUILD_ROOT)/dpdk

distclean:
	rm -rf $(BUILD_ROOT)
