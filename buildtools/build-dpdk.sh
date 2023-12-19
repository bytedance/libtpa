#!/bin/bash
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
# Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>

[ -z "$DPDK_VERSION" -o -z "$RTE_TARGET" -o -z "$RTE_SDK" ] && {
	echo "error: missing env var of DPDK_VERSION, RTE_SDK, RTE_TARGET"
	exit 1
}

DPDK_GIT_REPO=${DPDK_GIT_REPO:-http://dpdk.org/git/dpdk-stable}
BUILD_MODE=${BUILD_MODE:-debug}
BUILD_MARK_FILE="$RTE_SDK/.built"
BUILDTOOLS_DIR="$(pwd)/buildtools"
DPDK_SRC="$(pwd)/third/dpdk"

get_dpdk()
{
	[ -d "$RTE_SDK" ] && return

	[ -d "$DPDK_SRC/.git" ] || {
		echo ":: fetching dpdk repo $DPDK_GIT_REPO"
		git clone $DPDK_GIT_REPO $DPDK_SRC || exit
	}

	git clone file://$DPDK_SRC --branch $DPDK_VERSION $RTE_SDK || {
		echo
		echo ":: error: failed to clone dpdk repo"
		echo ":: hint: you should follow the README.md guide"
		echo
		exit 1
	}
}

set_config()
{
	cfg=$1
	val=$2

	if grep "^$cfg=" -q $RTE_TARGET/.config; then
		sed "s/^$cfg=.*/$cfg=$val/" -i $RTE_TARGET/.config
	else
		echo "$cfg=y" >> $RTE_TARGET/.config
	fi
}

config()
{
	make config T=$RTE_TARGET O=$RTE_TARGET

	set_config CONFIG_RTE_MAX_MEMSEG_LISTS 512
	set_config CONFIG_RTE_LIBRTE_KNI  n
	set_config CONFIG_RTE_KNI_KMOD    n
	set_config CONFIG_RTE_EAL_IGB_UIO n

	# for building with make, we don't disable other drivers
	set_config CONFIG_RTE_LIBRTE_MLX5_PMD y

	if [ "$BUILD_MODE" = "debug" ]; then
		set_config CONFIG_RTE_LIBRTE_MEMPOOL_DEBUG y
	fi
}

build_with_make()
{
	config

	make install T=$RTE_TARGET -j 8 	\
		"EXTRA_CFLAGS=$EXTRA_CFLAGS"	\
		"EXTRA_LDFLAGS=$EXTRA_LDFLAGS"
}

get_disable_driver_list()
{
	[ -z "$MLNX_ONLY" ] && return

	enable_list="net/mlx5
		     common/mlx5
		     bus/pci
		     bus/vdev
		     mempool/ring"

	[[ "$DPDK_VERSION" =~ "v22.11" ]] && enable_list+=" bus/auxiliary"

	disable_list=""
	for i in drivers/*/*; do
		[ -d "$i" ] || continue

		drv=$(echo $i | sed 's/drivers\///')
		echo "$enable_list" | grep -qw $drv && continue

		disable_list+="$drv,"
	done

	echo $disable_list
}

build_with_meson()
{
	# XXX: Nah..., DPDK with meson doesn't even provide an interface to us ...
	sed 's/RTE_MAX_MEMSEG_LISTS.*/RTE_MAX_MEMSEG_LISTS 512/' -i config/rte_config.h
	if [ "$BUILD_MODE" = "debug" ]; then
		echo "#define RTE_LIBRTE_MEMPOOL_DEBUG 1" >> config/rte_config.h
	fi

	meson build -Dc_args="$EXTRA_CFLAGS" -Dc_link_args="$EXTRA_LDFLAGS" \
		    -Dprefix=`pwd`/$RTE_TARGET  -Dexamples="" -Dtests=false \
		    -Ddisable_drivers=$(get_disable_driver_list)

	[ "$(uname -m)" = "aarch64" ] && {
		sed -e '/RTE_MAX_LCORE/c\#define RTE_MAX_LCORE 256'         \
		    -e '/RTE_MAX_NUMA_NODES/c\#define RTE_MAX_NUMA_NODES 4' \
		    -i build/rte_build_config.h
		opts="-j 2"
	}
	ninja -C build $opts
	ninja -C build install
}

skip_dpdk_build()
{
	build_mark="mode=$BUILD_MODE-static=$static_link-cflags='$EXTRA_CFLAGS'"

	if [ ! -f "$BUILD_MARK_FILE" ]; then
		false
		return
	fi

	if [ "$(cat $BUILD_MARK_FILE)" != "$build_mark" ]; then
		false
		return
	fi

	true
}

apply_patches()
{
	git config -l | grep -q user || {
		echo ":: config fake git user and email ..."
		git config user.email "build@local.com"
		git config user.name  "Build Machine"
	}

	if [ "$DPDK_VERSION" = "v19.11" ]; then
		git am $BUILDTOOLS_DIR/patches/0001-mlx5-fix-memory-leak.patch
	elif [[ "$DPDK_VERSION" =~ "v20.11.3" ]]; then
		git am $BUILDTOOLS_DIR/patches/0001-net-mlx5-add-the-control-for-FDB-default-rule.patch
		git am $BUILDTOOLS_DIR/patches/0001-net-mlx5-linux-fix-missed-Rx-packet-stats.patch
	fi
}

disable_avx512()
{
	# FIXME: a hack to disable avx512 build
	if [ -f "buildtools/binutils-avx512-check.sh" ]; then
		echo "exit 1" >> buildtools/binutils-avx512-check.sh
	fi
}

build()
{
	mkdir -p $(dirname $RTE_SDK)

	get_dpdk
	skip_dpdk_build && echo ":: dpdk build is skipped" && return

	cd $RTE_SDK

	# do hard cleanup
	git reset --hard $DPDK_VERSION || {
		echo ":: $DPDK_VERSION: no such dpdk version"
		exit 1
	}
	rm -f $BUILD_MARK_FILE
	rm -rf $RTE_TARGET build

	apply_patches
	disable_avx512

	if [ -f "GNUmakefile" ]; then
		echo ":: building dpdk $DPDK_VERSION with make ..."
		time build_with_make > build.log
	else
		echo ":: building dpdk $DPDK_VERSION with meson ..."
		time build_with_meson > build.log
	fi

	if [ $? -ne 0 ]; then
		cat build.log
		exit 1
	fi

	echo $build_mark > $BUILD_MARK_FILE
}

build
