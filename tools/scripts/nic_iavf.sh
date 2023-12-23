#!/bin/bash
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2022-2023, ByteDance Ltd. and/or its Affiliates
# Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
# Author: Tao Liu <liutao.xyz@bytedance.com>

VF_MAPPING=""

vf_is_free()
{
	local vf=$1

	local group=$(basename $(readlink $vf/iommu_group) 2>/dev/null)
	[ -z "$group" ] && {
		echo "warn: no iommu group found for $vf" 1>&2
		return 1
	}

	# the cmd "<" just tries to open the file. If it succeeds, it means
	# the VF is free. Otherwise, it's taken.
	< /dev/vfio/noiommu-$group
}

get_unused_vf()
{
	local eth=$1

	for vf in /sys/class/net/$eth/device/virtfn*; do
		vf_is_free $vf 2>/dev/null && readlink $vf | awk -F'/' '{print $2}' && return
	done

	echo "error: running out of VF" 1>&2
}

nic_dev_init()
{
	for eth in $(get_eth_list $TPA_ETH_DEV); do
		vf=$(get_unused_vf $eth)
		[ -z "$vf" ] && return 1

		VF_MAPPING+="$eth $vf\n"
	done
}

nic_dev_get_pci()
{
	local eth=$1

	echo -e "$VF_MAPPING" | grep $eth | awk '{print $2}'
}

nic_dev_get_dpdk_args()
{
	local args="extra_args = --iova-mode pa; "

	args+="pci = "
	while read eth pci; do
		args+="$pci "
	done <<< "$(echo -e $VF_MAPPING)"

	echo "$args"
}
