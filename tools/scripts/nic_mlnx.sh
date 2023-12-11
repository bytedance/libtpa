#!/bin/bash
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2022-2023, ByteDance Ltd. and/or its Affiliates
# Author: Tao Liu <liutao.xyz@bytedance.com>

nic_dev_get_pci()
{
	ethtool -i $1 | grep bus | awk '{print $2}'
}

nic_dev_get_dpdk_args()
{
	args=""

	for eth in $(get_eth_list $TPA_ETH_DEV); do
		args+="$(nic_dev_get_pci $eth) "
	done

	echo $args
}

nic_dev_init()
{
	:
}
