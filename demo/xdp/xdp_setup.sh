#!/bin/bash
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023-2024, ByteDance Ltd. and/or its Affiliates
# Author: WenLong Luo <luowenlong.linl@bytedance.com>

ns1="tpans1"
ns2="tpans2"

veth1="tpaveth1"
veth2="tpaveth2"

ip1="192.168.0.22"
ip2="192.168.0.23"
mask="255.255.255.0"
ip_prefix=24

setup_eth()
{
	local ns=$1
	local eth=$2
	local ip=$3

	ip netns add $ns
	ip link set $eth netns $ns
	ip -n $ns link set dev lo up
	ip -n $ns link set dev $eth up
	ip -n $ns addr add dev $eth "${ip}/${ip_prefix}"
}

setup_veth_env()
{
	ip link add dev $veth1 type veth peer name $veth2

	setup_eth $ns1 $veth1 $ip1
	setup_eth $ns2 $veth2 $ip2
}

gen_xdp_cfg()
{
	cat > $1/tpa.cfg << EOF
net {
	name = $2
	ip   = $3
	mask = $mask
}

dpdk {
	extra_args = "--no-pci --vdev net_af_xdp0,iface=$2,start_queue=0,queue_count=1,xdp_prog=/usr/share/tpa/xdp_flow_steering.o"
}

EOF
}

do_setup_env()
{
	local subdir=$1
	local name=$2
	local ip=$3

	mkdir -p $subdir
	gen_xdp_cfg $subdir $name $ip
}

setup_env()
{
	setup_veth_env

	do_setup_env $ns1 $veth1 $ip1
	do_setup_env $ns2 $veth2 $ip2

	cat << EOF
Two network namespaces have been created:
$ns1: $veth1 $ip1
$ns2: $veth2 $ip2

You can enter namespace by:
        ip netns exec \$ns bash

Now, You can enter ./$ns1 or ./$ns2 subdir to execute libtpa apps.
EOF
}

[ "$1" = "cleanup" ] && {
	ip netns delete $ns1
	ip netns delete $ns2
	exit
}

setup_env
