# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023, ByteDance Ltd. and/or its Affiliates
# Author: Tao Liu <liutao.xyz@bytedance.com>

params:
  server_nr_thread: [ 1 ]
  client_nr_thread: [ 1 ]
  duration: [ 5s ]

  ip: [ "127.0.0.1", "::1" ]

  test: [ rr ]
  size: [ 16KB ]

  mtu: [ 9000, 4000, 1500 ]
  client_mss: [ 0, 512, 1750, 4096, 8192 ]
  server_mss: [ 0, 512, 1750, 4096, 8192 ]
end

#include tperf-common.msh

mtu_cfg()
{
	eth=$(tpa run | grep net | sed 's/.*name=//' | sed 's/;.*//')
	ip link set $eth mtu $mtu

	pci=$(ethtool -i $eth | grep bus | awk '{print $2}')
	lspci -D | grep $pci | grep -q 'Virtual Function' && {
		# TODO: we need double confirm it with Mellanox
		if [ $client_mss -eq 8192 ] && [ $server_mss -eq 8192 ]; then
			echo "warn: mangle mss from 8k to 4k to bypass mlnx VF failure"
			client_mss=4096
			server_mss=4096
		fi
	}
}

cfg()
{
	mtu_cfg

	SERVER_TPA_CFG="tcp { usr_snd_mss=$client_mss; }"
	CLIENT_TPA_CFG="tcp { usr_snd_mss=$server_mss; }"
}

verify()
{
	detect_count0_error
}

cfg
run
verify
