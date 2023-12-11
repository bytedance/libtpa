# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023, ByteDance Ltd. and/or its Affiliates
# Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>

params:
  server_nr_thread: [2]

  client_nr_thread: [4]

  duration: [ 1m ]
  test: [ write ]
  connection_per_thread: [1000]
  size: [4KB, 128KB]
end

#include tperf-common.msh

cfg()
{
	# - a smaller mbuf_mem_size would trigger ooo drop
	local cfg="dpdk { mbuf_mem_size=100MB; }"

	SERVER_TPA_CFG+=$cfg
	CLIENT_TPA_CFG+=$cfg
}

cfg
run
