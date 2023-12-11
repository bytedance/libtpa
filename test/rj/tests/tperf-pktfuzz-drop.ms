# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023, ByteDance Ltd. and/or its Affiliates
# Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>

params:
  server_nr_thread: [2]
  client_nr_thread: [4]
  test: [ write, rw, crr, rr ]
  connection_per_thread: [1, 100, 400]
  size: [4KB, 128KB]
  pktfuzz:
  - drop -r 0.1
  - cut -r 0.1 -h -n 50
end

#include tperf-common.msh

cfg()
{
	# - time_wait is needed for crr testing
	# - a smaller mbuf_mem_size would trigger ooo drop
	local cfg="tcp { time_wait = 100ms; } dpdk { mbuf_mem_size=100MB; }"

	SERVER_TPA_CFG=$cfg
	CLIENT_TPA_CFG=$cfg
}

cfg
run
