# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023, ByteDance Ltd. and/or its Affiliates
# Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>

params:
  server_nr_thread: [1, 4]
  server_flow_mark: [0, 1]
  server_sock_offload: [0, 1]
  server_port_block_offload: [0, 1]

  client_nr_thread: [1, 4]
  client_flow_mark: [0, 1]
  client_sock_offload: [0, 1]
  client_port_block_offload: [0, 1]

  duration: [ 1m ]
  test: [ crr ]
  ip: [ "127.0.0.1", "::1" ]
end

#include tperf-common.msh

offload_cfg()
{
	echo "offload { flow_mark=$1; sock_offload=$2; port_block_offload=$3; }"
}

cfg()
{
	cfg="tcp { time_wait = 100ms; } log { level = 1; }"
	server_cfg="$(offload_cfg $server_flow_mark $server_sock_offload $server_port_block_offload)"
	client_cfg="$(offload_cfg $client_flow_mark $client_sock_offload $client_port_block_offload)"

	SERVER_TPA_CFG="$cfg $server_cfg"
	CLIENT_TPA_CFG="$cfg $client_cfg"
}

verify()
{
	detect_count0_error
	detect_zero_io_conn_error
}

cfg
run
verify
