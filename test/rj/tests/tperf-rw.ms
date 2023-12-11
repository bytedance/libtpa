# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023, ByteDance Ltd. and/or its Affiliates
# Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>

params:
  server_nr_thread: [1, 4]
  client_nr_thread: [1, 4]
  connection_per_thread: [ 1, 100, 400 ]
  ip: [ "127.0.0.1", "::1" ]
  test: [ read, write, rw, rr ]
  tso: [ 0, 1 ]
  zwrite: [ 0, 1 ]
  size: [ 1, 1500, 4KB, 128KB ]
end

#include tperf-common.msh

run
