#!/usr/bin/ruby
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
# Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>

require './testcase.rb'

UTcaseMatrix.new(ARGV[0]).testcases.each { |tcase|
	puts tcase.cmd
}
