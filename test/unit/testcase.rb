#!/usr/bin/ruby
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
# Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>

require 'yaml'

class UTcase
	def initialize(cmd)
		@cmd = cmd
	end

	attr_reader :cmd

	def exec(log_file=nil, cpu=1)
		if log_file
			system "echo running #{@cmd} ... >> #{log_file}"
			system "taskset -c #{cpu} #{UNIT_BIN_DIR}/test/#{@cmd} >>#{log_file} 2>&1"
		else
			system "taskset -c #{cpu} #{UNIT_BIN_DIR}/test/#{@cmd}"
		end
	end

	def bin
		@cmd.split[0]
	end
end

class UTcaseMatrix
	def initialize(tcase)
		@tcase = tcase

		@testcases = []

		iterate_test_matrix
	end

	attr_reader :testcases

private
	def get_options(matrix)
		return matrix[@tcase] if matrix[@tcase]

		matrix.each { |k, v|
			if k.include? ".*" and @tcase =~ Regexp.new(k)
				return v
			end
		}

		return {}
	end

	def get_options_list
		options_list = []

		matrix = YAML.load_file "test-matrix.yaml"
		get_options(matrix).each { |param, options|
			options_list.push options
		}

		options_list
	end

	def iterate_options(list, curr_depth, max_depth)
		if curr_depth == max_depth
			@testcases.push UTcase.new(@tcase + ' ' + @curr_opts.join(' '))
			return
		end

		list[curr_depth].each { |arg|
			@curr_opts[curr_depth] = arg

			iterate_options list, curr_depth + 1, max_depth
		}
	end

	def iterate_test_matrix
		@curr_opts = []

		options_list = get_options_list
		iterate_options options_list, 0, options_list.size
	end
end
