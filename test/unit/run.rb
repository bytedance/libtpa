#!/usr/bin/ruby
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
# Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>

require 'optparse'
require 'fileutils'
require 'colorize'
require 'etc'
require 'json'

TPA_ROOT = Dir.pwd + '/../..'
LOG_ROOT    = Dir.pwd + '/logs'
UNIT_BIN_DIR = "/tmp/tpa/bin"

require './testcase.rb'

$jobs  = 1
$times = 1
$utcase_queue = Queue.new
$nr_loop = 0
$threads = []
$to_quit = false
$force_to_quit = false
$runners = []
$cpu_list = [ 1 ]
$pretty_mode = false
$stop_on_failure = false
$failed_rt = "/tmp/tpa/ut-failed-rt"
$version = nil
$startup_time = Time.now
$nr_total_testcase = nil

def log(ut_id, msg)
	log_file = "#{LOG_ROOT}/#{ut_id}"
	system "echo #{Time.now} '#{msg}' >> #{log_file}"
end

def log_info(ut_id, msg)
	log ut_id, msg.green
end

def log_debug(ut_id, msg)
	log ut_id, msg.gray
end

def log_error(ut_id, msg)
	log ut_id, msg.red
end

def parse_cpu_list(cpu_list)
	$cpu_list = []

	cpu_list.split(',').each { |range|
		cpus = range.split '-'
		return false if cpus.size > 2

		if cpus.size == 1
			$cpu_list.push cpus[0]
			next
		end

		cpus[0].to_i.upto(cpus[1].to_i).each { |cpu|
			return false if cpu >= Etc.nprocessors
			$cpu_list.push cpu.to_s
		}
	}

	true
end

def parse_args
	opt_parser = OptionParser.new do |opts|
		opts.banner = "Usage: #{$0} [options] [testcases]"

		opts.separator ''
		opts.separator 'options:'

		opts.on('-j jobs', '--jobs jobs', 'speicify the number of testcases to run concurrently') { |jobs|
			$jobs = jobs.to_i
		}

		opts.on('-t times', '--times times', 'speicify the number of times to run for given testcases') { |times|
			$times = times.to_i
		}

		opts.on('-c cpu', '--cpu cpu', 'speicify the cpu list to run the testcases') { |cpu_list|
			if not parse_cpu_list cpu_list
				STDERR.puts "error: invalid cpu list: #{cpu_list}"
				puts opts
				exit 1
			end
		}

		opts.on('-s', '--stop-on-failure', 'stop testing once one failure is met') {
			$stop_on_failure = true
		}

		opts.on('-p', '--pretty', 'pretty mode') {
			$pretty_mode = true
		}

		opts.on_tail('-h', '--help', 'Show this message') {
			puts opts
			exit
		}
	end

	opt_parser.parse!(ARGV)
	if ARGV.empty?
		$testcases = File.read("#{TPA_ROOT}/build/bin/test/unit/.bins.list").chomp.split
	else
		$testcases = ARGV
	end

	FileUtils.rm_f $failed_rt
end

def setup
	parse_args

	FileUtils.mkdir_p "#{UNIT_BIN_DIR}/test"
	system "cp #{TPA_ROOT}/build/bin/test/unit/* #{UNIT_BIN_DIR}/test/"
	system "cp #{TPA_ROOT}/build/bin/tools/* #{UNIT_BIN_DIR}/"
	system "cp #{TPA_ROOT}/build/bin/tpad/tpad #{UNIT_BIN_DIR}/"

	ENV['TPA_PATH'] = UNIT_BIN_DIR

	$version = %x[ strings #{UNIT_BIN_DIR}/test/tcp_connect | grep '^v[0-9]*\\.[0-9]*' | head -n 1 ].chomp

	FileUtils.mkdir_p LOG_ROOT
end

def feed_testcases
	tests = []

	$testcases.each { |testcase|
		UTcaseMatrix.new(testcase).testcases.each { |tcase|
			tests.push tcase
		}
	}

	tests.shuffle.each { |tcase|
		$utcase_queue.push tcase
	}

	$nr_total_testcase = tests.size if not $nr_total_testcase

	$nr_loop += 1
end

def feeder_loop
	loop {
		break if $force_to_quit

		if $utcase_queue.empty?
			feed_testcases

			if $times > 0
				$times -= 1
				break if $times == 0
			end
		end

		# XXX: if feeder is the bottleneck, sleep less
		if $utcase_queue.size < $jobs and $times == 0
			sleep 0.01
		else
			sleep 1
		end
	}

	$to_quit = true
	puts ":: testcase feeder quits" if ENV['DEBUG']
end

def spawn_feeder
	$threads.push Thread.new {
		feeder_loop
	}
end

def get_failed_rt(tcase, bin)
	_rt = "/tpa/ut-results/#{$version}/#{bin}"
	FileUtils.mkdir_p _rt

	i = 0
	rt = _rt
	loop {
		rt = _rt + '/' + i.to_s
		if not File.exist? rt
			begin
				FileUtils.mkdir rt
			rescue Errno::EEXIST
				i += 1
				next
			rescue => error
				puts error.message
				raise
			end

			break
		end

		i += 1
	}

	rt
end

def archive_failed_testcase(tcase, ut_root, log)
	bin = tcase.cmd.split[0]
	rt = get_failed_rt tcase, bin

	system "cp #{ut_root}/core #{rt}" if File.exist? "#{ut_root}/core"
	system "cp #{ut_root}/socks.bad.json #{rt}" if File.exist? "#{ut_root}/socks.bad.json"
	system "cp #{UNIT_BIN_DIR}/test/#{bin} #{rt}"
	system "cp -a #{log} #{rt}/log"
	system "cp #{ut_root}/trace/* #{rt}"

	Dir["#{rt}/**/*"].each { |file|
		system "gzip #{file}" if File.file? file
	}

	system "echo #{rt} >> #{$failed_rt}"
end

def runner_loop(id, cpu)
	ut_id   = "ut-#{id}"
	ut_root = "/tmp/tpa/#{ut_id}"

	ut_log     = ut_root + '/log'
	tmp_log    = ut_root + '/.log.tmp'
	failed_log = ut_root + '/log.failed'
	FileUtils.rm_f ut_log
	FileUtils.rm_f failed_log

	loop {
		break if $force_to_quit
		tcase = $utcase_queue.pop(non_block = true) rescue tcase = nil
		if tcase
			pid = fork {
				ENV['UT_ROOT_PREFIX'] = File.dirname ut_root
				ENV['UT_ID']   = ut_id

				puts ":: running #{tcase.cmd} ..." if not $pretty_mode

				FileUtils.rm_f tmp_log
				FileUtils.rm_f  ut_root + '/flock'
				FileUtils.rm_f  ut_root + '/socks.bad.json'
				FileUtils.rm_rf ut_root + '/trace'
				FileUtils.mkdir_p ut_root

				system "cp cfg-syntax #{ut_root}"
				system "cp cfg-option #{ut_root}"
				system "cp bonding.txt #{ut_root}"
				Dir.chdir ut_root

				log_info ut_id, "running #{tcase.cmd} ..."
				exit 1 if not tcase.exec tmp_log, cpu
			}

			Process.waitpid pid
			failed = $?.exitstatus != 0
			log_error ut_id, "failure detected" if failed

			# hmm, we remove socks mem file at tpad, breaking
			# follow sk json output validation.
			#if File.exist? "#{ut_root}/socks"
			#	system "#{UNIT_BIN_DIR}/sock-list -j -f #{ut_root}/socks > #{ut_root}/socks.json"
			#	begin
			#		JSON.parse(File.read "#{ut_root}/socks.json")
			#	rescue JSON::ParserError
			#		log_error ut_id, "bad json detected"
			#		system "mv #{ut_root}/socks.json #{ut_root}/socks.bad.json"
			#		failed = true
			#	end
			#end

			$runners[id]["nr_testcase"] += 1
			if failed and not $force_to_quit
				$runners[id]["nr_failure"] += 1
				$runners[id]["failed_log"] = failed_log
				$runners[id]["failed_testcases"][tcase.cmd] ||= 0
				$runners[id]["failed_testcases"][tcase.cmd] += 1

				archive_failed_testcase tcase, ut_root, tmp_log
				system "cat #{tmp_log} >> #{failed_log}"

				$force_to_quit = true if $stop_on_failure
			end

			next
		end

		break if $to_quit
		sleep 0.01
	}

	puts ":: runner #{id} quits" if ENV['DEBUG']
end

def spawn_runners
	# make sure we have testcases feed
	loop {
		break if not $utcase_queue.empty?
		sleep 1
	}

	0.upto($jobs - 1) { |i|
		$runners[i] = {
			"nr_testcase"	=> 0,
			"nr_failure"	=> 0,
			"failed_testcases" => {},
		}

		$threads.push Thread.new {
			runner_loop i, $cpu_list[i % $cpu_list.size]
		}
	}
end

def normalize_time(sec)
	if sec > 24 * 3600
		div = 24 * 3600
		unit = "d"
	elsif sec > 3600
		div = 3600
		unit = "h"
	elsif sec > 60
		div = 60
		unit = "m"
	else
		div = 1
		unit = 's'
	end

	(sec.to_f / div).round(2).to_s + unit
end

def get_avg_time(duration, nr_finished_testcase)
	return "-" if not $nr_total_testcase

	normalize_time(duration * $nr_total_testcase / nr_finished_testcase)
end

def pretty_show
	loop {
		break if $force_to_quit or $to_quit

		nr_testcase = 0
		nr_failure  = 0
		duration = Time.now - $startup_time

		$runners.each { |runner|
			nr_testcase += runner["nr_testcase"]
			nr_failure  += runner["nr_failure"]
		}

		printf "\r:: #{$version} total/failure/loop: %s / %s / %s %s; duration total/avg: %s/%s %s",
			nr_testcase.to_s.cyan,
			nr_failure > 0 ? nr_failure.to_s.bold.red : nr_failure.to_s.bold.green,
			$nr_loop.to_s,
			File.exist?($failed_rt) ? $failed_rt.light_black : "",
			normalize_time(duration), get_avg_time(duration, nr_testcase),
			"    \b\b\b\b" # to reset stale chars

		sleep 0.2
	}
	puts
end

def show_summary
	pretty_show if $pretty_mode

	$threads.each { |thread|
		thread.join
	}

	nr_testcase = 0
	nr_failure  = 0
	failed_testcases = {}
	failed_file = "/tmp/tpa/failed.logs"

	FileUtils.rm_f failed_file
	$runners.each { |runner|
		nr_testcase += runner["nr_testcase"]
		nr_failure  += runner["nr_failure"]
		system "cat #{runner['failed_log']} >> #{failed_file}" if runner["failed_log"]

		runner["failed_testcases"].each { |tcase, failed_times|
			failed_testcases[tcase] ||= 0
			failed_testcases[tcase] += failed_times
		}
	}

	printf ":: total/failure/loop: %s / %s / %s\n",
		nr_testcase.to_s.cyan,
		nr_failure > 0 ? nr_failure.to_s.bold.red : nr_failure.to_s.bold.green,
		$nr_loop.to_s

	if File.exist? failed_file
		puts "\n   failed testcases:"

		failed_testcases.sort.to_h.each { |tcase, failed_times|
			puts "\t#{failed_times} \t#{tcase}"
		}
		puts "\n\tless #{failed_file}"
	end
end

Signal.trap('INT') {
	$force_to_quit = true
}

setup
spawn_feeder
spawn_runners
show_summary
