/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <getopt.h>
#include <sys/uio.h>

#include "test_utils.h"

#define MAX_DATA_SIZE	1448

static void test_tcp_input_bench_basic(void)
{
	struct tcp_sock *tsock;
	struct packet *pkts[BATCH_SIZE];
	struct tpa_iovec iov[BATCH_SIZE];
	int data_size = MESSAGE_SIZE;
	uint32_t off = 0;
	int ret;
	int i;

	printf("testing tcp rcv bench [basic] ...\n");

	if (data_size > MAX_DATA_SIZE)
		data_size = MAX_DATA_SIZE;

	tsock = ut_tcp_connect();

	WHILE_NOT_TIME_UP() {
		for (i = 0; i < BATCH_SIZE; i++) {
			pkts[i] = ut_inject_data_packet(tsock, tsock->rcv_nxt + off, data_size);
			off += data_size;
		}

		ut_tcp_input(tsock, pkts, BATCH_SIZE); {
			ret = tpa_zreadv(tsock->sid, iov, BATCH_SIZE);
			assert(ret == off);
			for (i = 0; i < BATCH_SIZE; i++) {
				assert(iov[i].iov_len == data_size);
				iov[i].iov_read_done(iov[i].iov_base, iov[i].iov_param);
			}

			ut_tcp_output_skip_csum_verify(NULL, -1);
		}
		off = 0;

		ut_measure_rate(tsock, 1000 * 1000);
	}

	ut_dump_tsock_stats(tsock);

	ut_tcp_output(NULL, -1);
	ut_assert_mbuf_count();
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_tcp_input_bench_basic();

	return 0;
}
