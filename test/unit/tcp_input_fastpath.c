/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <getopt.h>
#include <sys/uio.h>

#include "test_utils.h"

static void test_tcp_input_fastpath_basic(void)
{
	struct tcp_sock *tsock;
	struct packet *pkts[3];
	struct tpa_iovec iov[3];
	uint32_t off = 0;
	int ret;

	printf("testing tcp rcv fastpath basic ...\n");

	tsock = ut_tcp_connect();

	pkts[0] = ut_inject_data_packet(tsock, tsock->rcv_nxt + off, 1000); off += 1000;
	pkts[1] = ut_inject_data_packet(tsock, tsock->rcv_nxt + off, 1000); off += 1000;
	pkts[2] = ut_inject_data_packet(tsock, tsock->rcv_nxt + off, 1000); off += 1000;
	ut_tcp_input(tsock, pkts, 3); {
		assert(tsock->stats_base[BYTE_RECV_FASTPATH] == off);
		ret = tpa_zreadv(tsock->sid, iov, 3);
		assert(ret == off);
		iov[0].iov_read_done(iov[0].iov_base, iov[0].iov_param);
		iov[1].iov_read_done(iov[1].iov_base, iov[1].iov_param);
		iov[2].iov_read_done(iov[2].iov_base, iov[2].iov_param);
	}

	off = 0;
	pkts[0] = ut_inject_data_packet(tsock, tsock->rcv_nxt + off, 1000); off += 1000;
	pkts[1] = ut_inject_data_packet(tsock, tsock->rcv_nxt + off, 1000); off += 1000;
	pkts[2] = ut_inject_data_packet(tsock, tsock->rcv_nxt + off, 1000); off += 1000;
	ut_packet_tcp_hdr(pkts[0])->tcp_flags |= TCP_FLAG_PSH;
	ut_tcp_input(tsock, pkts, 3); {
		assert(tsock->stats_base[BYTE_RECV_FASTPATH] == 6000);
		ret = tpa_zreadv(tsock->sid, iov, 3);
		assert(ret == off);
		iov[0].iov_read_done(iov[0].iov_base, iov[0].iov_param);
		iov[1].iov_read_done(iov[1].iov_base, iov[1].iov_param);
		iov[2].iov_read_done(iov[2].iov_base, iov[2].iov_param);
	}

	ut_dump_tsock_stats(tsock);

	ut_tcp_output(NULL, -1);
	ut_assert_mbuf_count();
}

static void test_tcp_input_fastpath_no_ack(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;

	printf("testing tcp rcv fastpath no ACK ...\n");

	tsock = ut_tcp_connect();

	pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt, 1000);
	ut_packet_tcp_hdr(pkt)->tcp_flags = TCP_FLAG_PSH;
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->stats_base[BYTE_RECV_FASTPATH] == 0);
		assert(tsock->stats_base[BYTE_RECV] == 0);
	}

	pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt, 1000);
	ut_packet_tcp_hdr(pkt)->tcp_flags = TCP_FLAG_FIN | TCP_FLAG_ACK;
	ut_tcp_input_one_and_drain(tsock, pkt); {
		assert(tsock->stats_base[BYTE_RECV_FASTPATH] == 0);
		assert(tsock->stats_base[BYTE_RECV] == 1000);
	}

	ut_dump_tsock_stats(tsock);

	ut_tcp_output(NULL, -1);
	ut_assert_mbuf_count();
}

static void test_tcp_input_fastpath_wrong_ack(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;

	printf("testing tcp rcv fastpath wrong ACK ...\n");

	tsock = ut_tcp_connect();

	pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt, 1000);
	ut_packet_tcp_hdr(pkt)->recv_ack = htonl(tsock->snd_nxt  + 1);
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->stats_base[BYTE_RECV_FASTPATH] == 0);
		assert(tsock->stats_base[BYTE_RECV] == 0);
	}

	pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt, 1000);
	ut_packet_tcp_hdr(pkt)->recv_ack = htonl(tsock->snd_una  - 1);
	ut_tcp_input_one_and_drain(tsock, pkt); {
		assert(tsock->stats_base[BYTE_RECV_FASTPATH] == 0);
		assert(tsock->stats_base[BYTE_RECV] == 1000);
	}

	ut_dump_tsock_stats(tsock);

	ut_tcp_output(NULL, -1);
	ut_assert_mbuf_count();
}


int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_tcp_input_fastpath_basic();
	test_tcp_input_fastpath_no_ack();
	test_tcp_input_fastpath_wrong_ack();

	return 0;
}
