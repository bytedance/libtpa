/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <getopt.h>
#include <sys/uio.h>

#include "test_utils.h"

static void test_tcp_input_rst_at_CLOSED(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;

	printf("testing tcp_input_rst at state [CLOSED] ...\n");

	tsock = ut_tcp_connect();

	tsock->state = TCP_STATE_CLOSED;

	pkt = ut_inject_rst_packet(tsock);
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->stats_base[PKT_RECV_AFTER_CLOSE] == 1);
	}

	ut_close(tsock, CLOSE_TYPE_CLOSE_DIRECTLY);
}

static void test_tcp_input_rst_at_SYN_SENT(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;

	printf("testing tcp_input_rst at state [SYN_SENT] ...\n");

	tsock = ut_tcp_connect();
	ut_event_ctrl(tsock, TPA_EVENT_CTRL_ADD, TPA_EVENT_IN | TPA_EVENT_OUT);

	tsock->state = TCP_STATE_SYN_SENT;

	pkt = ut_inject_rst_packet(tsock);
	ut_tcp_input_one(tsock, pkt);
	assert((ut_event_poll(tsock) & TPA_EVENT_ERR) != 0); {
		assert(tsock->err == ECONNREFUSED);

		assert(ut_write(tsock, 100) == -1); {
			assert(errno == ECONNREFUSED); errno = 0;
		}

		assert(ut_readv(tsock, 1) == -1); {
			assert(errno == ECONNREFUSED); errno = 0;
		}
	}

	ut_close(tsock, CLOSE_TYPE_CLOSE_DIRECTLY);
}

static void test_tcp_input_rst_at_ESTABLISHED(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;

	printf("testing tcp_input_rst at state [ESTABLISHED] ...\n");

	tsock = ut_tcp_connect();
	ut_event_ctrl(tsock, TPA_EVENT_CTRL_ADD, TPA_EVENT_IN | TPA_EVENT_OUT);

	pkt = ut_inject_rst_packet(tsock);
	ut_tcp_input_one(tsock, pkt);
	assert((ut_event_poll(tsock) & TPA_EVENT_ERR) != 0); {
		assert(tsock->err == ECONNRESET);

		assert(ut_write(tsock, 100) == -1); {
			assert(errno == ECONNRESET); errno = 0;
		}

		assert(ut_readv(tsock, 1) == -1); {
			assert(errno == ECONNRESET); errno = 0;
		}
	}

	ut_close(tsock, CLOSE_TYPE_CLOSE_DIRECTLY);
}

static void test_tcp_input_rst_with_data(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;

	printf("testing tcp_input_rst [with data] ...\n");

	tsock = ut_tcp_connect();

	pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt, 1000);
	ut_packet_tcp_hdr(pkt)->tcp_flags |= TCP_FLAG_RST;
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->state == TCP_STATE_CLOSED);
	}

	ut_close(tsock, CLOSE_TYPE_CLOSE_DIRECTLY);
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_tcp_input_rst_at_CLOSED();
	test_tcp_input_rst_at_SYN_SENT();
	test_tcp_input_rst_at_ESTABLISHED();
	test_tcp_input_rst_with_data();

	return 0;
}
