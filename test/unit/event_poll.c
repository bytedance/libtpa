/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>

#include "test_utils.h"

static void test_tcp_event_poll_basic(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;

	printf("%s\n", __func__);

	tsock = ut_tcp_connect();

	ut_event_ctrl(tsock, TPA_EVENT_CTRL_ADD, TPA_EVENT_IN | TPA_EVENT_OUT);
	assert(ut_event_poll(tsock) == TPA_EVENT_OUT);
	assert(ut_event_poll(tsock) == 0);

	ut_event_ctrl(tsock, TPA_EVENT_CTRL_MOD, TPA_EVENT_IN);
	pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt, 1000);
	ut_tcp_input_one(tsock, pkt); {
		assert(ut_event_poll(tsock) == TPA_EVENT_IN);
		assert(ut_event_poll(tsock) == 0);
	}

	ut_write_assert(tsock, 10);
	ut_tcp_output(NULL, 0); {
		assert(ut_event_poll(tsock) == 0);
	}

	ut_close(tsock, CLOSE_TYPE_RESET);
}

static void test_tcp_event_poll_OUT_ET(void)
{
	struct tcp_sock *tsock;

	printf("%s\n", __func__);

	tsock = ut_tcp_connect();

	ut_event_ctrl(tsock, TPA_EVENT_CTRL_ADD, TPA_EVENT_IN | TPA_EVENT_OUT);
	assert(ut_event_poll(tsock) == TPA_EVENT_OUT);
	assert(ut_event_poll(tsock) == 0);

	ut_write_assert(tsock, 1); {
		ut_tcp_output(NULL, 0);
		assert(ut_event_poll(tsock) == 0);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_event_poll_after_close(void)
{
	struct tcp_sock *tsock;
	struct tpa_event event;

	printf("%s\n", __func__);

	tsock = ut_tcp_connect();

	ut_event_ctrl(tsock, TPA_EVENT_CTRL_ADD, TPA_EVENT_IN | TPA_EVENT_OUT);
	ut_close(tsock, CLOSE_TYPE_4WAY);

	assert(tpa_event_poll(worker, &event, 1) == 0);
}

static void test_tcp_event_poll_del_after_add(void)
{
	struct tcp_sock *tsock;

	printf("%s\n", __func__);

	tsock = ut_tcp_connect();

	ut_event_ctrl(tsock, TPA_EVENT_CTRL_ADD, TPA_EVENT_IN | TPA_EVENT_OUT);
	ut_event_ctrl(tsock, TPA_EVENT_CTRL_DEL, 0);
	assert(ut_event_poll(tsock) == 0);

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_event_poll_zero_events(void)
{
	struct tcp_sock *tsock;

	printf("%s\n", __func__);

	tsock = ut_tcp_connect();

	ut_event_ctrl(tsock, TPA_EVENT_CTRL_ADD, TPA_EVENT_IN | TPA_EVENT_OUT);
	ut_event_ctrl(tsock, TPA_EVENT_CTRL_MOD, 0);
	assert(ut_event_poll(tsock) == 0);

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

/*
 * The OUT event should be re-fired if the first write gets EAGAIN (say,
 * due to out of mbufs.  Otherwise, it will never be waken up.
 */
static void test_tcp_event_poll_first_write_egain(void)
{
	struct tcp_sock *tsock;
	struct tpa_iovec iov;

	printf("%s\n", __func__);

	tsock = ut_tcp_connect();
	ut_event_ctrl(tsock, TPA_EVENT_CTRL_ADD, TPA_EVENT_IN | TPA_EVENT_OUT);

	/* exhausts mbufs */
	while (packet_alloc(&worker->zwrite_pkt_pool))
		;
	while (packet_alloc(generic_pkt_pool))
		;
	while (tx_desc_alloc(worker->tx_desc_pool))
		;


	setup_tpa_iovec(&iov, 4096, 0);
	assert(tpa_zwritev(tsock->sid, &iov, 1) == -1); {
		assert(errno == EAGAIN);
		assert(ut_event_poll(tsock) == TPA_EVENT_OUT);

		iov.iov_write_done(iov.iov_base, iov.iov_param);
	}

	setup_tpa_iovec(&iov, 4096, 1);
	assert(tpa_zwritev(tsock->sid, &iov, 1) == -1); {
		assert(errno == EAGAIN);
		assert(ut_event_poll(tsock) == TPA_EVENT_OUT);

		iov.iov_write_done(iov.iov_base, iov.iov_param);
	}

	/* no ut_close on purpose, as it would fail due to out of mbuf */
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_tcp_event_poll_basic();
	test_tcp_event_poll_OUT_ET();
	test_tcp_event_poll_after_close();
	test_tcp_event_poll_del_after_add();
	test_tcp_event_poll_zero_events();

	/* XXX: this should be run last, as it exhausts mbufs */
	test_tcp_event_poll_first_write_egain();

	return 0;
}
