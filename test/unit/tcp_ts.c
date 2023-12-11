/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>

#include "test_utils.h"

static void test_tcp_ts_basic(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt, 1000);
	fill_opt_ts((uint8_t *)(ut_packet_tcp_hdr(pkt) + 1), tsock->ts_recent, tsock->snd_ts);
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->stats_base[ERR_TCP_INVALID_TS] == 0);
	}

	pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt, 1000);
	fill_opt_ts((uint8_t *)(ut_packet_tcp_hdr(pkt) + 1), tsock->ts_recent - 1, tsock->snd_ts);
	/* XXX: can't use ut_tcp_input_one here; as it asserts no invalid ts pkt is injected */
	ut_tcp_input_raw(tsock, &pkt, 1); {
		assert(tsock->stats_base[ERR_TCP_INVALID_TS] == 1);
	}

	ut_close(tsock, CLOSE_TYPE_RESET);
}

static void test_tcp_ts_wrap(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	uint32_t ts;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	ts = tsock->ts_recent - 1;
	pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt, 1000);
	fill_opt_ts((uint8_t *)(ut_packet_tcp_hdr(pkt) + 1), ts, tsock->snd_ts);

	/*
	 * simulate tsock being idle for 24days
	 * also can't use ut_tcp_input_one here as it updates ts_us
	 */
	worker->ts_us += TCP_PAWS_IDLE_MAX * 1e6;
	ut_tcp_input_raw(tsock, &pkt, 1); {
		assert(tsock->stats_base[ERR_TCP_INVALID_TS] == 0);
		assert(tsock->ts_recent == ts);
		assert(tsock->ts_recent_in_sec == now_in_sec(worker));
	}

	ut_close(tsock, CLOSE_TYPE_RESET);
}

/*
 * RFC 7323 5.2: when an <RST> segment is received, it MUST NOT be
 * subjected to the PAWS check by verifying an acceptable value in
 * SEG.TSval, and information from the Timestamps option MUST NOT
 * be used to update connection state information.
 */
static void test_tcp_ts_paws_reset(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	uint32_t ts;

	printf("testing %s [rst pkt] ...\n", __func__);

	tsock = ut_tcp_connect();

	ts = tsock->ts_recent - 1;
	pkt = ut_inject_rst_packet(tsock);
	fill_opt_ts((uint8_t *)(ut_packet_tcp_hdr(pkt) + 1), ts, tsock->snd_ts);

	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->stats_base[ERR_TCP_INVALID_TS] == 0);
		assert(tsock->ts_recent != ts);
		assert(tsock->ts_recent_in_sec == now_in_sec(worker));
		assert(tsock->state == TCP_STATE_CLOSED);
	}

	ut_close(tsock, CLOSE_TYPE_CLOSE_DIRECTLY);
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_tcp_ts_basic();
	test_tcp_ts_wrap();
	test_tcp_ts_paws_reset();

	return 0;
}
