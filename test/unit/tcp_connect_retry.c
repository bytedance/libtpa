/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <unistd.h>

#include "test_utils.h"

static int has_ts;
static int mss;
static int wscale;

static void test_tcp_connect_retry(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	struct packet *synack_pkt;
	struct tcp_opts opts;
	int sid;

	printf("testing tcp_connect [retry] ...\n");

	/* tx syn */
	sid = ut_connect_to(SERVER_IP_STR, SERVER_PORT, NULL);
	assert(sid >= 0);
	assert(ut_tcp_output(&pkt, 1) == 1); {
		/* verify the syn pkt being sent out is okay */
		tsock = tsock_get_by_sid(sid);
		assert(parse_tcp_opts(&opts, pkt) == 0);
		assert(opts.has_ts == tsock->ts_enabled);
		assert(opts.has_wscale == tsock->ws_enabled);
		packet_free(pkt);
	}

	/* syn retry */
	synack_pkt = make_synack_packet(tsock, has_ts, mss, wscale, 1);
	ut_simulate_rto_timeout(tsock); {
		assert(ut_tcp_output(&pkt, 1) == 1);
		assert(TCP_SEG(pkt)->seq == tsock->snd_isn);
		assert(parse_tcp_opts(&opts, pkt) == 0);
		assert(opts.has_ts == tsock->ts_enabled);
		assert(opts.has_wscale == tsock->ws_enabled);
		packet_free(pkt);
	}

	/*
	 * 2. rcv syn-ack
	 */
	pkt = synack_pkt;
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->state == TCP_STATE_ESTABLISHED);
		assert(tsock->snd_nxt - tsock->snd_isn == 1);
		assert(tsock->snd_una == tsock->snd_nxt);
		assert(tsock->snd_mss > 0);
		assert(tsock->snd_cwnd > 0);
		assert(tsock->snd_wscale <= TCP_WSCALE_MAX);
		assert(tsock->snd_ssthresh <= TCP_SSTHRESH_MAX);
		assert(tsock->rcv_wscale <= TCP_WSCALE_MAX);
		assert(tsock->rcv_wnd < TCP_WINDOW_MAX);
		assert(tsock->ts_ok == !!has_ts);
		assert(tsock->ws_ok == !!wscale);
		assert(tsock->rto_shift == 0);
	}

	/*
	 * 3. verify ack being sent out
	 */
	assert(ut_tcp_output(&pkt, 1) == 1); {
		assert(has_flag_ack(pkt));
		assert(!has_flag_syn(pkt));
		assert(!has_flag_rst(pkt));
		assert(parse_tcp_opts(&opts, pkt) == 0);
		assert(tsock->ts_ok == !!has_ts);
		assert(opts.has_mss == 0);
		assert(opts.has_wscale == 0);
		assert(TCP_SEG(pkt)->len == 0);
		packet_free(pkt);
	}

	ut_assert_mbuf_count();
}

static void test_tcp_syn_sent_and_write(void)
{
	struct tcp_sock *tsock;
	ssize_t ret;
	int sid;

	printf("testing tcp_connect [syn_sent and write] ...\n");

	/* tx syn only */
	sid = ut_connect_to(SERVER_IP_STR, SERVER_PORT, NULL); {
		assert(sid >= 0);
		tsock = tsock_get_by_sid(sid);
		ut_tcp_output(NULL, 0);
	}

	ret = ut_write(tsock, 1500 * 10);
	assert(ret == -1 && errno == ENOTCONN);

	ut_close(tsock, CLOSE_TYPE_CLOSE_DIRECTLY);
}

static void test_tcp_connect_timeout(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	struct tcp_opts opts;
	uint64_t start_ts_us;
	int sid;

	printf("testing tcp_connect [timeout] ...\n");

	/* tx syn */
	sid = ut_connect_to(SERVER_IP_STR, SERVER_PORT, NULL);
	assert(sid >= 0);
	assert(ut_tcp_output(&pkt, 1) == 1); {
		/* verify the syn pkt being sent out is okay */
		tsock = tsock_get_by_sid(sid);
		assert(parse_tcp_opts(&opts, pkt) == 0);
		assert(opts.has_ts == tsock->ts_enabled);
		assert(opts.has_wscale == tsock->ws_enabled);
		packet_free(pkt);
	}

	/* syn retry */
	start_ts_us = worker->ts_us;
	tcp_cfg.syn_retries = 4;
	do {
		usleep(10 * 1000);

		pkt = NULL;
		assert(ut_tcp_output(&pkt, 1) <= 1);
		if (pkt) {
			printf(":: %d: syn re-xmit after %.2fs\n", tsock->rto_shift, (double)(worker->ts_us - start_ts_us) / 1e6);
			start_ts_us = worker->ts_us;
			assert(TCP_SEG(pkt)->seq == tsock->snd_isn);
			assert(parse_tcp_opts(&opts, pkt) == 0);
			assert(opts.has_ts == tsock->ts_enabled);
			assert(opts.has_wscale == tsock->ws_enabled);
			packet_free(pkt);
		}
	} while (tsock->state == TCP_STATE_SYN_SENT); {
		assert(tsock->state == TCP_STATE_CLOSED);
		assert(tsock->err == ETIMEDOUT);

		ut_event_ctrl(tsock, TPA_EVENT_CTRL_ADD, TPA_EVENT_IN | TPA_EVENT_OUT);
		assert((ut_event_poll(tsock) & TPA_EVENT_ERR) != 0); {
			assert(ut_write(tsock, 100) == -1); {
				assert(errno == ETIMEDOUT); errno = 0;
			}

			assert(ut_readv(tsock, 1) == -1); {
				assert(errno == ETIMEDOUT); errno = 0;
			}
		}
	}

	ut_dump_tsock_stats(tsock);
	ut_assert_mbuf_count();
}

static void test_tcp_connect_timeout_and_close(void)
{
	struct tcp_sock *tsock;
	int sid;
	int i;

	printf("testing tcp_connect [timeout then close] ...\n");

	/* tx syn */
	sid = ut_connect_to(SERVER_IP_STR, SERVER_PORT, NULL); {
		assert(sid >= 0);
		tsock = tsock_get_by_sid(sid);
		assert(ut_tcp_output(NULL, 0) == 1);
	}

	/* syn retry */
	tcp_cfg.syn_retries = 2;
	for (i = 0; i < tcp_cfg.syn_retries; i++) {
		usleep(0.3 * 1e6 * (i+1));

		if (i == tcp_cfg.syn_retries - 1)
			tpa_close(sid);

		assert(ut_tcp_output(NULL, 1) <= 1);
	} while (tsock->state == TCP_STATE_SYN_SENT); {
		assert(tsock->state == TCP_STATE_CLOSED);
		assert(tsock->err == ETIMEDOUT);
	}

	ut_dump_tsock_stats(tsock);
	ut_assert_mbuf_count();
}

/*
 * Here is a corner case that triggered a crash
 * - syn sent
 * - RTO happens
 * - got the syn-ack, then it's established
 * - then write
 */
static void test_tcp_connect_syn_sent_rto_established_write(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	int sid;

	printf("testing %s ...\n", __func__);

	/* tx syn */
	sid = ut_connect_to(SERVER_IP_STR, SERVER_PORT, NULL); {
		assert(sid >= 0);
		tsock = &sock_ctrl->socks[sid];
	}
	assert(ut_tcp_output(NULL, -1) == 1);

	/* RTO */
	ut_simulate_rto_timeout(tsock);

	/* rcv syn-ack */
	pkt = make_synack_packet(tsock, has_ts, mss, wscale, 1);
	ut_tcp_input_one(tsock, pkt);

	/* write */
	ut_write_assert(tsock, 1000);

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	has_ts = ut_test_opts.has_ts;
	mss    = ut_test_opts.mss;
	wscale = ut_test_opts.wscale;

	test_tcp_connect_retry();
	test_tcp_syn_sent_and_write();
	test_tcp_connect_timeout();
	test_tcp_connect_timeout_and_close();
	test_tcp_connect_syn_sent_rto_established_write();

	return 0;
}
