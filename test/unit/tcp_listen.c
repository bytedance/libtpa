/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <unistd.h>

#include "test_utils.h"

static struct packet *inject_syn_packet(struct tcp_sock *tsock)
{
	struct packet *pkt;
	uint32_t isn;
	int opt_len = 0;

	isn = isn_gen(&tsock->local_ip, &tsock->remote_ip, tsock->local_port, tsock->remote_port);

	pkt = ut_make_packet(1, tsock->local_port, tsock->sid);
	ut_tcp_set_hdr(pkt, isn, 0, TCP_FLAG_SYN, 65535);

	/*
	 * Inject an invalid tcp option; make sure we can handle it well.
	 *
	 * XXX: we probably should introduce a standalone testcase for it.
	 */
	opt_len = ut_tcp_set_opt(ut_packet_tcp_hdr(pkt), opt_len, TCP_OPT_TS_KIND, rte_rdtsc() >> 10);
	opt_len = ut_tcp_set_opt(ut_packet_tcp_hdr(pkt), opt_len, TCP_OPT_WSCALE_KIND, 10);
	opt_len = ut_tcp_set_opt(ut_packet_tcp_hdr(pkt), opt_len, TCP_OPT_TYPE_UNKNOWN, 0);

	ut_ip_set_hdr(pkt, opt_len, 0);

	return pkt;
}

static struct tcp_sock *find_tsock_by_synack_pkt(struct packet *pkt)
{
	struct tcp_sock *tsock;
	struct sock_key key;

	assert(pkt->dst_port);
	assert(TCP_SEG(pkt)->flags == (TCP_FLAG_SYN | TCP_FLAG_ACK));
	assert(TCP_SEG(pkt)->wnd == 65535);

	init_tpa_ip_from_pkt(pkt, &key.local_ip, &key.remote_ip);
	key.local_port  = ntohs(pkt->src_port);
	key.remote_port = ntohs(pkt->dst_port);

	tsock = sock_table_lookup(&worker->sock_table, &key);
	assert(tsock != NULL);

	assert(tsock->state == TCP_STATE_SYN_RCVD);

	return tsock;
}

static struct tcp_sock *accept_one_tsock(int expected_sid, void *data)
{
	struct tcp_sock *tsock;
	int sid;

	assert(tpa_accept_burst(worker, &sid, 1) == 1); {
		tsock = &sock_ctrl->socks[sid];
		assert(tsock->sid == sid);

		if (expected_sid >= 0)
			assert(sid == expected_sid);

		if (data) {
			struct tpa_sock_info info;

			assert(tpa_sock_info_get(sid, &info) == 0);
			assert(info.data == data);
		}
	}

	return tsock;
}

static int listen_random_port(const char *local, void *data)
{
	struct tpa_sock_opts opts;
	uint16_t port;
	int sid;

	memset(&opts, 0, sizeof(opts));
	opts.data = data;

	while (1) {
		port = (rand() % 65000) + 1024;

		sid = tpa_listen_on(local, port, &opts);
		if (sid >= 0)
			return sid;

		if (errno != EADDRINUSE)
			return sid;
	}

	return -1;
}

static struct tcp_sock *do_tcp_listen_one(int port, struct tcp_sock **listen_tsock_ptr,
					  int drain_accept_queue)
{
	struct tcp_sock *listen_tsock;
	struct tcp_sock *tsock;
	struct packet *pkt;
	void *data = (void *)(uintptr_t)rand();
	int sid;

	sid = listen_random_port(NULL, data); {
		assert(sid >= 0 && sid < tcp_cfg.nr_max_sock);
		listen_tsock = &sock_ctrl->socks[sid];
	}

	pkt = inject_syn_packet(listen_tsock);
	ut_tcp_input_one(listen_tsock, pkt); {
		assert(listen_tsock->state == TCP_STATE_LISTEN);

		assert(ut_tcp_output(&pkt, 1) == 1); {
			tsock = find_tsock_by_synack_pkt(pkt);
		}
	}

	pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt);
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->state == TCP_STATE_ESTABLISHED);
		assert(tsock->ts_ok == 1);
	}

	if (listen_tsock_ptr)
		*listen_tsock_ptr = listen_tsock;
	else
		ut_close(listen_tsock, CLOSE_TYPE_CLOSE_DIRECTLY);

	if (drain_accept_queue)
		assert(accept_one_tsock(tsock->sid, data) == tsock);

	return tsock;
}

static struct tcp_sock *tcp_listen_one(void)
{
	return do_tcp_listen_one(0, NULL, 1);
}

static void test_tcp_listen_basic(void)
{
	struct tcp_sock *tsock;

	printf(":: %s\n", __func__);

	tsock = tcp_listen_one();

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_listen_and_read(void)
{
	struct tcp_sock *tsock;
	struct tpa_iovec iov;
	struct packet *pkt;

	printf(":: %s\n", __func__);

	tsock = tcp_listen_one();

	pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt, 1000);
	ut_tcp_input_one(tsock, pkt); {
		assert(ut_event_poll(tsock) == 0);

		assert(tpa_zreadv(tsock->sid, &iov, 1) == 1000);
		iov.iov_read_done(iov.iov_base, iov.iov_param);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_listen_synack_data_before_offload(void)
{
	struct tcp_sock *listen_tsock;
	struct tcp_sock *tsock;
	struct packet *pkt;
	struct packet *data_pkt;
	struct tpa_iovec iov;
	struct tpa_sock_info info;
	int sid;

	printf(":: %s\n", __func__);

	sid = listen_random_port(NULL, &info); {
		assert(sid >= 0 && sid < tcp_cfg.nr_max_sock);
		listen_tsock = &sock_ctrl->socks[sid];
	}

	pkt = inject_syn_packet(listen_tsock);
	ut_tcp_input_one(listen_tsock, pkt); {
		assert(listen_tsock->state == TCP_STATE_LISTEN);

		assert(ut_tcp_output(&pkt, 1) == 1); {
			tsock = find_tsock_by_synack_pkt(pkt);
		}
	}

	/*
	 * simulate the syn-ack pkt and data pkt get recv at the same
	 * time before sock being offloaded (therefore, the data_pkt
	 * would still match the listen tsock, with the flow mark
	 * from it).
	 */
	pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt);
	data_pkt = ut_inject_data_packet(tsock, tsock->rcv_nxt, 1000);
	data_pkt->mbuf.hash.fdir.hi = make_flow_mark(worker->id, listen_tsock->sid);
	ut_tcp_input_one(tsock, pkt);
	ut_tcp_input_one(tsock, data_pkt); {
		assert(tsock->state == TCP_STATE_ESTABLISHED);

		assert(tpa_accept_burst(worker, &sid, 1) == 1);
		assert(sid == tsock->sid);
		assert(tpa_sock_info_get(sid, &info) == 0);
		assert(info.data == (void *)&info);

		assert(tpa_zreadv(tsock->sid, &iov, 1) == 1000);
		iov.iov_read_done(iov.iov_base, iov.iov_param);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
	ut_close(listen_tsock, CLOSE_TYPE_CLOSE_DIRECTLY);
}

static void test_tcp_listen_invalid_pkt(void)
{
	struct tcp_sock *listen_tsock;
	struct packet *pkt;
	int sid;

	printf(":: %s\n", __func__);

	sid = listen_random_port(NULL, NULL); {
		assert(sid >= 0 && sid < tcp_cfg.nr_max_sock);
		listen_tsock = &sock_ctrl->socks[sid];
	}

	pkt = ut_inject_data_packet(listen_tsock, 0, 1000);
	ut_packet_tcp_hdr(pkt)->tcp_flags = 0;
	ut_tcp_input_one(listen_tsock, pkt); {
		assert(listen_tsock->state == TCP_STATE_LISTEN);

		assert(ut_tcp_output(NULL, 1) == 0);
		assert(listen_tsock->stats_base[WARN_INVLIAD_PKT_AT_LISTEN] == 1);
	}

	ut_close(listen_tsock, CLOSE_TYPE_CLOSE_DIRECTLY);
}

static void test_tcp_listen_dup_syn(void)
{
	struct tcp_sock *listen_tsock;
	struct tcp_sock *tsock;
	struct packet *pkts[2];
	int sid;

	printf(":: %s\n", __func__);

	sid = listen_random_port(NULL, NULL); {
		assert(sid >= 0 && sid < tcp_cfg.nr_max_sock);
		listen_tsock = &sock_ctrl->socks[sid];
	}

	/* inject dup syn */
	pkts[0] = inject_syn_packet(listen_tsock);
	pkts[1] = inject_syn_packet(listen_tsock);
	ut_tcp_input(listen_tsock, pkts, 2); {
		assert(ut_tcp_output(pkts, 2) == 2); {
			tsock = find_tsock_by_synack_pkt(pkts[0]);

			assert(TCP_SEG(pkts[1])->len == 0);
			assert(TCP_SEG(pkts[1])->flags == TCP_FLAG_ACK);

			packet_free(pkts[0]);
			packet_free(pkts[1]);
		}
	}

	ut_close(tsock, CLOSE_TYPE_4WAY); {
		/*
		 * drain the accept queue and the return value
		 * should be 0: it's been filtered out by sanity check.
		 */
		assert(tpa_accept_burst(worker, &sid, 1) == 0);
	}
	ut_close(listen_tsock, CLOSE_TYPE_CLOSE_DIRECTLY);
}

static void test_tcp_listen_port(void)
{
	struct tcp_sock *listen_tsock;
	uint16_t port;
	int sid;

	printf(":: %s\n", __func__);

	/* test EADDRINUSE */
	sid = listen_random_port(NULL, NULL); {
		assert(sid >= 0);
		listen_tsock = &sock_ctrl->socks[sid];
		port = ntohs(listen_tsock->local_port);

		assert(tpa_listen_on(NULL, port, NULL) < 0);
		assert(errno == EADDRINUSE);
	}

	ut_close(listen_tsock, CLOSE_TYPE_CLOSE_DIRECTLY); {
		sid = tpa_listen_on(NULL, port, NULL); {
			assert(sid >= 0);
			listen_tsock = &sock_ctrl->socks[sid];

			ut_close(listen_tsock, CLOSE_TYPE_CLOSE_DIRECTLY);
		}
	}
}

static void test_tcp_listen_port2(void)
{
	struct tcp_sock *listen_tsock;
	struct tcp_sock *tsock;
	uint16_t port;

	printf(":: %s\n", __func__);

	tsock = do_tcp_listen_one(0, &listen_tsock, 1); {
		port = ntohs(listen_tsock->local_port);
	}

	/* a child socket close would not free the listen port */
	ut_close(tsock, CLOSE_TYPE_4WAY); {
		assert(tpa_listen_on(NULL, port, NULL) < 0);
		assert(errno == EADDRINUSE);
	}

	ut_close(listen_tsock, CLOSE_TYPE_CLOSE_DIRECTLY);
}

static void test_tcp_listen_synack_retry(void)
{
	struct tcp_sock *listen_tsock;
	struct tcp_sock *tsock;
	struct packet *pkt;
	int sid;

	printf(":: %s\n", __func__);

	sid = listen_random_port(NULL, NULL); {
		assert(sid >= 0 && sid < tcp_cfg.nr_max_sock);
		listen_tsock = &sock_ctrl->socks[sid];
	}

	pkt = inject_syn_packet(listen_tsock);
	ut_tcp_input_one(listen_tsock, pkt); {
		assert(ut_tcp_output(&pkt, 1) == 1); {
			tsock = find_tsock_by_synack_pkt(pkt);
		}
	}

	ut_simulate_rto_timeout(tsock); {
		assert(ut_tcp_output(&pkt, 1) == 1); {
			assert(find_tsock_by_synack_pkt(pkt) == tsock);
		}
	}

	pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt);
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->state == TCP_STATE_ESTABLISHED);
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
	ut_close(listen_tsock, CLOSE_TYPE_CLOSE_DIRECTLY);
}

static void test_tcp_listen_synack_retry_timeout(void)
{
	struct tcp_sock *listen_tsock;
	struct tcp_sock *tsock;
	struct packet *pkt;
	int sid;
	int ret;
	int i;

	printf(":: %s\n", __func__);

	sid = listen_random_port(NULL, NULL); {
		assert(sid >= 0 && sid < tcp_cfg.nr_max_sock);
		listen_tsock = &sock_ctrl->socks[sid];
	}

	pkt = inject_syn_packet(listen_tsock);
	ut_tcp_input_one(listen_tsock, pkt); {
		assert(ut_tcp_output(&pkt, 1) == 1); {
			tsock = find_tsock_by_synack_pkt(pkt);
		}
	}

	tcp_cfg.syn_retries = 4;
	for (i = 0; i < tcp_cfg.syn_retries; i++) {
		ut_simulate_rto_timeout(tsock); {
			ret = ut_tcp_output(&pkt, 1); {
				if (i == tcp_cfg.syn_retries - 1) {
					assert(ret == 0);
				} else {
					assert(ret == 1);
					assert(find_tsock_by_synack_pkt(pkt) == tsock);
				}
			}
		}
	}

	assert(tsock->state == TCP_STATE_CLOSED);

	ut_close(listen_tsock, CLOSE_TYPE_CLOSE_DIRECTLY);
}

static void test_tcp_listen_addr(void)
{
	printf(":: %s\n", __func__);
	int sid;

	sid = listen_random_port("127.0.0.1", NULL); {
		assert(sid >= 0);
		ut_close(&sock_ctrl->socks[sid], CLOSE_TYPE_CLOSE_DIRECTLY);
	}

	sid = listen_random_port("::1", NULL); {
		assert(sid >= 0);
		ut_close(&sock_ctrl->socks[sid], CLOSE_TYPE_CLOSE_DIRECTLY);
	}

	/* listen on any address other than local address would fail */
	assert(tpa_listen_on("::2", 80, NULL) < 0);
	assert(tpa_listen_on("192.168.30.40", 80, NULL) < 0);
}

static void test_tcp_listen_accept(void)
{
	struct tcp_sock *tsock;

	printf(":: %s\n", __func__);

	/* leave a stale tsock in recv queue */
	tsock = do_tcp_listen_one(0, NULL, 0);
	ut_close(tsock, CLOSE_TYPE_4WAY);

	/*
	 * accept with 1 bugdet would filter the stale one and return with
	 * the newly accepted tsock
	 */
	tsock = do_tcp_listen_one(0, NULL, 0);
	accept_one_tsock(-1, NULL);

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_tcp_listen_recv_ack(void)
{
	struct tcp_sock *listen_tsock;
	struct packet *pkt;
	int sid;

	printf(":: %s\n", __func__);

	sid = listen_random_port(NULL, NULL); {
		assert(sid >= 0 && sid < tcp_cfg.nr_max_sock);
		listen_tsock = &sock_ctrl->socks[sid];
	}

	pkt = ut_inject_data_packet(listen_tsock, 0, 1000);
	ut_tcp_input_one(listen_tsock, pkt); {
		assert(ut_tcp_output(&pkt, 1) == 1); {
			assert(TCP_SEG(pkt)->flags == TCP_FLAG_RST);
			assert(TCP_SEG(pkt)->len == 0);
			assert(listen_tsock->stats_base[WARN_ACK_AT_LISTEN] == 1);
		}
	}

	ut_close(listen_tsock, CLOSE_TYPE_CLOSE_DIRECTLY);
}

static void test_tcp_listen_recv_rst_at_syn_rcvd(void)
{
	struct tcp_sock *listen_tsock;
	struct tcp_sock *tsock;
	struct packet *pkt;
	int sid;

	printf(":: %s\n", __func__);

	sid = listen_random_port(NULL, NULL); {
		assert(sid >= 0 && sid < tcp_cfg.nr_max_sock);
		listen_tsock = &sock_ctrl->socks[sid];
	}

	pkt = inject_syn_packet(listen_tsock);
	ut_tcp_input_one(listen_tsock, pkt); {
		assert(listen_tsock->state == TCP_STATE_LISTEN);

		assert(ut_tcp_output(&pkt, 1) == 1); {
			tsock = find_tsock_by_synack_pkt(pkt);
		}
	}

	pkt = ut_inject_rst_packet(tsock);
	ut_tcp_input_one(listen_tsock, pkt); {
		assert(ut_tcp_output(NULL, -1) == 0); {
			assert(tsock->state == TCP_STATE_CLOSED);
			assert(tsock->sid == TSOCK_SID_FREEED);
		}
	}

	ut_close(listen_tsock, CLOSE_TYPE_CLOSE_DIRECTLY);
}

/*
 * - close the sock at SYN_RCVD state (before the SYN is acked).
 * - ack SYN and FIN in one packet
 */
static void test_tcp_listen_syn_rcvd_then_close(void)
{
	struct tcp_sock *listen_tsock;
	struct tcp_sock *tsock;
	struct packet *pkt;
	int sid;

	printf(":: %s\n", __func__);

	sid = listen_random_port(NULL, NULL); {
		assert(sid >= 0 && sid < tcp_cfg.nr_max_sock);
		listen_tsock = &sock_ctrl->socks[sid];
	}

	pkt = inject_syn_packet(listen_tsock);
	ut_tcp_input_one(listen_tsock, pkt); {
		assert(listen_tsock->state == TCP_STATE_LISTEN);

		assert(ut_tcp_output(&pkt, 1) == 1); {
			tsock = find_tsock_by_synack_pkt(pkt);
		}
	}

	/* xmit FIN */
	tpa_close(tsock->sid);
	ut_tcp_output(NULL, -1); {
		assert(tsock->state == TCP_STATE_FIN_WAIT_1);
	}

	/* ack SYN and FIN together */
	pkt = ut_inject_ack_packet(tsock, tsock->snd_isn + 2);
	ut_tcp_input_one(listen_tsock, pkt); {
		assert(tsock->state == TCP_STATE_FIN_WAIT_2);
	}

	ut_close(listen_tsock, CLOSE_TYPE_CLOSE_DIRECTLY);
}

static void test_tcp_accept_at_close_wait(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;

	printf("%s\n", __func__);

	tsock = do_tcp_listen_one(0, NULL, 0);

	pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt);
	ut_packet_tcp_hdr(pkt)->tcp_flags |= TCP_FLAG_FIN;
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->state == TCP_STATE_CLOSE_WAIT);
	}

	accept_one_tsock(-1, NULL);

	/* XXX: we have no passive close at ut_close */
	tpa_close(tsock->sid);
	ut_tcp_output(NULL, -1);
}

static void test_tcp_listen_offload_fail(void)
{
	int sid;

	printf(":: testing %s\n", __func__);

	/* a trick to make flow offload fail */
	dev.caps |= FLOW_OFFLOAD; {
		sid = listen_random_port("127.0.0.1", NULL); {
			assert(sid < 0);
			assert(errno == EBUSY);
		}

		sid = listen_random_port("::1", NULL); {
			assert(sid < 0);
			assert(errno == EBUSY);
		}

		sid = listen_random_port(NULL, NULL); {
			assert(sid < 0);
			assert(errno == EBUSY);
		}
	}

	/* make sure we are back to normal */
	dev.caps &= ~FLOW_OFFLOAD; {
		sid = listen_random_port("127.0.0.1", NULL); {
			assert(sid >= 0);
			ut_close(&sock_ctrl->socks[sid], CLOSE_TYPE_CLOSE_DIRECTLY);
		}

		sid = listen_random_port("::1", NULL); {
			assert(sid >= 0);
			ut_close(&sock_ctrl->socks[sid], CLOSE_TYPE_CLOSE_DIRECTLY);
		}

		sid = listen_random_port(NULL, NULL); {
			assert(sid >= 0);
			ut_close(&sock_ctrl->socks[sid], CLOSE_TYPE_CLOSE_DIRECTLY);
		}
	}
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_tcp_listen_basic();
	test_tcp_listen_and_read();
	test_tcp_listen_synack_data_before_offload();
	test_tcp_listen_invalid_pkt();
	test_tcp_listen_dup_syn();
	test_tcp_listen_port();
	test_tcp_listen_port2();
	test_tcp_listen_synack_retry();
	test_tcp_listen_synack_retry_timeout();
	test_tcp_listen_addr();
	test_tcp_listen_accept();
	test_tcp_listen_recv_ack();
	test_tcp_listen_recv_rst_at_syn_rcvd();
	test_tcp_listen_syn_rcvd_then_close();
	test_tcp_accept_at_close_wait();
	test_tcp_listen_offload_fail();

	return 0;
}
