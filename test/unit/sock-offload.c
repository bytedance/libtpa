/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <unistd.h>

#include "test_utils.h"

/*
 * Here is the thing: destroying a NIC rule (by invoking rte_flow_destroy)
 * is not real time. Even after the destroying the rule, some pkts may have
 * already been on the NIC rx queue, leading us still be able to recv them
 * after the destroy.
 *
 * That could be problematic if not handled well. Below are few cases.
 */



/*
 * Assume tsock 0 is assigned to worker 0 (tsock0->worker = worker0); then
 * it's closed. But we may still recv some pkts belong to it later (in
 * some abnormal case).
 *
 * Now assume tsock 0 was re-allocated, to worker 1 (tsock0->worker = worker1 now).
 *
 * Then assume a stale pkt belong to the old tsock0 is recved; that pkt
 * will go to worker 0, while the other pkts belong to the new tsock0
 * will go to worker 1. They both reference one tsock, which is dangerous,
 * as tsock is meant to be per-worker and therefore lock free.
 *
 * A proper solution for that would be including the worker info at the flow
 * mark. This will make sure a tsock is processed only at one worker at a
 * time. Besides that, we also need to do extra sanity check at tsock lookup:
 * make sure the pkt is intended for this sock. We drop it otherwise.
 */
static void test_sock_offload_stale_pkt_mismatch_tuple(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;

	printf("testing sock offload [stale pkt mismatch tuple] ...\n");

	tsock = ut_tcp_connect();

	pkt = ut_inject_rst_packet(tsock); {
		/* simulate a pkt to an old tsock (has the same sid) */
		ut_packet_tcp_hdr(pkt)->dst_port = 1;

		ut_tcp_input_one(tsock, pkt); {
			assert(tsock->state == TCP_STATE_ESTABLISHED);
			assert(worker->stats_base[WARN_STALE_PKT_TUPLE_MISMATCH] == 1);
		}
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

static void test_sock_offload_stale_pkt_mismatch_worker(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;

	printf("testing sock offload [stale pkt mismatch worker] ...\n");

	tsock = ut_tcp_connect();

	pkt = ut_inject_rst_packet(tsock); {
		/*
		 * simulate a pkt to an old tsock (has the same sid) assigned
		 * to a different worker; therefore, a hack is needed
		 */
		tpa_cfg.nr_worker = 2;
		pkt->mbuf.hash.fdir.hi = make_flow_mark(1, tsock->sid);

		ut_tcp_input_one(tsock, pkt); {
			assert(tsock->state == TCP_STATE_ESTABLISHED);
			assert(worker->stats_base[WARN_STALE_PKT_WORKER_MISMATCH] == 1);
		}
		tpa_cfg.nr_worker = 1;
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_sock_offload_stale_pkt_mismatch_tuple();
	test_sock_offload_stale_pkt_mismatch_worker();

	return 0;
}
