/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <getopt.h>
#include <sys/uio.h>

#include "test_utils.h"

/*
 * test passive close
 */


/*
 * TODO:
  * - test with more states
  * - test with pending send buffer
  * - test with pending recv buffer?
  * - test with pending ooo recv buffer
  */
static void test_tcp_input_fin(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	uint32_t fin_seq;

	printf("testing tcp_input_fin ...\n");

	tsock = ut_tcp_connect();
	fin_seq = tsock->rcv_nxt;

	/* recv FIN */
	pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt);
	ut_packet_tcp_hdr(pkt)->tcp_flags |= TCP_FLAG_FIN;
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->state == TCP_STATE_CLOSE_WAIT);
		assert(tsock->err == 0);

		ut_event_ctrl(tsock, TPA_EVENT_CTRL_ADD, TPA_EVENT_IN | TPA_EVENT_OUT);
		assert(ut_event_poll(tsock) == (TPA_EVENT_IN | TPA_EVENT_OUT)); {
			assert(ut_readv(tsock, 1) == 0);
		}

		/* ACK the FIN */
		assert(ut_tcp_output(&pkt, 1) == 1); {
			assert(TCP_SEG(pkt)->ack == (uint32_t)(fin_seq + 1));
			packet_free(pkt);
		}
	}

	/* close and send our FIN */
	tpa_close(tsock->sid);
	assert(ut_tcp_output(&pkt, 1) == 1); {
		assert(tsock->state == TCP_STATE_LAST_ACK);
		assert(TCP_SEG(pkt)->flags == (TCP_FLAG_FIN | TCP_FLAG_ACK));
		packet_free(pkt);
	}

	/* simulate the ack of our FIN */
	pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt);
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->state == TCP_STATE_CLOSED);
	}

	ut_dump_tsock_stats(tsock);
	ut_assert_mbuf_count();
}

static void test_tcp_input_fin_with_old_ack(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	/* xmit FIN */
	tpa_close(tsock->sid);
	assert(ut_tcp_output(&pkt, 1) == 1); {
		assert(tsock->state == TCP_STATE_FIN_WAIT_1);
		packet_free(pkt);
	}

	/* simulate the ack of our FIN */
	pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt);
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->state == TCP_STATE_FIN_WAIT_2);
	}

	/*
	 * simulate the FIN from the remote end
	 *
	 * note that here an old ACK is shipped (which is accepted
	 * per rfc 793 page 71: the ACK will be sliently ignored).
	 */
	pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt - 1);
	ut_packet_tcp_hdr(pkt)->tcp_flags |= TCP_FLAG_FIN;
	ut_tcp_input_one(tsock, pkt); {
		assert(tsock->state == TCP_STATE_TIME_WAIT);

		/* xmit the ACK */
		assert(ut_tcp_output(NULL, 1) == 1);
	}

	ut_dump_tsock_stats(tsock);
	ut_assert_mbuf_count();
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_tcp_input_fin();
	test_tcp_input_fin_with_old_ack();

	return 0;
}
