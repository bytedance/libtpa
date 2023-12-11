/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <unistd.h>

#include "test_utils.h"

static void test_tcp_zwritev_mixed(void)
{
	struct tcp_sock *tsock;
	struct tpa_iovec iov[2];
	struct packet *pkt;
	ssize_t ret;

	printf("testing %s ...\n", __func__);

	tsock = ut_tcp_connect();

	/* write with ack */
	setup_tpa_iovec(&iov[0], tsock->snd_mss + 1, 0);
	setup_tpa_iovec(&iov[1], tsock->snd_mss + 1, 1);
	ret = tpa_zwritev(tsock->sid, iov, 2); {
		assert(ret == tsock->snd_mss * 2 + 2);

		ut_tcp_output(NULL, -1); {
			assert(tsock->stats_base[PKT_XMIT] == 2);
		}

		pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt);
		ut_tcp_input_one(tsock, pkt); {
			assert(tsock->snd_una == tsock->snd_nxt);
		}
	}


	/* another write without ack */
	setup_tpa_iovec(&iov[0], tsock->snd_mss + 1, 0);
	setup_tpa_iovec(&iov[1], tsock->snd_mss + 1, 1);
	ret = tpa_zwritev(tsock->sid, iov, 2); {
		assert(ret == tsock->snd_mss * 2 + 2);

		ut_tcp_output(NULL, -1); {
			assert(tsock->stats_base[PKT_XMIT] == 4);
		}
	}

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

#define IOV_COUNT	6

/*
 * mix all stuff below together in one write call:
 * - zero copy write
 * - non zero copy write
 * - iov_len == 0
 */
static void test_tcp_zwritev_mixed_stress(void)
{
	struct tcp_sock *tsock;
	struct packet *pkt;
	struct tpa_iovec iov[IOV_COUNT];
	int nr_zero_len = 0;
	uint32_t len;
	int zwrite;
	int i;

	printf("testing tcp_output stress ...\n");

	tsock = ut_tcp_connect();

	WHILE_NOT_TIME_UP() {
		for (i = 0; i < IOV_COUNT; i++) {
			if (rand() % 100 < 10)
				len = rand() % (1<<20);
			else
				len = rand() % 8192;
			zwrite = rand() % 2;

			if (len) {
				setup_tpa_iovec(&iov[i], len, zwrite);
			} else {
				nr_zero_len += 1;
				iov[i].iov_len = 0;
			}
		}

		if (tpa_zwritev(tsock->sid, iov, IOV_COUNT) < 0) {
			assert(errno == EAGAIN);
			for (i = 0; i < IOV_COUNT; i++) {
				if (iov[i].iov_len)
					iov[i].iov_write_done(iov[i].iov_base, iov[i].iov_param);
			}
		}

		ut_tcp_output(NULL, 0);

		pkt = ut_inject_ack_packet(tsock, tsock->snd_nxt - 511);
		ut_tcp_input_one(tsock, pkt);

		ut_measure_rate(tsock, 1000 * 1000);
	}

	printf("nr_zero_len: %d\n", nr_zero_len);

	ut_close(tsock, CLOSE_TYPE_4WAY);
}

int main(int argc, char *argv[])
{
	ut_init(argc, argv);

	test_tcp_zwritev_mixed();
	test_tcp_zwritev_mixed_stress();

	return 0;
}
