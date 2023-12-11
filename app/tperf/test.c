/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>

#include "tperf.h"

static int read_test_info(struct connection *conn, struct tpa_iovec *iov, int size)
{
	uint32_t off = conn->info_off;
	int bytes_eaten = 0;
	int idx = 0;
	int len;

	/* if already parsed? */
	if (off == sizeof(struct test_info))
		return 0;

	while (off < sizeof(struct test_info)) {
		len = MIN(iov[idx].iov_len, sizeof(struct test_info) - off);
		memcpy(&conn->info_raw[off], iov[idx].iov_base, len);

		off += len;
		bytes_eaten += len;

		size -= len;
		if (size == 0)
			break;
	}

	conn->info_off = off;
	if (off == sizeof(struct test_info))
		init_server_conn(conn);

	return bytes_eaten;
}

static void read_test_data(struct connection *conn, struct tpa_iovec *iov,
			   int bytes_read, int bytes_eaten)
{
	char *base;
	int len;
	int sum = 0;
	int i = 0;

	while (sum < bytes_read) {
		base = iov[i].iov_base;
		len  = iov[i].iov_len;

		if (sum < bytes_eaten) {
			/* is this iov completely consumed? */
			if (sum + len < bytes_eaten)
				goto next;

			base = iov[i].iov_base + bytes_eaten - sum;
			len -= bytes_eaten - sum;
		}

		if (conn->integrity_enabled)
			integrity_verify(base, len, conn->integrity_off + conn->stats.bytes_read);

		UPDATE_STATS(conn, bytes_read, len);

	next:
		iov[i].iov_read_done(iov[i].iov_base, iov[i].iov_param);

		sum += iov[i].iov_len;
		i += 1;
	}

	conn->read.off += bytes_read - bytes_eaten;
}

static void on_rr_read_done(struct connection *conn)
{
	assert(conn->read.off == conn->read.budget);

	/* we got the respose: the request is done */
	if (conn->is_client) {
		update_latency(conn);

		if (conn->test == TEST_CRR)
			conn->to_close = 1;
	}

	/*
	 * re-open the write, when we are the
	 * - server: we just got the req; we need send the response; OR,
	 * - client and the test is RR: we just got the response,
	 *   let's start another request.
	 */
	if (!conn->is_client || conn->test == TEST_RR) {
		conn->write.budget = conn->message_size;
		event_queue_add(conn, TPA_EVENT_OUT);
	}

	conn->read.off = 0;
}

static void on_read_done(struct connection *conn)
{
	if (conn->read.off < conn->read.budget)
		return;

	if ((conn->test == TEST_RR || conn->test == TEST_CRR)) {
		on_rr_read_done(conn);
	} else {
		/* doesn't really matter here */
		conn->read.off -= conn->read.budget;
	}
}

int conn_on_read(struct connection *conn)
{
	struct tpa_iovec iov[BATCH_SIZE];
	int bytes_read;
	int bytes_eaten;

	while (1) {
		bytes_read = tpa_zreadv(conn->sid, iov, BATCH_SIZE);
		if (bytes_read < 0) {
			if (errno == EAGAIN)
				break;

			return -1;
		}

		if (bytes_read == 0)
			return -1;

		bytes_eaten = read_test_info(conn, iov, bytes_read);
		read_test_data(conn, iov, bytes_read, bytes_eaten);

		on_read_done(conn);
	}

	return 0;
}

static int emit_test_info(struct connection *conn)
{
	struct test_info *info = &conn->info;
	int ret;

	if (conn->info_off == sizeof(struct test_info))
		return 0;

	info->test = conn->test;
	info->integrity_enabled = conn->integrity_enabled;
	info->integrity_off = conn->integrity_off;
	info->enable_zwrite = conn->enable_zwrite;
	info->message_size = conn->message_size;

	ret = tpa_write(conn->sid, info, sizeof(*info));
	if (ret != sizeof(*info)) {
		if (ret == -1 && errno == EAGAIN)
			return 0;

		fprintf(stderr, "err_emit_test_info: %s\n", strerror(errno));
		return -1;
	}

	conn->info_off = sizeof(struct test_info);

	return 0;
}

static void zwrite_done(void *iov_base, void *iov_param)
{
	struct mbuf *mbuf = iov_param;
	struct connection *conn = mbuf->private;

	mbuf_put(mbuf);
	conn_put(conn);
}

static int setup_test_data(struct test_thread *thread, struct connection *conn, struct tpa_iovec *iov)
{
	int budget = conn->write.budget;
	size_t off = conn->write.off;
	struct mbuf *mbuf;
	int nr_iov = 0;
	int len;

	while (off < budget) {
		mbuf = mbuf_alloc(thread->mbuf_pool);
		assert(mbuf != NULL);

		mbuf->private = conn_get(conn);

		len = MIN(budget - off, MBUF_SIZE);
		iov[nr_iov].iov_base = mbuf->data;
		iov[nr_iov].iov_len  = len;
		iov[nr_iov].iov_phys = conn->enable_zwrite;
		iov[nr_iov].iov_write_done = zwrite_done;
		iov[nr_iov].iov_param = mbuf;

		if (conn->integrity_enabled)
			integrity_fill(mbuf->data, len, conn->integrity_off + conn->stats.bytes_write + off);

		nr_iov += 1;
		off += len;
	}

	return nr_iov;
}

static void on_write_done(struct connection *conn, int bytes_write)
{
	UPDATE_STATS(conn, bytes_write, bytes_write);
	conn->write.off += bytes_write;

	if (conn->write.off < conn->write.budget)
		return;
	assert(conn->write.off == conn->write.budget);

	/* disable futher writes unless we get the response */
	if (conn->test == TEST_RR || conn->test == TEST_CRR)
		conn->write.budget = 0;

	conn->write.off = 0;
}

int conn_on_write(struct connection *conn)
{
	struct test_thread *thread = conn->thread;
	int bytes_write;
	int nr_iov;
	int i;

	if (ctx.is_client && emit_test_info(conn) < 0)
		return -1;

	while (conn->write.budget) {
		struct tpa_iovec iov[conn->write.budget / MBUF_SIZE + 1];

		if (mbuf_pool_free_count(thread->mbuf_pool) * MBUF_SIZE < conn->write.budget) {
			event_queue_add(conn, TPA_EVENT_OUT);
			break;
		}

		nr_iov = setup_test_data(thread, conn, iov);
		bytes_write = tpa_zwritev(conn->sid, iov, nr_iov);
		if (bytes_write < 0) {
			int err = errno;

			for (i = 0; i < nr_iov; i++)
				iov[i].iov_write_done(iov[i].iov_base, iov[i].iov_param);

			if (err == EAGAIN)
				break;

			return -1;
		}

		on_write_done(conn, bytes_write);
	}

	return 0;
}
