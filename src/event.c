/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <stdint.h>

#include "api/tpa.h"
#include "worker.h"
#include "sock.h"

int tpa_event_ctrl(int sid, int op, struct tpa_event *event)
{
	struct tcp_sock *tsock;

	tsock = tsock_get_by_sid(sid);
	if (!tsock) {
		errno = EINVAL;
		return -1;
	}

	if (op == TPA_EVENT_CTRL_DEL) {
		tsock->interested_events = 0;
	} else {
		tsock->event.data = event->data;
		tsock->interested_events = event->events | TPA_EVENT_HUP | TPA_EVENT_ERR;

		/* if we already got events, fire them now. Or should we not? */
		if (tsock->event.events)
			tsock_event_add(tsock, tsock->event.events);
	}

	return 0;
}

int tpa_event_poll(struct tpa_worker *worker, struct tpa_event *events, int max)
{
	struct tcp_sock *tsock;
	uint32_t events_to_report;
	int nr_event = 0;

	while (nr_event < max) {
		tsock = FLEX_FIFO_POP_ENTRY(worker->event_queue, struct tcp_sock, event_node);
		if (!tsock)
			break;

		if (tsock->close_issued)
			continue;

		if (tsock->sid < 0)
			continue;

		events_to_report = tsock->event.events & tsock->interested_events;
		tsock->event.events &= ~events_to_report;
		if (events_to_report == 0)
			continue;

		events[nr_event].events = events_to_report;
		events[nr_event].data   = tsock->event.data;
		nr_event += 1;
	}

	worker->cycles.last_poll = worker->cycles.start;

	return nr_event;
}
