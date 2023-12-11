/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022, ByteDance Ltd. and/or its Affiliates
 * Author: Wenlong Luo <luowenlong.linl@bytedance.com>
 */
#ifndef _CTRL_H_
#define _CTRL_H_

struct ctrl_event;
typedef void *(*ctrl_event_cb_t)(struct ctrl_event *event);

struct ctrl_event {
	int fd;
	int timeout_event;

	ctrl_event_cb_t cb;
	void *arg;
};

struct ctrl_event *ctrl_timeout_event_create(long seconds, ctrl_event_cb_t cb,
					     void *arg, const char *name);
struct ctrl_event *ctrl_event_create(int fd, ctrl_event_cb_t cb,
				     void *arg, const char *name);
void ctrl_event_destroy(struct ctrl_event *ctrl_event);

int ctrl_init(void);


#endif
