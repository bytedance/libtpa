/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 * Author: Wenlong Luo <luowenlong.linl@bytedance.com>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <string.h>
#include <errno.h>
#include <sched.h>
#include <pthread.h>
#include <unistd.h>

#include "ctrl.h"
#include "log.h"

static int ctrl_thread_create(void *(*func)(void *), void *arg, const char *name)
{
	pthread_t tid;
	int ctrl_cpu = 0;
	cpu_set_t cpuset;

	if (pthread_create(&tid, NULL, func, arg) < 0) {
		LOG_ERR("failed to create ctrl thread: %s", name);
		return -1;
	}

	if (pthread_setname_np(tid, name) < 0)
		LOG_WARN("failed to set thread name: %s", name);

	if (getenv("TPA_CTRL_CPU"))
		ctrl_cpu = atoi(getenv("TPA_CTRL_CPU"));
	CPU_ZERO(&cpuset);
	CPU_SET(ctrl_cpu, &cpuset);

	if (pthread_setaffinity_np(tid, sizeof(cpu_set_t), &cpuset))
		LOG_WARN("failed to bind thread %s to cpu %d", name, ctrl_cpu);

	return 0;
}

static void timeout_event_done(int fd)
{
	uint64_t expirations;
	int ret;

	ret = read(fd, &expirations, sizeof(expirations));
	(void)ret;
}

static int epfd = -1;

#define MAX_EPOLL_EVENT		16

static void *poll_ctrl_event(void *ignored)
{
	struct epoll_event events[MAX_EPOLL_EVENT];
	struct ctrl_event *ctrl_event;
	int i;
	int ret;

	while (1) {
		ret = epoll_wait(epfd, events, MAX_EPOLL_EVENT, -1);

		for (i = 0; i < ret; i++) {
			ctrl_event = events[i].data.ptr;

			if (ctrl_event->timeout_event)
				timeout_event_done(ctrl_event->fd);

			if (ctrl_event->cb)
				ctrl_event->cb(ctrl_event);
		}
	}

	LOG_ERR("tpa ctrl thread quit");
	return NULL;
}

static struct ctrl_event *do_ctrl_event_create(ctrl_event_cb_t cb, void *arg,
					       int timeout_event, const char *name)
{
	struct ctrl_event *ctrl_event;

	ctrl_event = malloc(sizeof(struct ctrl_event));
	if (!ctrl_event) {
		LOG_ERR("failed to malloc ctrl event for %s:%s", name, strerror(errno));
		return NULL;
	}

	ctrl_event->cb = cb;
	ctrl_event->arg  = arg;
	ctrl_event->timeout_event = timeout_event;

	return ctrl_event;
}

static int ctrl_event_register(struct ctrl_event *ctrl_event, const char *name)
{
	struct epoll_event epoll_event;

	epoll_event.events = EPOLLIN;
	epoll_event.data.ptr = (void *)ctrl_event;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, ctrl_event->fd, &epoll_event) != 0) {
		LOG_ERR("ctrl thread epoll ctl fd %d for %s error: %s",
			ctrl_event->fd, name, strerror(errno));
		return -1;
	}

	return 0;
}

static int ctrl_timerfd_create(long seconds)
{
	struct itimerspec time;
	int timerfd;

	timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	if (timerfd == -1) {
		LOG_ERR("failed to create timerfd: %s", strerror(errno));
		return -1;
	}

	time.it_value.tv_sec = seconds;
	time.it_value.tv_nsec = 0;
	time.it_interval.tv_sec = seconds;
	time.it_interval.tv_nsec = 0;
	if (timerfd_settime(timerfd, 0, &time, NULL) != 0) {
		LOG_ERR("failed to set time: %s", strerror(errno));
		close(timerfd);
		return -1;
	}

	return timerfd;
}

struct ctrl_event *ctrl_timeout_event_create(long seconds, ctrl_event_cb_t cb,
					     void *arg, const char *name)
{
	struct ctrl_event *ctrl_event;

	ctrl_event = do_ctrl_event_create(cb, arg, 1, name);
	if (!ctrl_event)
		return NULL;

	ctrl_event->fd   = ctrl_timerfd_create(seconds);
	if (ctrl_event->fd < 0 || ctrl_event_register(ctrl_event, name) == -1) {
		free(ctrl_event);
		return NULL;
	}

	return ctrl_event;
}

struct ctrl_event *ctrl_event_create(int fd, ctrl_event_cb_t cb,
				     void *arg, const char *name)
{
	struct ctrl_event *ctrl_event;

	ctrl_event = do_ctrl_event_create(cb, arg, 0, name);
	if (!ctrl_event)
		return NULL;

	ctrl_event->fd = fd;
	if (ctrl_event_register(ctrl_event, name) == -1) {
		free(ctrl_event);
		return NULL;
	}

	return ctrl_event;
}

void ctrl_event_destroy(struct ctrl_event *ctrl_event)
{
	epoll_ctl(epfd, EPOLL_CTL_DEL, ctrl_event->fd, NULL);

	if (ctrl_event->timeout_event)
		close(ctrl_event->fd);

	free(ctrl_event);
}

int ctrl_init(void)
{
	epfd = epoll_create1(0);
	if (epfd < 0) {
		LOG_ERR("failed to create epoll fd: %s", strerror(errno));
		return -1;
	}

	if (ctrl_thread_create(poll_ctrl_event, NULL, "tpa-ctrl") != 0)
		return -1;

	return 0;
}
