/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _OFFLOAD_H_
#define _OFFLOAD_H_

#include <sys/queue.h>

#include <rte_flow.h>

#define OFFLOAD_NAME_SIZE		256

struct offload {
	int port;
	struct rte_flow *flow;

	TAILQ_ENTRY(offload) node;
};

struct offload_list {
	char *name;

	TAILQ_HEAD(, offload) head;
};

static inline void offload_list_init(struct offload_list *list)
{
	TAILQ_INIT(&list->head);
	list->name = NULL;
}


int offload_init(void);

int tsock_offload_create(struct tcp_sock *tsock);
void tsock_offload_destroy(struct tcp_sock *tsock);

struct port_block;
int port_block_offload_create(struct port_block *block);
void port_block_offload_destroy(struct port_block *block);

#endif
