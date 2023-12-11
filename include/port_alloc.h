/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _PORT_ALLOC_H_
#define _PORT_ALLOC_H_

#include "cfg.h"
#include "ip.h"
#include "sock_table.h"
#include "offload.h"
#include "timer.h"

/* TODO: make it configurable */
#define DEFAULT_PORT_BLOCK_SIZE		64
#define DEFAULT_PORT_BLOCK_MASK		(64 - 1)

#define MAX_PORT_BLOCK_PER_WORKER	((1<<16) / DEFAULT_PORT_BLOCK_SIZE)

struct tpa_worker;
struct port_block {
	uint16_t start;
	uint16_t end;
	uint16_t size;
	uint16_t mask;
	int refcnt;

	uint16_t port_mask;
	struct tpa_worker *worker;

	struct offload_list offload_list;
	struct timer timer;
};

int local_port_range_set(struct cfg_spec *spec, const char *val);
int local_port_range_get(struct cfg_spec *spec, char *val);
void port_alloc_init(void);
int port_block_offload_create(struct port_block *block);

struct tcp_sock;
uint16_t port_bind(struct tpa_worker *worker, struct sock_key *key, struct tcp_sock *tsock);
int port_unbind(struct tpa_worker *worker, struct sock_key *key);

uint16_t port_alloc(uint16_t port);
int port_free(uint16_t port);

#endif
