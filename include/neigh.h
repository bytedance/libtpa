/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _NEIGH_H_
#define _NEIGH_H_

#include <rte_ether.h>

#include "tpa.h"
#include "worker.h"
#include "ip.h"

#define NEIGH_QUEUE_LEN		1024

#define ND_SKIP		-2

/*
 * TODO: get rid of the count limit and use hash for search
 */
#define MAX_NEIGH_ENTRY	512

struct neigh_entry {
	struct tpa_ip ip;
	struct rte_ether_addr mac;

	uint64_t last_update;
};

struct neigh_ops {
	int (*nd_init)(void);
	int (*nd_solicit)(struct tpa_ip *ip, struct tpa_worker *worker);
	int (*nd_solicit_by_socket)(int fd, struct tpa_ip *ip);
	int (*nd_handle_reply)(uint8_t *packet, size_t len);
};

void neigh_init(void);
int neigh_wait_enqueue(struct packet *pkt);
int neigh_flush(struct tpa_worker *worker);
void neigh_update(struct tpa_ip *ip, uint8_t *mac);
void neigh_handle_reply(struct tpa_ip *ip, uint8_t *mac);
struct neigh_entry *neigh_find(struct tpa_ip *ip);
struct neigh_entry *neigh_lookup(struct tpa_worker *worker, struct tpa_ip *ip);
int eth_lookup(struct tpa_worker *worker, struct tpa_ip *ip, struct rte_ether_hdr *eth);
int get_neigh_cache_len(void);

struct shell_buf;
void neigh_dump(struct shell_buf *reply);

/* XXX: this probably should be reworked with callback */
void flush_tcp_packet(struct packet *pkt, int err);

static inline struct neigh_entry *neigh_find_ip4(uint32_t ip4)
{
	struct tpa_ip ip;

	return neigh_find(tpa_ip_set_ipv4(&ip, ip4));
}

/* arp.c */
int arp_input(struct tpa_worker *worker, struct packet *pkt);
int arp_handle_reply(uint8_t *packet, size_t len);
extern const struct neigh_ops arp_ops;


/* ndp.c */
extern const struct neigh_ops ndp_ops;
int ndp_handle_reply(uint8_t *packet, size_t len);

#endif
