/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _SOCK_TABLE_H_
#define _SOCK_TABLE_H_

#include <stdint.h>
#include <sys/queue.h>

#include <rte_spinlock.h>
#include <rte_table_hash_func.h>

struct sock_key {
	struct tpa_ip local_ip;
	struct tpa_ip remote_ip;

	union {
		struct {
			uint16_t local_port;
			uint16_t remote_port;
		};

		uint32_t port;
	};
};

struct sock_entry {
	struct sock_key key;
	struct tcp_sock *tsock;

	TAILQ_ENTRY(sock_entry) node;
};

TAILQ_HEAD(sock_entry_list, sock_entry);

#define SOCK_TABLE_SIZE		4096

struct sock_table {
	rte_spinlock_t lock;

	struct sock_entry_list lists[SOCK_TABLE_SIZE];
};

static inline void sock_key_init(struct sock_key *key,
				 struct tpa_ip *remote_ip, uint16_t remote_port,
				 struct tpa_ip *local_ip, uint16_t local_port)
{
	key->remote_ip = *remote_ip;
	key->remote_port = remote_port;

	key->local_ip = *local_ip;
	key->local_port = local_port;
}

static inline int sock_key_equal(struct sock_key *a, struct sock_key *b)
{
	return tpa_ip_equal(&a->local_ip,  &b->local_ip) &&
	       tpa_ip_equal(&a->remote_ip, &b->remote_ip) &&
	       a->port == b->port;
}

static inline uint32_t sock_hash_idx(struct sock_key *key)
{
	uint64_t hash;

	/* we ignore local ip here as it does not change */
	hash = rte_crc32_u64(key->remote_ip.u64[0] | (uint64_t)key->local_port,
			     key->remote_ip.u64[1] | (uint64_t)key->remote_port);

	RTE_BUILD_BUG_ON((SOCK_TABLE_SIZE & (SOCK_TABLE_SIZE - 1)) != 0);
	return hash & (SOCK_TABLE_SIZE - 1);
}

static inline struct tcp_sock *sock_table_lookup(struct sock_table *table, struct sock_key *key)
{
	struct sock_entry_list *list = &table->lists[sock_hash_idx(key)];
	struct sock_entry *entry;

	TAILQ_FOREACH(entry, list, node) {
		if (sock_key_equal(&entry->key, key))
			return entry->tsock;
	}

	return NULL;
}

static inline int sock_table_add(struct sock_table *table, struct sock_key *key, struct tcp_sock *tsock)
{
	struct sock_entry_list *list = &table->lists[sock_hash_idx(key)];
	struct sock_entry *entry;

	if (sock_table_lookup(table, key))
		return -1;

	entry = malloc(sizeof(struct sock_entry));
	if (!entry)
		return -1;

	entry->key = *key;
	entry->tsock = tsock;
	TAILQ_INSERT_TAIL(list, entry, node);

	return 0;
}

static inline int sock_table_del(struct sock_table *table, struct sock_key *key)
{
	struct sock_entry_list *list = &table->lists[sock_hash_idx(key)];
	struct sock_entry *entry;

	TAILQ_FOREACH(entry, list, node) {
		if (sock_key_equal(&entry->key, key)) {
			TAILQ_REMOVE(list, entry, node);
			free(entry);

			return 0;
		}
	}

	return -1;
}

static inline void sock_table_init(struct sock_table *table)
{
	int i;

	rte_spinlock_init(&table->lock);

	for (i = 0; i < SOCK_TABLE_SIZE; i++)
		TAILQ_INIT(&table->lists[i]);
}

/*
 * here goes the lock version
 */

static inline struct tcp_sock *sock_table_lookup_lock(struct sock_table *table, struct sock_key *key)
{
	struct tcp_sock *tsock;

	rte_spinlock_lock(&table->lock);
	tsock = sock_table_lookup(table, key);
	rte_spinlock_unlock(&table->lock);

	return tsock;
}

static inline int sock_table_add_lock(struct sock_table *table, struct sock_key *key, struct tcp_sock *tsock)
{
	int ret;

	rte_spinlock_lock(&table->lock);
	ret = sock_table_add(table, key, tsock);
	rte_spinlock_unlock(&table->lock);

	return ret;
}

static inline int sock_table_del_lock(struct sock_table *table, struct sock_key *key)
{
	int ret;

	rte_spinlock_lock(&table->lock);
	ret = sock_table_del(table, key);
	rte_spinlock_unlock(&table->lock);

	return ret;
}

#endif
