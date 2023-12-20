/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 * Author: Kai Xiong <xiongkai.123@bytedance.com>
 */
#include <stdio.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <fcntl.h>

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>

#include "tpa.h"
#include "lib/utils.h"
#include "log.h"
#include "dev.h"
#include "shell.h"
#include "packet.h"
#include "neigh.h"
#include "ctrl.h"

struct neigh_cache {
	int nr_neigh;
	int accept_garp;
	struct neigh_entry *gw_neigh;
	struct neigh_entry *gw6_neigh;
	struct neigh_entry neigh_entries[MAX_NEIGH_ENTRY];

	struct rte_ring *neigh_waiting_queue;
	rte_spinlock_t lock;
};

static struct neigh_cache neigh_cache = {
	.lock = RTE_SPINLOCK_INITIALIZER,
};

#define NR_NEIGH_IMPL		2

struct neigh_impl {
	const char *name;
	const struct neigh_ops *ops;
	int fd;
	int stats_code;
	int err_stats_code;

	uint64_t rx_pkts;
	uint64_t tx_pkts;
};

static struct neigh_impl neigh_impl[NR_NEIGH_IMPL]  = {
	{ "arp", &arp_ops, -1, ARP_SOLICIT, ERR_ARP_SOLICIT, 0, 0 },
	{ "ndp", &ndp_ops, -1, NDP_SOLICIT, ERR_NDP_SOLICIT, 0, 0 },
};

int get_neigh_cache_len(void)
{
	return neigh_cache.nr_neigh;
}

static struct neigh_entry *neigh_find_locked(struct tpa_ip *ip)
{
	struct neigh_entry *entry;
	int i;

	for (i = 0; i < neigh_cache.nr_neigh; i++) {
		entry = &neigh_cache.neigh_entries[i];

		if (tpa_ip_equal(&entry->ip, ip))
			return entry;
	}

	return NULL;
}

struct neigh_entry *neigh_find(struct tpa_ip *ip)
{
	struct neigh_entry *entry;

	rte_spinlock_lock(&neigh_cache.lock);
	entry = neigh_find_locked(ip);
	rte_spinlock_unlock(&neigh_cache.lock);

	return entry;
}

/* lock required */
static int neigh_evict(struct neigh_entry *evicted)
{
	struct neigh_entry *entry;
	int idx;

	do {
		idx = rand() % neigh_cache.nr_neigh;
		entry = &neigh_cache.neigh_entries[idx];
	} while (entry == neigh_cache.gw_neigh || entry == neigh_cache.gw6_neigh);

	*evicted = *entry;

	return idx;
}

/* lock required */
static void neigh_add(struct tpa_ip *ip, uint8_t *mac, struct neigh_entry *evicted)
{
	int idx = neigh_cache.nr_neigh;

	if (idx == MAX_NEIGH_ENTRY)
		idx = neigh_evict(evicted);

	neigh_cache.neigh_entries[idx].ip = *ip;
	memcpy(neigh_cache.neigh_entries[idx].mac.addr_bytes, mac, RTE_ETHER_ADDR_LEN);
	neigh_cache.neigh_entries[idx].last_update = rte_rdtsc();

	if (neigh_cache.nr_neigh < MAX_NEIGH_ENTRY)
		neigh_cache.nr_neigh += 1;
}

enum {
	NEIGH_NONE,
	NEIGH_ADD,
	NEIGH_UPDATE
};

void neigh_update(struct tpa_ip *ip, uint8_t *mac)
{
	struct neigh_entry *entry;
	struct neigh_entry evicted;
	char ip_str[INET6_ADDRSTRLEN];
	int op = NEIGH_NONE;

	tpa_ip_to_str(ip, ip_str, sizeof(ip_str));
	if (memcmp(mac, "\x00\x00\x00\x00\x00\x00", 6) == 0) {
		LOG_WARN("skip zero-mac update for ip %s", ip_str);
		return;
	}

	memset(&evicted, 0, sizeof(evicted));
	rte_spinlock_lock(&neigh_cache.lock);
	entry = neigh_find_locked(ip);
	if (!entry) {
		neigh_add(ip, mac, &evicted);
		op = NEIGH_ADD;
	} else {
		if (memcmp(entry->mac.addr_bytes, mac, RTE_ETHER_ADDR_LEN) != 0) {
			memcpy(entry->mac.addr_bytes, mac, RTE_ETHER_ADDR_LEN);
			op = NEIGH_UPDATE;
			entry->last_update = rte_rdtsc();
		}
	}
	rte_spinlock_unlock(&neigh_cache.lock);

	if (tpa_ip_is_ipv4(ip)) {
		if (tpa_ip_get_ipv4(ip) == dev.gw4)
			neigh_cache.gw_neigh = entry;
	} else {
		if (tpa_ip_equal(ip, &dev.gw6.ip))
			neigh_cache.gw6_neigh = entry;
	}

	if (op == NEIGH_NONE)
		return;

	/* do log outside spin lock */
	LOG("NEIGH %s: %s\t"MAC_FMT, op == NEIGH_ADD ? "add" : "update",
	    ip_str, MAC_ARGS(mac));

	if (evicted.ip.u64[0] | evicted.ip.u64[1]) {
		LOG("NEIGH evict: %s\t"MAC_FMT,
		    tpa_ip_to_str(&evicted.ip, ip_str, sizeof(ip_str)),
		    MAC_ARGS(mac));
	}
}

static inline int invalid_entry(struct neigh_entry *entry)
{
	return entry == NULL || rte_is_zero_ether_addr(&entry->mac);
}

static struct tpa_ip neigh_target_ip(struct tpa_ip *ip)
{
	struct tpa_ip ret;

	if (tpa_ip_is_ipv4(ip)) {
		if ((tpa_ip_get_ipv4(ip) & dev.mask) != (dev.ip4 & dev.mask))
			tpa_ip_set_ipv4(&ret, dev.gw4);
		else
			ret = *ip;
	} else {
		if (in_same_subnet(&dev.ip6.ip, ip, dev.ip6.prefixlen))
			ret = *ip;
		else
			ret = dev.gw6.ip;
	}

	return ret;
}

static struct neigh_entry *do_neigh_lookup(struct tpa_worker *worker, struct tpa_ip *ip)
{
	struct neigh_entry *entry = NULL;
	struct neigh_entry evicted;
	uint8_t mac[6] = { 0, };

	entry = neigh_find(ip);
	if (invalid_entry(entry)) {
		if (!entry) {
			rte_spinlock_lock(&neigh_cache.lock);
			neigh_add(ip, mac, &evicted);
			rte_spinlock_unlock(&neigh_cache.lock);
		}

		return NULL;
	}

	return entry;
}

struct neigh_entry *neigh_lookup(struct tpa_worker *worker, struct tpa_ip *ip)
{
	struct neigh_entry *entry;
	struct tpa_ip target_ip;

	target_ip = neigh_target_ip(ip);

	entry = do_neigh_lookup(worker, &target_ip);
	if (!entry) {
		struct neigh_impl *impl = &neigh_impl[!tpa_ip_is_ipv4(&target_ip)];
		int ret;

		ret = impl->ops->nd_solicit(&target_ip, worker);
		if (ret == 0) {
			WORKER_STATS_INC(worker, impl->stats_code);
		} else {
			WORKER_STATS_INC(worker, -ret);
			WORKER_STATS_INC(worker, impl->err_stats_code);
		}
	}

	return entry;
}

int eth_lookup(struct tpa_worker *worker, struct tpa_ip *ip, struct rte_ether_hdr *eth)
{
	struct neigh_entry *entry;

	rte_ether_addr_copy(&dev.mac, ETH_SRC_ADDR(eth));
	eth->ether_type = htons(tpa_ip_is_ipv4(ip) ? RTE_ETHER_TYPE_IPV4 : RTE_ETHER_TYPE_IPV6);

	entry = neigh_lookup(worker, ip);
	if (entry) {
		rte_ether_addr_copy(&entry->mac, ETH_DST_ADDR(eth));
		return 0;
	}

	memset(ETH_DST_ADDR(eth), 0, RTE_ETHER_ADDR_LEN);

	return -1;
}

static int do_neigh_wait_enqueue(struct packet *pkt)
{
	return rte_ring_enqueue(neigh_cache.neigh_waiting_queue, pkt) == 0 ?
	       0 : -ERR_NEIGH_ENQUEUE;
}

static inline int stale_tsock(struct tcp_sock *tsock)
{
	return tsock->sid < 0 || tsock->state == TCP_STATE_CLOSED;
}

static void try_drop_stale_neigh_request(void)
{
	struct packet *pkts[NEIGH_QUEUE_LEN];
	uint32_t nr_pkt;
	uint32_t i;

	nr_pkt = rte_ring_dequeue_burst(neigh_cache.neigh_waiting_queue, (void **)pkts,
					NEIGH_QUEUE_LEN, NULL);

	/* FIXME: it's not efficient */
	for(i = 0; i < nr_pkt; i++) {
		if (!stale_tsock(pkts[i]->tsock))
			do_neigh_wait_enqueue(pkts[i]);
	}
}

int neigh_wait_enqueue(struct packet *pkt)
{
	if (do_neigh_wait_enqueue(pkt) == 0)
		return 0;

	/* try to make some room for this new request */
	try_drop_stale_neigh_request();
	return do_neigh_wait_enqueue(pkt);
}

int neigh_flush(struct tpa_worker *worker)
{
	struct packet *pkt;
	uint32_t i;
	int ret;

	for(i = 0; i < BATCH_SIZE; i++) {
		pkt = FLEX_FIFO_POP_ENTRY_LOCK(worker->neigh_flush_queue, struct packet, neigh_node);
		if (!pkt)
			break;

		if (pkt->flags & PKT_FLAG_STALE_NEIGH) {
			packet_free(pkt);
			continue;
		}

		ret = dev_port_txq_enqueue(0, worker->queue, pkt);

		/* it should be always true; as we only support TCP */
		if (pkt->tsock)
			flush_tcp_packet(pkt, ret);

		if (unlikely(ret < 0)) {
			WORKER_STATS_INC(worker, -ret);
			packet_free(pkt);
		}
	}

	return i;
}

/*
 * check to see if an NEIGH response could fill a mac of pkts in
 * in the neigh wait queue. If so, fill it and queue it to the worker
 * neigh_flush_queue. The worker then will flush the queue by queuing
 * them to the dev txq (to send them out wire).
 */
static void check_neigh_wait_queue(void)
{
	struct neigh_entry *entry;
	struct tcp_sock *tsock;
	struct packet *pkts[NEIGH_QUEUE_LEN];
	struct tpa_ip ip;
	uint32_t nr_pkt;
	uint32_t i;

	nr_pkt = rte_ring_dequeue_burst(neigh_cache.neigh_waiting_queue, (void **)pkts,
					NEIGH_QUEUE_LEN, NULL);
	for(i = 0; i < nr_pkt; i++) {
		tsock = pkts[i]->tsock;

		/* simply drop stale neigh request */
		if (stale_tsock(tsock)) {
			/*
			 * We can't free it here (the neigh thread).
			 * here we add a mark and free it later (in
			 * worker thread).
			 */
			pkts[i]->flags |= PKT_FLAG_STALE_NEIGH;
			goto push;
		}

		ip = neigh_target_ip(&tsock->remote_ip);
		entry = do_neigh_lookup(NULL, &ip);
		if (invalid_entry(entry)) {
			/* enqueue it back */
			do_neigh_wait_enqueue(pkts[i]);
			continue;
		}

		rte_ether_addr_copy(&entry->mac, rte_pktmbuf_mtod(&pkts[i]->mbuf, struct rte_ether_addr *));
		rte_ether_addr_copy(&entry->mac, ETH_DST_ADDR(&tsock->net_hdr.eth));

	push:
		flex_fifo_push(tsock->worker->neigh_flush_queue, &pkts[i]->neigh_node);
	}
}

void neigh_handle_reply(struct tpa_ip *ip, uint8_t *mac)
{
	struct neigh_entry *entry;

	/* we ignore gratuitous ARP responses unless asked to */
	entry = neigh_find(ip);
	if (entry || neigh_cache.accept_garp)
		neigh_update(ip, mac);

	if (entry)
		check_neigh_wait_queue();
}

static int set_nonblock(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1)
		return -1;

	flags |= O_NONBLOCK;

	return fcntl(fd, F_SETFL, flags);
}

static void *neigh_recv(struct ctrl_event *event)
{
	struct neigh_impl *impl = event->arg;
	struct sockaddr saddr;
	socklen_t saddr_size;
	uint8_t packet[2000];
	int ret;

	while (1) {
		saddr_size = sizeof(saddr);
		ret = recvfrom(impl->fd, packet, sizeof(packet), 0, &saddr, &saddr_size);
		if (ret < 0) {
			if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
				break;

			LOG_ERR("failed to recv neigh response: %s", strerror(errno));
			break;
		}

		impl->ops->nd_handle_reply(packet, ret);
		impl->rx_pkts += 1;
	}

	return NULL;
}

#define SOLICIT_TIMEOUT		30

static void *neigh_solicit(struct ctrl_event *event)
{
	struct neigh_entry *entry;
	struct neigh_impl *impl;
	uint64_t now = rte_rdtsc();
	int i;

	for (i = 0; i < neigh_cache.nr_neigh; i++) {
		entry = &neigh_cache.neigh_entries[i];
		if (TSC_TO_US(now - entry->last_update) > SOLICIT_TIMEOUT * 1000000) {
			impl = &neigh_impl[!tpa_ip_is_ipv4(&entry->ip)];
			impl->ops->nd_solicit_by_socket(impl->fd, &entry->ip);
			impl->tx_pkts++;
		}
	}

	return NULL;
}

static void neigh_impl_init(void)
{
	struct neigh_impl *impl;
	int fd;
	int i;

	for (i = 0; i < NR_NEIGH_IMPL; i++) {
		impl = &neigh_impl[i];

		LOG("neighbor init: %s", impl->name);
		fd = impl->ops->nd_init();
		if (fd == ND_SKIP)
			continue;

		if (fd < 0) {
			LOG_ERR("failed to create poll socket for %s: %s",
				impl->name, strerror(errno));
			continue;
		}

		if (set_nonblock(fd) < 0) {
			LOG_ERR("failed to set nonblock for fd %d: %s", fd, strerror(errno));
			continue;
		}

		impl->fd = fd;
		ctrl_event_create(fd, neigh_recv, impl, impl->name);
	}
	ctrl_timeout_event_create(SOLICIT_TIMEOUT, neigh_solicit, NULL, "neigh-solicit");
}

static void neigh_queue_init(void)
{
	struct rte_ring *ring;
	char name[48];

	tpa_snprintf(name, sizeof(name), "neigh_waiting_ring");
	ring = rte_ring_create(name, NEIGH_QUEUE_LEN, rte_socket_id(), 0);

	PANIC_ON(ring == NULL, "failed to create ring %s", name);
	neigh_cache.neigh_waiting_queue = ring;
}

void neigh_dump(struct shell_buf *reply)
{
	struct neigh_entry *entry;
	char buf[INET6_ADDRSTRLEN];
	size_t i;

	for(i = 0; i < neigh_cache.nr_neigh; i++) {
		entry = &neigh_cache.neigh_entries[i];

		shell_append_reply(reply, "%s\t" MAC_FMT "\n",
				   tpa_ip_to_str(&entry->ip, buf, sizeof(buf)),
				   MAC_ARGS(entry->mac.addr_bytes));
	}
}

static int cmd_neigh(struct shell_cmd_info *cmd)
{
	neigh_dump(cmd->reply);

	if (cmd->argc == 1 && strcmp(cmd->argv[0], "-s") == 0) {
		shell_append_reply(cmd->reply,
				   "---\n"
				   "ARP.rx_pkts: %lu\n"
				   "ARP.tx_pkts: %lu\n"
				   "NDP.rx_pkts: %lu\n"
				   "NDP.tx_pkts: %lu\n",
				   neigh_impl[0].rx_pkts,
				   neigh_impl[0].tx_pkts,
				   neigh_impl[1].rx_pkts,
				   neigh_impl[1].tx_pkts);
	}

	return 0;
}

static const struct shell_cmd neigh = {
	.name    = "neigh",
	.handler = cmd_neigh,
};

void neigh_init(void)
{
	neigh_queue_init();
	shell_register_cmd(&neigh);

	neigh_impl_init();

	if (getenv("TPA_ARP_ACCEPT_GARP"))
		neigh_cache.accept_garp = 1;
}
