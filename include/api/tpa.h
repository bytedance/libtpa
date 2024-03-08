/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _TPA_API_H_
#define _TPA_API_H_

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TPA_EVENT_IN			0x1
#define TPA_EVENT_OUT		0x4
#define TPA_EVENT_ERR		0x8
#define TPA_EVENT_HUP		0x10

#define TPA_EVENT_CTRL_ADD		1
#define TPA_EVENT_CTRL_DEL		2
#define TPA_EVENT_CTRL_MOD		3

struct tpa_event {
	uint32_t events;
	void *data;
};

struct tpa_iovec {
	void    *iov_base;
	uint64_t iov_phys;
	uint32_t iov_len;
	uint32_t iov_reserved;
	void    *iov_param;
	union {
		void (*iov_read_done)(void *iov_base, void *iov_param);
		void (*iov_write_done)(void *iov_base, void *iov_param);
	};
};


/*
 * Provides extra options for socks going to be created by
 * tpa_connect_to and tpa_listen_on.
 */
struct tpa_sock_opts {
	/*
	 * When @listen_scaling is set to
	 * - 0: passive connections will be only distributed to the worker
	 *      where this listen sock has been bound to.
	 * - 1: passive connections will be distributed to all workers.
	 *
	 * tpa_listen_on only.
	 */
	uint64_t listen_scaling:1;
	uint64_t bits_reserved:63;

	/*
	 * A private data set by user for listen sock. It could be
	 * retrieved by tpa_sock_info_get when a new sock is accepted.
	 *
	 * tpa_listen_on only.
	 */
	void *data;

	/*
	 * Specifies a local port to bind to.
	 *
	 * tpa_connect_to only.
	 */
	uint16_t local_port;
	uint8_t reserved[128 - 18];  /* XXX: it's ugly */
} __attribute__((packed));

struct tpa_ip {
	union {
		uint8_t  u8[16];
		uint32_t u32[4];
		uint64_t u64[2];
	};
};

struct tpa_sock_info {
	struct tpa_worker *worker;

        /* it's the tpa_sock_opts.data set by user */
	void *data;

	struct tpa_ip local_ip;
	struct tpa_ip remote_ip;
	uint16_t local_port;
	uint16_t remote_port;

	uint8_t reserved[76];
};

static inline int tpa_ip_is_ipv4(const struct tpa_ip *ip)
{
	return ip->u64[0] == 0 && ip->u32[2] == 0xffff0000;
}

static inline struct tpa_ip *tpa_ip_set_ipv4(struct tpa_ip *ip, const uint32_t ip4)
{
	ip->u64[0] = 0;
	ip->u32[2] = 0xffff0000;
	ip->u32[3] = ip4;

	return ip;
}

static inline uint32_t tpa_ip_get_ipv4(const struct tpa_ip *ip)
{
	return ip->u32[3];
}

static inline struct tpa_ip *tpa_ip_set_ipv6(struct tpa_ip *ip, const uint8_t *ip6)
{
	memcpy(ip->u8, ip6, sizeof(*ip));

	return ip;
}

static inline struct tpa_ip *tpa_ip_from_str(struct tpa_ip *ip, const char *str)
{
	uint32_t ip4;

	if (inet_pton(AF_INET6, str, ip) == 1)
		return ip;

	if (inet_pton(AF_INET, str, &ip4) == 1)
		return tpa_ip_set_ipv4(ip, ip4);

	return NULL;
}

static inline const char *tpa_ip_to_str(const struct tpa_ip *ip, char *buf, size_t size)
{
	if (tpa_ip_is_ipv4(ip))
		return inet_ntop(AF_INET, &ip->u32[3], buf, size);
	else
		return inet_ntop(AF_INET6, ip->u8, buf, size);
}

int tpa_init(int nr_worker);

struct tpa_worker;
struct tpa_worker *tpa_worker_init(void);
void tpa_worker_run(struct tpa_worker *worker);

int tpa_connect_to(const char *server, uint16_t port, const struct tpa_sock_opts *opts);
int tpa_listen_on(const char *local, uint16_t port, const struct tpa_sock_opts *opts);
int tpa_accept_burst(struct tpa_worker *worker, int *sid, int nr_sid);
int tpa_sock_info_get(int sid, struct tpa_sock_info *info);
void tpa_close(int sid);

ssize_t tpa_zreadv(int sid, struct tpa_iovec *iov, int nr_iov);
ssize_t tpa_zwritev(int sid, const struct tpa_iovec *iov, int nr_iov);
ssize_t tpa_write(int sid, const void *buf, size_t count);

int tpa_event_ctrl(int sid, int op, struct tpa_event *event);
int tpa_event_poll(struct tpa_worker *worker, struct tpa_event *events, int max);

struct tpa_memseg {
	void    *virt_addr;
	uint64_t phys_addr;
	size_t   size;
	uint32_t page_size;
};

struct tpa_memseg *tpa_memsegs_get(void);
int tpa_extmem_register(void *virt_addr, size_t len, uint64_t *phys_addrs,
			   int nr_page, size_t page_size);
int tpa_extmem_unregister(void *virt_addr, size_t len);

#ifdef __cplusplus
}
#endif

#endif
