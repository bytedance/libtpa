/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _TPA_IP_
#define _TPA_IP_

#include <stdint.h>

#include <rte_byteorder.h>

#include "api/tpa.h"

static inline int tpa_ip_equal(struct tpa_ip *a, struct tpa_ip *b)
{
	return a->u64[0] == b->u64[0] && a->u64[1] == b->u64[1];
}

static inline int tpa_ip_is_loopback(struct tpa_ip *ip)
{
	if (tpa_ip_is_ipv4(ip))
		return tpa_ip_get_ipv4(ip) == 0x100007f;

	return ip->u64[0] == 0 && ip->u64[1] == 0x100000000000000ull;
}

static inline int in_same_subnet(struct tpa_ip *local, struct tpa_ip *remote,
				 int prefixlen)
{
	uint64_t *a = local->u64;
	uint64_t *b = remote->u64;

	if (prefixlen > 64) {
		if (a[0] != b[0])
			return 0;

		a += 1;
		b += 1;
		prefixlen -= 64;
	}

	return rte_cpu_to_be_64(a[0]) >> (64 - prefixlen) ==
	       rte_cpu_to_be_64(b[0]) >> (64 - prefixlen);
}

static inline int is_ip6_any(struct tpa_ip *ip)
{
	return ip->u64[0] == 0 && ip->u64[1] == 0;
}

#endif
