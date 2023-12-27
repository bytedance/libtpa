/*
 * SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause)
 * Copyright (c) 2024, ByteDance Ltd. and/or its Affiliates
 * Author: Wenlong Luo <luowenlong.linl@bytedance.com>
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>

#include "xdp_common.h"

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 32);
} xsks_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u8);
	__uint(max_entries, 1);
} dst_ip4_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct in6_addr);
	__type(value, __u8);
	__uint(max_entries, 1);
} dst_ip6_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u16);
	__type(value, __u8);
	__uint(max_entries, 65536);
} dst_port_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, XDP_STATS_MAX);
} xdp_stats SEC(".maps");

struct net_ctx {
	__u16 l3_type;
	__u16 l4_type;
	__u16 src_port;
	__u16 dst_port;

	union {
		struct iphdr *ip4;
		struct ipv6hdr *ip6;
	};

	struct tcphdr *tcp;
};

static __always_inline void xdp_stats_add(__u32 type, __u64 cnt)
{
	__u64 *val;

	if (type >= XDP_STATS_MAX)
		return;

	val = bpf_map_lookup_elem(&xdp_stats, &type);
	if (val)
		__sync_fetch_and_add(val, cnt);	
}

static __always_inline void xdp_stats_inc(__u32 type)
{
	xdp_stats_add(type, 1);
}

static __always_inline int xdp_return(int action)
{
	switch (action) {
	case XDP_PASS:
		xdp_stats_inc(XDP_STATS_PASS);
		break;
	case XDP_REDIRECT:
		xdp_stats_inc(XDP_STATS_REDIRECT);
		break;
	default:
		xdp_stats_inc(XDP_STATS_UNEXPECTED_ACTION);
	}

	return action;
}

static __always_inline int parse_net_hdr(void *data, void *data_end, struct net_ctx *net_ctx)
{
	struct ethhdr *eth = data;
	struct iphdr *ip4 = data + sizeof(*eth);
	struct ipv6hdr *ip6 = data + sizeof(*eth);
	__u64 hdr_len = sizeof(*eth);

	if (data + hdr_len > data_end)
		return -XDP_STATS_INVALID_PKT;

	net_ctx->l3_type = bpf_ntohs(eth->h_proto);
	if (net_ctx->l3_type == ETH_P_IP) {
		hdr_len += sizeof(*ip4);
		if (data + hdr_len > data_end)
			return -XDP_STATS_INVALID_PKT;

		net_ctx->l4_type = ip4->protocol;
		net_ctx->ip4 = ip4;
	} else if (net_ctx->l3_type == ETH_P_IPV6) {
		hdr_len += sizeof(*ip6);
		if (data + hdr_len > data_end)
			return -XDP_STATS_INVALID_PKT;

		net_ctx->l4_type = ip6->nexthdr;
		net_ctx->ip6 = ip6;
	} else
		return -XDP_STATS_NOT_IP;

	if (net_ctx->l4_type != IPPROTO_TCP)
		return -XDP_STATS_NOT_TCP;

	net_ctx->tcp = data + hdr_len;
	hdr_len += sizeof(struct tcphdr);
	if (data + hdr_len > data_end)
		return -XDP_STATS_INVALID_PKT;

	net_ctx->src_port = bpf_ntohs(net_ctx->tcp->source);
	net_ctx->dst_port = bpf_ntohs(net_ctx->tcp->dest);

	return 0;
}

static __always_inline int xsks_redirect(__u32 idx)
{
	if (!bpf_map_lookup_elem(&xsks_map, &idx)) {
		xdp_stats_inc(XDP_STATS_NO_XSKS);
		return XDP_PASS;
	}

	return bpf_redirect_map(&xsks_map, idx, 0);
}

SEC("xdp")
int tpaxdp_flow_steering(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct net_ctx net_ctx;
	__u8 *idx;
	int ret;

	ret = parse_net_hdr(data, data_end, &net_ctx);
	if (ret < 0) {
		xdp_stats_inc(-ret);
		goto mismatch;
	}

	if (net_ctx.l3_type == ETH_P_IPV6)
		idx = bpf_map_lookup_elem(&dst_ip6_map, &net_ctx.ip6->daddr);
	else
		idx = bpf_map_lookup_elem(&dst_ip4_map, &net_ctx.ip4->daddr);
	if (!idx) {
		xdp_stats_inc(XDP_STATS_DST_IP_MISMATCH);
		goto mismatch;
	}

	idx = bpf_map_lookup_elem(&dst_port_map, &net_ctx.dst_port);
	if (!idx) {
		xdp_stats_inc(XDP_STATS_DST_PORT_MISMATCH);
		goto mismatch;
	}

	return xdp_return(xsks_redirect(*idx));

mismatch:
	return xdp_return(XDP_PASS);
}

char _license[] SEC("license") = "Dual BSD/GPL";
