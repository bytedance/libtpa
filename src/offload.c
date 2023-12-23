/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <assert.h>

#include <rte_flow.h>

#include "lib/utils.h"
#include "log.h"
#include "sock.h"
#include "worker.h"
#include "cfg.h"
#include "offload.h"

/*
 * XXX: note that we do not support ip fragments.
 */

#define MAX_FLOW_PATTERN	8
#define MAX_FLOW_ACTION		8

struct flow_patterns {
	int cnt;
	struct rte_flow_item items[MAX_FLOW_PATTERN];;
};

struct flow_actions {
	int cnt;
	struct rte_flow_action actions[MAX_FLOW_ACTION];
};

struct offload_rule;
struct offload_ctx {
	struct offload_rule *rule;
	int is_ipv6;

	struct rte_flow_error error;

	struct rte_flow_attr attr;
	struct flow_patterns patterns;
	struct flow_actions  actions;

	struct rte_flow_item_ipv4 ip_spec;
	struct rte_flow_item_ipv4 ip_mask;

	struct rte_flow_item_ipv6 ip6_spec;
	struct rte_flow_item_ipv6 ip6_mask;

	struct rte_flow_item_tcp tcp_spec;
	struct rte_flow_item_tcp tcp_mask;

	struct rte_flow_action_mark mark;
	struct rte_flow_action_rss rss;
	struct rte_flow_action_queue queue;
	struct rte_flow_action_ethdev port_rep;

	/* FIXME: assumes no more than 256 workers */
	uint16_t queue_idx[256];
};

struct offload_rule {
	/*
	 * match
	 */
	uint16_t has_proto:1;
	uint16_t has_src_ip:1;
	uint16_t has_dst_ip:1;
	uint16_t has_src_port:1;
	uint16_t has_dst_port:1;
	uint16_t has_dst_port_mask:1;

	uint8_t proto;
	struct tpa_ip src_ip;
	struct tpa_ip dst_ip;

	uint16_t src_port;
	uint16_t dst_port;
	uint16_t dst_port_mask;


	/*
	 * action
	 */
	uint16_t has_rss:1;
	uint16_t has_rss_types:1;
	uint16_t has_queue:1;
	uint16_t has_mark:1;

	uint64_t rss_types;
	uint16_t queue;
	uint32_t mark;
};

#define OFFLOAD_SET(p, field, val)		do {	\
	(p)->has_##field = 1;				\
	(p)->field = val;				\
} while (0)

struct offload_cfg {
	uint32_t enable_flow_mark;
	uint32_t enable_sock_offload;
	uint32_t enable_port_block_offload;
};

static struct offload_cfg offload_cfg = {
	.enable_flow_mark = 1,
	.enable_sock_offload = 0,
	.enable_port_block_offload = 1,
};

static struct cfg_spec offload_cfg_specs[] = {
	{
		.name	  = "offload.flow_mark",
		.type     = CFG_TYPE_UINT,
		.data     = &offload_cfg.enable_flow_mark,
	}, {
		.name	  = "offload.sock_offload",
		.type     = CFG_TYPE_UINT,
		.data     = &offload_cfg.enable_sock_offload,
		.flags    = CFG_FLAG_RDONLY,
	}, {
		.name	  = "offload.port_block_offload",
		.type     = CFG_TYPE_UINT,
		.data     = &offload_cfg.enable_port_block_offload,
		.flags    = CFG_FLAG_RDONLY,
	},
};

static void dump_flow_attr(const struct rte_flow_attr *attr)
{
	LOG_DEBUG("attributes: ingress=%d, egress=%d, prio=%d, group=%d, transfer=%d",
		  attr->ingress, attr->egress, attr->priority, attr->group,
		  attr->transfer);
}

static void dump_flow_pattern(const struct rte_flow_item *item)
{
	if (item->type == RTE_FLOW_ITEM_TYPE_ETH) {
		const struct rte_flow_item_eth *eth_spec = item->spec;
		const struct rte_flow_item_eth *eth_mask = item->mask;

		LOG_DEBUG("rte flow eth pattern:");
		if (eth_spec)
			LOG_DEBUG("  spec = non-null");
		else
			LOG_DEBUG("  spec = null");

		if (eth_mask)
			LOG_DEBUG("  mask = non-null");
		else
			LOG_DEBUG("  mask = null");
	} else if (item->type == RTE_FLOW_ITEM_TYPE_IPV4) {
		const struct rte_flow_item_ipv4 *ipv4_spec = item->spec;
		const struct rte_flow_item_ipv4 *ipv4_mask = item->mask;

		LOG_DEBUG("rte flow ipv4 pattern:");
		if (ipv4_spec) {
			LOG_DEBUG("  spec: tos=0x%hhx ttl=%hhx proto=%hhu "
				  "src="IP_FMT", dst="IP_FMT,
				  ipv4_spec->hdr.type_of_service,
				  ipv4_spec->hdr.time_to_live,
				  ipv4_spec->hdr.next_proto_id,
				  IP_ARGS(ipv4_spec->hdr.src_addr),
				  IP_ARGS(ipv4_spec->hdr.dst_addr));
		} else {
			LOG_DEBUG("  spec = null");
		}
		if (ipv4_mask) {
			LOG_DEBUG("  mask: tos=0x%hhx ttl=0x%hhx proto=0x%hhx "
				  "src="IP_FMT", dst="IP_FMT,
				  ipv4_mask->hdr.type_of_service,
				  ipv4_mask->hdr.time_to_live,
				  ipv4_mask->hdr.next_proto_id,
				  IP_ARGS(ipv4_mask->hdr.src_addr),
				  IP_ARGS(ipv4_mask->hdr.dst_addr));
		} else {
			LOG_DEBUG("  mask = null");
		}
	} else if (item->type == RTE_FLOW_ITEM_TYPE_IPV6) {
		const struct rte_flow_item_ipv6 *ip6_spec = item->spec;
		const struct rte_flow_item_ipv6 *ip6_mask = item->mask;
		char src[INET6_ADDRSTRLEN];
		char dst[INET6_ADDRSTRLEN];

		LOG_DEBUG("rte flow ipv6 pattern:");
		if (ip6_spec) {
			inet_ntop(AF_INET6, ip6_spec->hdr.src_addr, src, INET6_ADDRSTRLEN);
			inet_ntop(AF_INET6, ip6_spec->hdr.dst_addr, dst, INET6_ADDRSTRLEN);
			LOG_DEBUG("  spec: vtc_flow=%u proto=%hhu src=%s, dst=%s ",
				  ip6_spec->hdr.vtc_flow, ip6_spec->hdr.proto,
				  src, dst);
		} else {
			LOG_DEBUG("  spec = null");
		}
		if (ip6_mask) {
			inet_ntop(AF_INET6, ip6_mask->hdr.src_addr, src, INET6_ADDRSTRLEN);
			inet_ntop(AF_INET6, ip6_mask->hdr.dst_addr, dst, INET6_ADDRSTRLEN);
			LOG_DEBUG("  mask: vtc_flow=%u proto=%hhu src=%s, dst=%s ",
				  ip6_mask->hdr.vtc_flow, ip6_mask->hdr.proto,
				  src, dst);
		} else {
			LOG_DEBUG("  mask = null");
		}
	} else if (item->type == RTE_FLOW_ITEM_TYPE_UDP) {
		const struct rte_flow_item_udp *udp_spec = item->spec;
		const struct rte_flow_item_udp *udp_mask = item->mask;

		LOG_DEBUG("rte flow udp pattern:");
		if (udp_spec) {
			LOG_DEBUG("  spec: src_port=%hu dst_port=%hu",
				  ntohs(udp_spec->hdr.src_port),
				  ntohs(udp_spec->hdr.dst_port));
		} else {
			LOG_DEBUG("  spec = null");
		}
		if (udp_mask) {
			LOG_DEBUG("  mask: src_port=0x%hx dst_port=0x%hx",
				  ntohs(udp_mask->hdr.src_port),
				  ntohs(udp_mask->hdr.dst_port));
		} else {
			LOG_DEBUG("  mask = null");
		}
	} else if (item->type == RTE_FLOW_ITEM_TYPE_TCP) {
		const struct rte_flow_item_tcp *tcp_spec = item->spec;
		const struct rte_flow_item_tcp *tcp_mask = item->mask;

		LOG_DEBUG("rte flow tcp pattern:");
		if (tcp_spec) {
			LOG_DEBUG("  spec: src_port=%hu dst_port=%hu",
				  ntohs(tcp_spec->hdr.src_port),
				  ntohs(tcp_spec->hdr.dst_port));
		} else {
			LOG_DEBUG("  spec = null");
		}
		if (tcp_mask) {
			LOG_DEBUG("  mask: src_port=0x%hx dst_port=0x%hx",
				  ntohs(tcp_mask->hdr.src_port),
				  ntohs(tcp_mask->hdr.dst_port));
		} else {
			LOG_DEBUG("  mask = null");
		}
	} else if (item->type == RTE_FLOW_ITEM_TYPE_END) {
		;
	} else {
		LOG_DEBUG("unknown rte flow pattern: %d", item->type);
	}
}

static void dump_flow_action(const struct rte_flow_action *action)
{
	if (action->type == RTE_FLOW_ACTION_TYPE_MARK) {
		const struct rte_flow_action_mark *mark = action->conf;

		LOG_DEBUG("rte flow mark action:");
		if (mark) {
			LOG_DEBUG("  id=%d", mark->id);
		} else {
			LOG_DEBUG("  null");
		}
	} else if (action->type == RTE_FLOW_ACTION_TYPE_RSS) {
		const struct rte_flow_action_rss *rss = action->conf;

		LOG_DEBUG("rte flow RSS action:");
		if (rss) {
			LOG_DEBUG("  queue_num=%d type=%lu", rss->queue_num, rss->types);
		} else {
			LOG_DEBUG("  null");
		}
	} else if (action->type == RTE_FLOW_ACTION_TYPE_QUEUE) {
		const struct rte_flow_action_queue *queue = action->conf;

		LOG_DEBUG("rte flow queue action:");
		if (queue) {
			LOG_DEBUG("  queue_idx=%d", queue->index);
		} else {
			LOG_DEBUG("  null");
		}
	} else if (action->type == RTE_FLOW_ACTION_TYPE_PORT_REPRESENTOR) {
		const struct rte_flow_action_ethdev *port = action->conf;

		LOG_DEBUG("rte flow port_representor action:");
		if (port) {
			LOG_DEBUG("  port=%d", port->port_id);
		} else {
			LOG_DEBUG("  null");
		}
	} else if (action->type == RTE_FLOW_ACTION_TYPE_END) {
		;
	} else {
		LOG_DEBUG("unknown rte flow action: %d", action->type);
	}
}

static void dump_flow(const struct offload_ctx *ctx, uint16_t port)
{
	int i;

	LOG_DEBUG("offloading to port %hu:", port);

	dump_flow_attr(&ctx->attr);

	for (i = 0; i < ctx->patterns.cnt; i++)
		dump_flow_pattern(&ctx->patterns.items[i]);

	for (i = 0; i < ctx->actions.cnt; i++)
		dump_flow_action(&ctx->actions.actions[i]);

	LOG_DEBUG("");
}

static void add_flow_pattern(struct flow_patterns *patterns,
			     enum rte_flow_item_type type,
			     const void *spec, const void *mask)
{
	int cnt = patterns->cnt;

	/* TODO: no assert, be tolerant */
	assert (cnt < MAX_FLOW_PATTERN);

	patterns->items[cnt].type = type;
	patterns->items[cnt].spec = spec;
	patterns->items[cnt].mask = mask;
	patterns->items[cnt].last = NULL;
	patterns->cnt++;
}

static void add_flow_action(struct flow_actions *actions,
			    enum rte_flow_action_type type,
			    const void *conf)
{
	int cnt = actions->cnt;

	assert (cnt < MAX_FLOW_ACTION);

	actions->actions[cnt].type = type;
	actions->actions[cnt].conf = conf;
	actions->cnt++;
}

static void add_mark_action(struct offload_ctx *ctx, uint32_t id)
{
	ctx->mark.id = id;
	add_flow_action(&ctx->actions, RTE_FLOW_ACTION_TYPE_MARK, &ctx->mark);
}

static inline void add_rss_action(struct offload_ctx *ctx, uint64_t rss_types)
{
	int i;

	ctx->rss = (struct rte_flow_action_rss) {
		.func = RTE_ETH_HASH_FUNCTION_DEFAULT,
		.level = 0,
		.types = rss_types,
		.queue_num = tpa_cfg.nr_worker,
		.queue = ctx->queue_idx,
		.key_len = 0,
		.key  = NULL
	};

	for (i = 0; i < tpa_cfg.nr_worker; i++)
		ctx->queue_idx[i] = i;

	add_flow_action(&ctx->actions, RTE_FLOW_ACTION_TYPE_RSS, &ctx->rss);
}

static void add_queue_action(struct offload_ctx *ctx, uint16_t queue)
{
	ctx->queue.index = queue;

	add_flow_action(&ctx->actions, RTE_FLOW_ACTION_TYPE_QUEUE, &ctx->queue);
}

static void add_port_rep_action(struct offload_ctx *ctx)
{
	ctx->port_rep.port_id = 0;
	add_flow_action(&ctx->actions, RTE_FLOW_ACTION_TYPE_PORT_REPRESENTOR, &ctx->port_rep);
}

static void offload_translate(struct offload_rule *rule, struct offload_ctx *ctx)
{
	memset(ctx, 0, sizeof(struct offload_ctx));

	ctx->rule = rule;

	if (rule->has_src_ip) {
		if (tpa_ip_is_ipv4(&rule->src_ip)) {
			ctx->ip_spec.hdr.src_addr = tpa_ip_get_ipv4(&rule->src_ip);
			ctx->ip_mask.hdr.src_addr = 0xffffffff;
		} else {
			memcpy(ctx->ip6_spec.hdr.src_addr, rule->src_ip.u8, 16);
			memset(ctx->ip6_mask.hdr.src_addr, 0xff, 16);
			ctx->is_ipv6 = 1;
		}
	}
	if (rule->has_dst_ip) {
		if (tpa_ip_is_ipv4(&rule->dst_ip)) {
			ctx->ip_spec.hdr.dst_addr = tpa_ip_get_ipv4(&rule->dst_ip);
			ctx->ip_mask.hdr.dst_addr = 0xffffffff;
			debug_assert(ctx->is_ipv6 == 0);
		} else {
			memcpy(ctx->ip6_spec.hdr.dst_addr, rule->dst_ip.u8, 16);
			memset(ctx->ip6_mask.hdr.dst_addr, 0xff, 16);
			ctx->is_ipv6 = 1;
		}
	}

	if (rule->has_proto) {
		if (ctx->is_ipv6) {
			ctx->ip6_spec.hdr.proto = rule->proto;
			ctx->ip6_mask.hdr.proto = 0xff;
		} else {
			ctx->ip_spec.hdr.next_proto_id = rule->proto;
			ctx->ip_mask.hdr.next_proto_id = 0xff;
		}
	}

	if (rule->has_src_port) {
		ctx->tcp_spec.hdr.src_port = rule->src_port;
		ctx->tcp_mask.hdr.src_port = 0xffff;
	}
	if (rule->has_dst_port) {
		ctx->tcp_spec.hdr.dst_port = rule->dst_port;
		if (rule->has_dst_port_mask)
			ctx->tcp_mask.hdr.dst_port = rule->dst_port_mask;
		else
			ctx->tcp_mask.hdr.dst_port = 0xffff;
	}

	add_flow_pattern(&ctx->patterns, RTE_FLOW_ITEM_TYPE_ETH, NULL, NULL);
	if (ctx->is_ipv6)
		add_flow_pattern(&ctx->patterns, RTE_FLOW_ITEM_TYPE_IPV6, &ctx->ip6_spec, &ctx->ip6_mask);
	else
		add_flow_pattern(&ctx->patterns, RTE_FLOW_ITEM_TYPE_IPV4, &ctx->ip_spec, &ctx->ip_mask);
	add_flow_pattern(&ctx->patterns, RTE_FLOW_ITEM_TYPE_TCP,  &ctx->tcp_spec, &ctx->tcp_mask);

	if (rule->has_mark)
		add_mark_action(ctx, rule->mark);

	if (rule->has_queue) {
		add_queue_action(ctx, rule->queue);
	} else if (rule->has_rss) {
		uint64_t rss_types;

		if (rule->has_rss_types)
			rss_types = rule->rss_types;
		else
			rss_types = ETH_RSS_IP | ETH_RSS_TCP;

		add_rss_action(ctx, rss_types);
	}
}

static struct rte_flow *flow_create(struct offload_ctx *ctx, int port)
{
	struct rte_flow *flow;

	add_flow_pattern(&ctx->patterns, RTE_FLOW_ITEM_TYPE_END, NULL, NULL);
	add_flow_action(&ctx->actions, RTE_FLOW_ACTION_TYPE_END, NULL);

	dump_flow(ctx, port);

	pthread_mutex_lock(&dev.mutex);
	flow = rte_flow_create(port, &ctx->attr, ctx->patterns.items,
			       ctx->actions.actions, &ctx->error);
	pthread_mutex_unlock(&dev.mutex);
	if (!flow) {
		LOG_ERR("failed to create rte flow: %d, %s on port %d",
			ctx->error.type, ctx->error.message, port);
	}

	return flow;
}

static void iavf_offload_workaround(struct offload_ctx *ctx)
{
	/* append a PORT_REPRESENTOR action, which is needed for iavf */
	add_port_rep_action(ctx);
}

static struct rte_flow *do_offload_create(struct offload_ctx *ctx, int priority, int port)
{
	ctx->attr.ingress = 1;
	ctx->attr.priority = priority;

	return flow_create(ctx, port);
}

static void offload_set_name(struct offload_list *list, const char *fmt, ...)
{
	char *name = malloc(OFFLOAD_NAME_SIZE);
	va_list ap;

	if (!name)
		return;

	va_start(ap, fmt);
	vsnprintf(name, OFFLOAD_NAME_SIZE, fmt, ap);
	va_end(ap);

	list->name = name;
}

static int offload_destroy(struct offload_list *list)
{
	struct rte_flow_error error;
	struct offload *offload;
	struct offload *next;
	int failed = 0;
	int ret;

	/* double destroy? */
	if (!list->name)
		return -1;

	offload = TAILQ_FIRST(&list->head);

	LOG("destroying offload %s", list->name);

	while (offload) {
		next = TAILQ_NEXT(offload, node);

		pthread_mutex_lock(&dev.mutex);
		ret = rte_flow_destroy(offload->port, offload->flow, &error);
		pthread_mutex_unlock(&dev.mutex);

		if (ret != 0) {
			LOG("failed to destroy sub-offload %s, %s on port %d",
			    list->name, error.message, offload->port);
			failed = 1;
		}

		TAILQ_REMOVE(&list->head, offload, node);
		free(offload);

		offload = next;
	}

	free(list->name);
	list->name = NULL;

	return failed ? -1 : 0;
}

static int offload_create(struct offload_list *list, struct offload_rule *rule, int priority)
{
	struct offload *offload;
	struct rte_flow *flow;
	struct offload_ctx ctx;
	int i;

	LOG("offloading %s", list->name);

	offload_translate(rule, &ctx);

	if (dev.nic == NIC_TYPE_IAVF)
		iavf_offload_workaround(&ctx);

	for (i = 0; i < dev.nr_port; i++) {
		offload = malloc(sizeof(struct offload));
		if (!offload)
			goto fail;

		flow = do_offload_create(&ctx, priority, i);
		if (!flow) {
			free(offload);
			goto fail;
		}

		offload->flow = flow;
		offload->port = i;
		TAILQ_INSERT_TAIL(&list->head, offload, node);
	}

	return 0;

fail:
	LOG_WARN("failed to offload %s", list->name);
	offload_destroy(list);

	return -1;
}

static int tsock_offload_do_create(struct tcp_sock *tsock, int ipv6)
{
	struct offload_rule rule;
	struct tpa_ip local_ip;
	int priority = 0;

	memset(&rule, 0, sizeof(rule));

	if (tsock->state == TCP_STATE_LISTEN)
		priority = 1;

	if (ipv6)
		local_ip = dev.ip6.ip;
	else
		tpa_ip_set_ipv4(&local_ip, dev.ip4);

	OFFLOAD_SET(&rule, dst_ip, local_ip);
	OFFLOAD_SET(&rule, dst_port, tsock->local_port);
	if (tsock->state != TCP_STATE_LISTEN) {
		OFFLOAD_SET(&rule, src_ip, tsock->remote_ip);
		OFFLOAD_SET(&rule, src_port, tsock->remote_port);
	}

	if (offload_cfg.enable_flow_mark)
		OFFLOAD_SET(&rule, mark, make_flow_mark(tsock->worker->id, tsock->sid));
	if (tsock->state == TCP_STATE_LISTEN && tsock->opts.listen_scaling)
		rule.has_rss = 1;
	else
		OFFLOAD_SET(&rule, queue, tsock->worker->id);

	return offload_create(&tsock->offload_list, &rule, priority);
}

/*
 * if tsock->local_ip is ipv6 ANY, it means it's a listen tsock,
 * we create 2 rte_flow for both ipv4 and ipv6. Otherwise, we create
 * only one rte_flow.
 */
int tsock_offload_create(struct tcp_sock *tsock)
{
	struct tpa_ip *ip = &tsock->local_ip;
	char name[120];

	if (!(dev.caps & FLOW_OFFLOAD))
		return 0;

	/*
	 * XXX: sock offload is a must for listen sock, as we don't have
	 * port block offload for it.
	 */
	if (tsock->state != TCP_STATE_LISTEN && !offload_cfg.enable_sock_offload)
		return 0;

	get_flow_name(tsock, name, sizeof(name));
	offload_set_name(&tsock->offload_list, "%s", name);

	if (dev.ip4 && (is_ip6_any(ip) || tpa_ip_is_ipv4(ip))) {
		if (tsock_offload_do_create(tsock, 0) < 0)
			goto fail;
	}

	if (is_ip6_any(ip) || !tpa_ip_is_ipv4(ip)) {
		if (tsock_offload_do_create(tsock, 1) < 0)
			goto fail;
	}

	return 0;

fail:
	WORKER_STATS_INC(tsock->worker, SOCK_OFFLOAD_FAILURE);
	return -1;
}

void tsock_offload_destroy(struct tcp_sock *tsock)
{
	offload_destroy(&tsock->offload_list);
}

int port_block_offload_create(struct port_block *block)
{
	struct offload_rule rule;
	struct tpa_ip local_ips[2];
	int nr_ip = 0;
	int i;

	if (!(dev.caps & FLOW_OFFLOAD))
		return 0;

	if (!offload_cfg.enable_port_block_offload)
		return 0;

	offload_set_name(&block->offload_list, "port block %hu-%hu",
			 block->start, block->end);

	memset(&rule, 0, sizeof(rule));

	OFFLOAD_SET(&rule, dst_port, htons(block->start));
	OFFLOAD_SET(&rule, dst_port_mask, htons(block->port_mask));

	OFFLOAD_SET(&rule, queue, block->worker->id);

	if (dev.ip4)
		tpa_ip_set_ipv4(&local_ips[nr_ip++], dev.ip4);
	if (!is_ip6_any(&dev.ip6.ip))
		local_ips[nr_ip++] = dev.ip6.ip;

	for (i = 0; i < nr_ip; i++) {
		OFFLOAD_SET(&rule, dst_ip, local_ips[i]);
		if (offload_create(&block->offload_list, &rule, 1) < 0)
			goto fail;
	}

	return 0;

fail:
	WORKER_STATS_INC(block->worker, PORT_BLOCK_OFFLOAD_FAILURE);
	return -1;
}

void port_block_offload_destroy(struct port_block *block)
{
	offload_destroy(&block->offload_list);
}

int offload_init(void)
{
	cfg_spec_register(offload_cfg_specs, ARRAY_SIZE(offload_cfg_specs));
	cfg_section_parse("offload");

	if (offload_cfg.enable_sock_offload == 0 && offload_cfg.enable_port_block_offload == 0) {
		LOG_WARN("none offload enabled; forcing sock offload on");
		offload_cfg.enable_sock_offload = 1;
	}

	return 0;
}
