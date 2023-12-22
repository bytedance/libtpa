/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <libgen.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>

#include "sock.h"
#include "log.h"
#include "mem_file.h"
#include "tcp_queue.h"
#include "worker.h"
#include "tsock_trace.h"
#include "tpad.h"
#include "archive.h"

static void calc_csum(struct eth_ip_hdr *net_hdr, struct rte_tcp_hdr *tcp)
{
	if (ntohs(net_hdr->eth.ether_type) == RTE_ETHER_TYPE_IPV4) {
		net_hdr->ip4.hdr_checksum = 0;
		net_hdr->ip4.hdr_checksum = rte_ipv4_cksum(&net_hdr->ip4);

		tcp->cksum = 0;
		tcp->cksum = rte_ipv4_udptcp_cksum(&net_hdr->ip4, tcp);
	} else {
		tcp->cksum = 0;
		tcp->cksum = rte_ipv6_udptcp_cksum(&net_hdr->ip6, tcp);
	}
}

static void terminate_one_sock(struct tcp_sock *tsock, int fd, int ifindex)
{
	struct eth_ip_hdr *net_hdr;
	struct rte_tcp_hdr *tcp;
	struct sockaddr_ll addr;
	char buf[128];

	get_flow_name(tsock, buf, sizeof(buf));
	LOG("terminating tsock %s ...", buf);

	net_hdr = (struct eth_ip_hdr *)buf;
	tcp = (struct rte_tcp_hdr *)((char *)net_hdr + tsock->net_hdr_len);

	*net_hdr = tsock->net_hdr;
	if (tsock->is_ipv6) {
		net_hdr->ip6.payload_len = htons(sizeof(*tcp));
	} else {
		net_hdr->ip4.packet_id = htons(tsock->packet_id);
		net_hdr->ip4.total_length = htons(sizeof(net_hdr->ip4) + sizeof(*tcp));
	}

	memset(tcp, 0, sizeof(*tcp));
	tcp->src_port = tsock->local_port;
	tcp->dst_port = tsock->remote_port;
	tcp->sent_seq = htonl(tsock->snd_nxt);
	tcp->tcp_flags = TCP_FLAG_RST;
	tcp->data_off = (sizeof(*tcp) >> 2) << 4;

	calc_csum(net_hdr, tcp);

	memset(&addr, 0, sizeof(addr));
	addr.sll_family   = AF_PACKET;
	addr.sll_ifindex  = ifindex;
	addr.sll_halen    = RTE_ETHER_ADDR_LEN;
	addr.sll_protocol = net_hdr->eth.ether_type;
	memcpy(addr.sll_addr, ETH_SRC_ADDR(&net_hdr->eth), RTE_ETHER_ADDR_LEN);

	if (sendto(fd, buf, tsock->net_hdr_len + sizeof(*tcp),
		   0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		LOG_WARN("failed to terminate tsock %d: %s",
			 tsock->sid, strerror(errno));
	}
}

static void tpad_symlink(const char *target, const char *linkpath)
{
	if (symlink(target, linkpath) < 0) {
		LOG_WARN("failed to symlink %s -> %s: %s",
			 target, linkpath, strerror(errno));
	}
}

void sock_termination(void)
{
	struct archive_ctx ctx;
	struct tcp_sock *tsock;
	struct mem_file *mem_file;
	uint64_t id;
	int ifindex;
	int fd;
	int i;

	mem_file = mem_file_map(tpad.sock_file, NULL, MEM_FILE_READ);
	if (!mem_file)
		return;

	archive_ctx_init(&ctx, tpad.archive_dir, "socks", 16);
	id = archive_raw(&ctx, mem_file->hdr, mem_file->hdr->size);
	unlink(tpad.sock_file);

	if (id != UINT64_MAX)
		tpad_symlink(archive_path(&ctx, id), tpad.sock_file);

	ifindex = if_nametoindex(tpad.eth_dev);
	if (ifindex == 0) {
		LOG_WARN("skip sock termination due to failed to get ifindex for %s: %s",
			 tpad.eth_dev, strerror(errno));
		return;
	}

	/*
	 * setting protocol to 0 here means we'd like to recv
	 * no pkts from kernel
	 */
	fd = socket(AF_PACKET, SOCK_RAW, 0);
	if(fd == -1) {
		LOG_WARN("failed to create AF_PACKET: %s", strerror(errno));
		return;
	}

	sock_ctrl = mem_file_data(mem_file);
	for (i = 0; i < sock_ctrl->nr_max_sock; i++) {
		tsock = &sock_ctrl->socks[i];

		if (tsock->sid >= 0 && tsock->state == TCP_STATE_ESTABLISHED)
			terminate_one_sock(tsock, fd, ifindex);
	}
}

/* XXX: de-duplicate */
static struct mem_file *map_tsock_trace_file(const char *path)
{
	struct mem_file *mem_file;

	mem_file = mem_file_map(path, NULL, MEM_FILE_READ);
	if (!mem_file)
		return NULL;

	memset(&tsock_trace_ctrl, 0, sizeof(tsock_trace_ctrl));
	tsock_trace_ctrl.file = mem_file_data(mem_file);
	tsock_trace_ctrl.size = mem_file_data_size(mem_file);

	tsock_trace_ctrl.parser = mem_file_parser(mem_file);
	tsock_trace_ctrl.parser_size = mem_file_parser_size(mem_file);

	return mem_file;
}

void sock_archive(void)
{
	struct archive_ctx ctx;
	struct mem_file *mem_file;
	struct tsock_trace *trace;
	char link_path[PATH_MAX];
	char name[256];
	uint64_t id;

	mem_file = map_tsock_trace_file(tpad.sock_trace_file);
	if (!mem_file)
		return;

	archive_ctx_init(&ctx, tpad.archive_dir, "trace", 16);
	id = archive_raw(&ctx, mem_file->hdr, mem_file->hdr->size);
	unlink(tpad.sock_trace_file);

	if (id == UINT64_MAX)
		return;

	tpa_snprintf(link_path, sizeof(link_path), "%s/socktrace",
		    dirname(strdup(tpad.sock_trace_file)));
	tpad_symlink(archive_path(&ctx, id), link_path);

	TSOCK_TRACE_FOREACH(trace) {
		if (trace->sid < 0)
			continue;

		tsock_trace_name(trace, "tpad", name, sizeof(name));
		archive_map_add(ctx.map, off, trace->init_time, trace->size,
				trace->sid, name, archive_path(&ctx, id));
	}
}
