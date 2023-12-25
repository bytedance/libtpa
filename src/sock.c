/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <sys/mman.h>

#include "api/tpa.h"

#include "tpa.h"
#include "log.h"
#include "sock.h"
#include "shell.h"
#include "worker.h"
#include "tcp_queue.h"
#include "tcp.h"
#include "trace.h"
#include "tsock_trace.h"
#include "mem_file.h"
#include "archive.h"
#include "neigh.h"
#include "port_alloc.h"

static struct sock_table listen_sock_table;

struct tcp_cfg tcp_cfg = {
	.enable_tso		= 1,
	.enable_ts		= 1,
	.enable_ws		= 1,
	.enable_sack		= 1,
	.enable_rx_merge	= 1,
	.drop_ooo_threshold	= 0,
	.measure_latency	= 0,
	.usr_snd_mss		= 0,
	.rcv_queue_size		= TSOCK_RXQ_LEN_DEFAULT,
	.snd_queue_size		= TSOCK_TXQ_LEN_DEFAULT,
	.time_wait		= TCP_TIME_WAIT_DEFAULT,
	.keepalive		= TCP_KEEPALIVE_DEFAULT,
	.delayed_ack		= TCP_DELAYED_ACK_DEFAULT,
	.cwnd_init		= TCP_CWND_DEFAULT,
	.cwnd_max		= TCP_CWND_MAX,
	.rcv_ooo_limit		= TSOCK_RCV_OOO_LIMIT,
	.tcp_rto_min		= TCP_RTO_MIN,
	.nr_max_sock		= DEFAULT_NR_MAX_SOCK,
	.pkt_max_chain		= PKT_MAX_CHAIN,
	.retries		= TCP_RETRIES_MAX,
	.syn_retries		= TCP_SYN_RETRIES_MAX,
	.write_chunk_size	= WRITE_CHUNK_SIZE,
};

static int tcp_cfg_set_with_regulation(struct cfg_spec *spec, const char *val);
static struct cfg_spec tcp_cfg_specs[] = {
	{
		.name	= "tcp.nr_max_sock",
		.type   = CFG_TYPE_UINT,
		.data   = &tcp_cfg.nr_max_sock,
		.flags  = CFG_FLAG_HAS_MAX | CFG_FLAG_POWEROF2,
		.max    = 256 << 10,
	}, {
		.name	= "tcp.pkt_max_chain",
		.type   = CFG_TYPE_UINT,
		.data   = &tcp_cfg.pkt_max_chain,
		.flags  = CFG_FLAG_HAS_MAX | CFG_FLAG_HAS_MIN,
		.max    = PKT_MAX_CHAIN,
		.min    = 2,
		.set    = tcp_cfg_set_with_regulation,
	}, {
		.name	= "tcp.usr_snd_mss",
		.type   = CFG_TYPE_UINT,
		.data   = &tcp_cfg.usr_snd_mss,
		.flags  = CFG_FLAG_HAS_MAX | CFG_FLAG_RDONLY,
		.max    = DEFAULT_MAX_MTU - PKT_MAX_HDR_LEN,
	}, {
		.name	= "tcp.time_wait",
		.type   = CFG_TYPE_TIME,
		.data   = &tcp_cfg.time_wait,
		.flags  = CFG_FLAG_HAS_MAX,
		.max    = TCP_RTO_MAX,
	}, {
		.name	= "tcp.keepalive",
		.type   = CFG_TYPE_TIME,
		.data   = &tcp_cfg.keepalive,
		.flags  = CFG_FLAG_HAS_MAX,
		.max    = TCP_RTO_MAX,
	}, {
		.name	= "tcp.delayed_ack",
		.type   = CFG_TYPE_TIME,
		.data   = &tcp_cfg.delayed_ack,
		.flags  = CFG_FLAG_HAS_MAX,
		.max    = 500 * 1000, /* rfc1122 4.2.3.2 (page 96) */
	}, {
		.name   = "tcp.tso",
		.type   = CFG_TYPE_UINT,
		.data   = &tcp_cfg.enable_tso,
	}, {
		.name   = "tcp.rx_merge",
		.type   = CFG_TYPE_UINT,
		.data   = &tcp_cfg.enable_rx_merge,
	}, {
		.name   = "tcp.opt_ts",
		.type   = CFG_TYPE_UINT,
		.data   = &tcp_cfg.enable_ts,
	}, {
		.name   = "tcp.opt_ws",
		.type   = CFG_TYPE_UINT,
		.data   = &tcp_cfg.enable_ws,
	}, {
		.name   = "tcp.opt_sack",
		.type   = CFG_TYPE_UINT,
		.data   = &tcp_cfg.enable_sack,
	}, {
		.name	= "tcp.retries",
		.type   = CFG_TYPE_UINT,
		.data   = &tcp_cfg.retries,
		.flags  = CFG_FLAG_HAS_MAX,
		.max    = UINT8_MAX,
	}, {
		.name	= "tcp.syn_retries",
		.type   = CFG_TYPE_UINT,
		.data   = &tcp_cfg.syn_retries,
		.flags  = CFG_FLAG_HAS_MAX,
		.max    = UINT8_MAX,
	}, {
		.name	= "tcp.rcv_queue_size",
		.type   = CFG_TYPE_UINT,
		.data   = &tcp_cfg.rcv_queue_size,
		.flags  = CFG_FLAG_HAS_MAX,
		.max    = 1<<15,
	}, {
		.name	= "tcp.snd_queue_size",
		.type   = CFG_TYPE_UINT,
		.data   = &tcp_cfg.snd_queue_size,
		.flags  = CFG_FLAG_HAS_MAX,
		.max    = 1<<15,
	}, {
		.name	= "tcp.cwnd_init",
		.type   = CFG_TYPE_UINT,
		.data   = &tcp_cfg.cwnd_init,
		.flags  = CFG_FLAG_HAS_MAX,
		.max    = TCP_CWND_MAX,
	}, {
		.name	= "tcp.cwnd_max",
		.type   = CFG_TYPE_UINT,
		.data   = &tcp_cfg.cwnd_max,
		.flags  = CFG_FLAG_HAS_MAX,
		.max    = TCP_CWND_MAX,
	}, {
		.name	= "tcp.rcv_ooo_limit",
		.type   = CFG_TYPE_UINT,
		.data   = &tcp_cfg.rcv_ooo_limit,
	}, {
		.name	= "tcp.drop_ooo_threshold",
		.type   = CFG_TYPE_UINT,
		.data   = &tcp_cfg.drop_ooo_threshold,
	}, {
		.name	= "tcp.measure_latency",
		.type   = CFG_TYPE_UINT,
		.data   = &tcp_cfg.measure_latency,
	}, {
		.name	= "tcp.rto_min",
		.type   = CFG_TYPE_TIME,
		.data   = &tcp_cfg.tcp_rto_min,
		.flags  = CFG_FLAG_HAS_MIN | CFG_FLAG_HAS_MAX,
		.min    = 10000, /* 10ms */
		.max    = TCP_RTO_MAX,
	}, {
		.name	= "tcp.write_chunk_size",
		.type   = CFG_TYPE_SIZE,
		.data   = &tcp_cfg.write_chunk_size,
		.flags  = CFG_FLAG_HAS_MIN | CFG_FLAG_HAS_MAX,
		.min    = 1,
		.max    = UINT32_MAX,
		.set    = tcp_cfg_set_with_regulation,
	}, {
		.name   = "tcp.local_port_range",
		.type   = CFG_TYPE_STR, /* XXX: a new type? */
		.set    = local_port_range_set,
		.get    = local_port_range_get,
	},
};

struct sock_ctrl *sock_ctrl;
struct tsock_trace_ctrl tsock_trace_ctrl;

/*
 * setup the trace dir and remove all stale files (to free memory)
 */
static void trace_root_init(void)
{
	const char *path = trace_root_get();
	struct dirent *de;
	DIR *dir;

	mkdir_p(path);

	dir = opendir(path);
	if (!dir)
		return;

	while (1) {
		de = readdir(dir);
		if (!de)
			break;

		if (strcmp(de->d_name, ".") == 0 ||
		    strcmp(de->d_name, "..") == 0)
			continue;

		LOG("removing stale trace file %s/%s", path, de->d_name);
		if (unlinkat(dirfd(dir), de->d_name, 0) < 0) {
			LOG_ERR("failed to remove trace file %s/%s: %s",
				path, de->d_name, strerror(errno));
		}
	}

	closedir(dir);
}

static void map_tsock_trace_file(void)
{
	struct tsock_trace_file *file;
	char path[PATH_MAX];
	size_t size;
	struct mem_file *mem_file;

	trace_root_init();

	tpa_snprintf(path, sizeof(path), "%s/socktrace-%d", trace_root_get(), getpid());
	tpa_cfg.sock_trace_file = strdup(path);

	size = trace_cfg.nr_trace * TRACE_SIZE(trace_cfg.trace_size);
	mem_file = mem_file_create(path, size, "sock-trace");
	if (!mem_file)
		return;
	file = mem_file_data(mem_file);

	memset(&tsock_trace_ctrl, 0, sizeof(tsock_trace_ctrl));
	tsock_trace_ctrl.file = file;
	tsock_trace_ctrl.size = size;
	tsock_trace_ctrl.nr_trace = trace_cfg.nr_trace;
	tsock_trace_ctrl.pid = getpid();

	tsock_trace_ctrl.parser = mem_file_parser(mem_file);
	tsock_trace_ctrl.parser_size = mem_file_parser_size(mem_file);

	tsock_trace_ctrl.curr_trace_map = map_archive_map_file(CURR_TRACE_MAP_FILE);
}

static void tsock_trace_ctrl_init(void)
{
	int nr_trace = tsock_trace_ctrl.nr_trace;
	struct tsock_trace *trace;
	struct rte_ring *ring;
	int i;

	if (tsock_trace_ctrl.file == NULL)
		return;

	ring = rte_ring_create("tsock-trace", nr_trace, SOCKET_ID_ANY, RING_F_EXACT_SZ);
	if (ring == NULL) {
		LOG_WARN("failed to create tsock trace queue");
		tsock_trace_ctrl.file = NULL;
		return;
	}

	for (i = 0; i < nr_trace; i++) {
		trace = tsock_trace_at(i * TRACE_SIZE(trace_cfg.trace_size));
		trace->sid  = -1;
		trace->size = TRACE_SIZE(trace_cfg.trace_size);
		rte_ring_enqueue(ring, trace);
	}

	tsock_trace_ctrl.ring = ring;
}

static struct tsock_trace *tsock_trace_alloc(int sid)
{
	struct tsock_trace *trace;

	if (rte_ring_dequeue(tsock_trace_ctrl.ring, (void **)&trace) == 0) {
		trace->sid = sid;
		trace->init_time = get_time_in_us();
		trace->init_ts_us = TSC_TO_US(rte_rdtsc());

		return trace;
	}

	return NULL;
}

static void tsock_trace_free(struct tsock_trace *trace)
{
	rte_ring_enqueue(tsock_trace_ctrl.ring, trace);
}

void tsock_trace_init(struct tcp_sock *tsock, int sid)
{
	struct tsock_trace *trace;
	uint64_t nr_record;

	RTE_BUILD_BUG_ON(TT_MAX > UINT8_MAX);

	if (!tsock_trace_ctrl.file)
		return;

	trace = tsock_trace_alloc(sid);
	if (!trace)
		return;

	nr_record = (trace->size - sizeof(struct tsock_trace)) / sizeof(uint64_t);
	trace->mask = (1 << log2_ceil(nr_record)) - 1;

	tsock->trace = trace;
	tsock->trace_size = trace->size;
}

void tsock_trace_archive(struct tsock_trace *trace, const char *fmt, ...)
{
	char name[PATH_MAX];
	char mark[128];
	va_list ap;

	if (!trace)
		return;

	va_start(ap, fmt);
	vsnprintf(mark, sizeof(mark), fmt, ap);
	va_end(ap);

	tsock_trace_name(trace, mark, name, sizeof(name));
	archive_submit(name, trace->sid, trace, trace->size,
		       tsock_trace_ctrl.parser, tsock_trace_ctrl.parser_size);
}

void tsock_trace_uninit(struct tcp_sock *tsock)
{
	if (tsock->trace) {
		tsock_trace_free(tsock->trace);
		tsock->trace = NULL;
	}
}

#define _COPY_OPTS(x)		short_opts->x = opts->x
static void convert_sock_opts(const struct tpa_sock_opts *opts,
			      struct tpa_sock_opts_short *short_opts)
{
	_COPY_OPTS(listen_scaling);
	_COPY_OPTS(local_port);
	_COPY_OPTS(data);
}

static int tsock_init(struct tcp_sock *tsock, int sid, const struct tpa_sock_opts *opts)
{
	struct tpa_worker *worker = tls_worker;
	uint64_t now;

	if (!worker) {
		LOG_ERR("trying to create sock in none-worker thread");
		return -EINVAL;
	}

	memset((uint8_t *)tsock + sizeof(tsock->sid), 0, sizeof(*tsock) - sizeof(tsock->sid));

	if (opts)
		convert_sock_opts(opts, &tsock->opts);

	__sync_fetch_and_add_4(&worker->nr_tsock, 1);
	__sync_fetch_and_add_8(&worker->nr_tsock_total, 1);

	tsock->tso_enabled  = tcp_cfg.enable_tso;
	tsock->ts_enabled   = tcp_cfg.enable_ts;
	tsock->ws_enabled   = tcp_cfg.enable_ws;
	tsock->sack_enabled = tcp_cfg.enable_sack;

	now = worker->ts_us;
	timer_init(&tsock->timer_rto,  &worker->timer_ctrl, tcp_timeout, tsock, now);
	timer_init(&tsock->timer_wait, &worker->timer_ctrl, tcp_timeout, tsock, now);
	timer_init(&tsock->timer_keepalive, &worker->timer_ctrl, tcp_timeout, tsock, now);

	/* TODO: we don't have to re-alloc it when the rxq or txq size are the same */
	tsock->rxq.objs = malloc(tcp_cfg.rcv_queue_size * sizeof(void *));
	if (!tsock->rxq.objs)
		return -ENOMEM;
	tcp_rxq_init(&tsock->rxq, tcp_cfg.rcv_queue_size);

	tsock->txq.descs = malloc(tcp_cfg.snd_queue_size * sizeof(void *));
	if (!tsock->txq.descs) {
		free(tsock->rxq.objs);
		return -ENOMEM;
	}
	tcp_txq_init(&tsock->txq, tcp_cfg.snd_queue_size);

	tsock_trace_init(tsock, sid);

	tsock->worker = worker;
	tsock->rcv_wnd = TSOCK_RCV_WND_DEFAULT(tsock);
	tsock->quickack = TSOCK_QUICKACK_COUNT;
	tsock->listen_sock = 0;
	rte_spinlock_init(&tsock->lock);

	TAILQ_INIT(&tsock->rcv_ooo_queue);
	offload_list_init(&tsock->offload_list);

	FLEX_FIFO_NODE_INIT(&tsock->output_node);
	FLEX_FIFO_NODE_INIT(&tsock->event_node);
	FLEX_FIFO_NODE_INIT(&tsock->accept_node);

	rte_smp_wmb();
	tsock->sid = sid;

	return 0;
}

static void reclaim_rxq(struct tcp_sock *tsock)
{
	struct packet *pkt;
	int i = 0;

	while (1) {
		pkt = tcp_rxq_peek_unread(&tsock->rxq, i++);
		if (!pkt)
			break;

		debug_assert(i <= tsock->rxq.size);
		packet_free(pkt);
	}

	free(tsock->rxq.objs);
}

static void reclaim_txq(struct tcp_sock *tsock)
{
	struct tx_desc *desc;
	int i = 0;

	while (1) {
		desc = tcp_txq_peek_una(&tsock->txq, i++);
		if (!desc)
			break;

		debug_assert(i <= tsock->txq.size);
		tx_desc_done(desc, tsock->worker);
	}

	free(tsock->txq.descs);
}

static void reclaim_rcv_ooo_queue(struct tcp_sock *tsock)
{
	struct packet *pkt;
	struct packet *next;

	pkt = TAILQ_FIRST(&tsock->rcv_ooo_queue);

	while (pkt) {
		next = TAILQ_NEXT(pkt, node);
		tsock_remove_ooo_pkt(tsock, pkt);
		packet_free(pkt);

		pkt = next;
	}

	debug_assert(tsock->nr_ooo_pkt == 0);
}

static int tsock_unbind(struct tcp_sock *tsock)
{
	struct sock_key key;

	sock_key_init(&key, &tsock->remote_ip, ntohs(tsock->remote_port),
		      &tsock->local_ip, ntohs(tsock->local_port));
	return port_unbind(tsock->worker, &key);
}

static int remove_passive_sock(struct tcp_sock *tsock)
{
	struct sock_key key;

	sock_key_init(&key, &tsock->remote_ip, ntohs(tsock->remote_port),
		      &tsock->local_ip, ntohs(tsock->local_port));
	return sock_table_del(&tsock->worker->sock_table, &key);
}

static int add_listen_sock(struct tcp_sock *tsock)
{
	struct sock_key key;

	memset(&key, 0, sizeof(key));
	key.local_port = ntohs(tsock->local_port);

	return sock_table_add_lock(&listen_sock_table, &key, tsock);
}

static int remove_listen_sock(struct tcp_sock *tsock)
{
	struct sock_key key;

	memset(&key, 0, sizeof(key));
	key.local_port = ntohs(tsock->local_port);

	return sock_table_del_lock(&listen_sock_table, &key);
}

int tsock_free(struct tcp_sock *tsock)
{
	struct tpa_worker *worker = tsock->worker;
	/*
	 * XXX: store and recover the errno, below code may change it;
	 * more specifically, so far, tsock_trace_uninit might change it.
	 */
	int err = errno;

	trace_tcp_release(tsock, err);

	__sync_fetch_and_add_4(&worker->nr_tsock, -1);
	tsock_offload_destroy(tsock);

	if (tsock->local_port) {
		/* XXX: it's a bit ugly */
		if (tsock->listen_sock) {
			port_free(ntohs(tsock->local_port));
			remove_listen_sock(tsock);
		} else if (tsock->passive_connection) {
			remove_passive_sock(tsock);
		} else {
			tsock_unbind(tsock);
		}
	}

	timer_close(&tsock->timer_rto,  TSC_TO_US(rte_rdtsc()));
	timer_close(&tsock->timer_wait, TSC_TO_US(rte_rdtsc()));
	timer_close(&tsock->timer_keepalive, TSC_TO_US(rte_rdtsc()));

	reclaim_rxq(tsock);
	reclaim_txq(tsock);
	reclaim_rcv_ooo_queue(tsock);

	flex_fifo_remove(worker->output, &tsock->output_node);
	flex_fifo_remove(worker->delayed_ack, &tsock->delayed_ack_node);
	flex_fifo_remove(worker->event_queue, &tsock->event_node);
	flex_fifo_remove(worker->accept, &tsock->accept_node);

	tsock_trace_uninit(tsock);

	rte_smp_wmb();
	tsock->sid = TSOCK_SID_FREEED;

	rte_atomic32_dec(&sock_ctrl->nr_sock);

	errno = err;

	return 0;
}

int tsock_try_update_eth_hdr(struct tpa_worker *worker, struct tcp_sock *tsock)
{
	struct rte_ether_hdr eth;

	if (eth_lookup(worker, &tsock->remote_ip, &eth) < 0)
		return -1;

	if (memcmp(&tsock->net_hdr.eth, &eth, sizeof(tsock->net_hdr.eth)) != 0) {
		tsock->net_hdr.eth = eth;
		WORKER_TSOCK_STATS_INC(worker, tsock, WARN_NEIGH_CHANGED);
	}

	return 0;
}

static int enlarge_sock_count(void)
{
	/* double the max sock count */
	uint64_t to_add = tcp_cfg.nr_max_sock * sizeof(struct tcp_sock);
	int i;

	if (sock_ctrl->expand_failed)
		return -1;

	if (mem_file_expand(sock_ctrl->mem_file, to_add) < 0) {
		sock_ctrl->expand_failed = 1;
		return -1;
	}

	/* mark those newly allocated socks free */
	for (i = tcp_cfg.nr_max_sock; i < tcp_cfg.nr_max_sock * 2; i++)
		sock_ctrl->socks[i].sid = TSOCK_SID_UNALLOCATED;

	tcp_cfg.nr_max_sock *= 2;
	sock_ctrl->nr_max_sock = tcp_cfg.nr_max_sock;
	sock_ctrl->nr_expand_times += 1;

	return 0;
}

static struct tcp_sock *sock_alloc(const struct tpa_sock_opts *opts)
{
	struct tcp_sock *tsock = NULL;
	static uint32_t next_sock;
	uint32_t i;
	int sid;

	rte_spinlock_lock(&sock_ctrl->lock);

again:
	for (i = 0; i < tcp_cfg.nr_max_sock; i++) {
		sid = (next_sock + i) & (tcp_cfg.nr_max_sock - 1);
		if (sock_ctrl->socks[sid].sid < 0) {
			tsock = &sock_ctrl->socks[sid];
			next_sock += i + 1;
			break;
		}
	}

	if (tsock == NULL && enlarge_sock_count() == 0) {
		next_sock = tcp_cfg.nr_max_sock / 2;
		goto again;
	}

	if (tsock && tsock_init(tsock, sid, opts) < 0)
		tsock = NULL;

	rte_spinlock_unlock(&sock_ctrl->lock);

	return tsock;
}

struct tcp_sock *sock_create(const struct tpa_sock_opts *opts, int is_ipv6)
{
	struct tcp_sock *tsock;

	tsock = sock_alloc(opts);
	if (!tsock) {
		errno = ENFILE;
		LOG_DEBUG("sock_alloc.failed=%d", errno);
		return NULL;
	}

	tsock->is_ipv6 = is_ipv6;
	rte_atomic32_inc(&sock_ctrl->nr_sock);

	return tsock;
}

static int tsock_bind(struct tcp_sock *tsock, struct tpa_ip *remote_ip, uint16_t remote_port)
{
	uint16_t local_port;
	struct tpa_ip local_ip;
	struct sock_key key;

	if (tsock->is_ipv6)
		local_ip = dev.ip6.ip;
	else
		tpa_ip_set_ipv4(&local_ip, dev.ip4);

	sock_key_init(&key, remote_ip, remote_port, &local_ip, tsock->opts.local_port);
	local_port = port_bind(tsock->worker, &key, tsock);
	if (local_port == 0) {
		errno = EADDRINUSE;
		return -1;
	}

	tsock->remote_ip = *remote_ip;
	tsock->local_ip = local_ip;
	tsock->remote_port = htons(remote_port);
	tsock->local_port = htons(local_port);

	tsock->err = 0;
	tsock_trace_base_init(tsock);
	if (tsock_offload_create(tsock) < 0) {
		errno = EBUSY;
		return -1;
	}

	return 0;
}

static int resolve_ip(const char *ip_str, struct tpa_ip *ip, int listen_mode)
{
	if (!tpa_ip_from_str(ip, ip_str))
		goto err;

	/*
	 * if it's a loopback address, turn it to a real address:
	 * the only way we now support loopback.
	 */
	if (tpa_ip_is_loopback(ip)) {
		if (tpa_ip_is_ipv4(ip))
			tpa_ip_set_ipv4(ip, dev.ip4);
		else
			*ip = dev.ip6.ip;
	}

	/* ditto: need convert 0.0.0.0 to dev.ip4 in listen mode */
	if (tpa_ip_is_ipv4(ip) && tpa_ip_get_ipv4(ip) == 0) {
		if (listen_mode)
			tpa_ip_set_ipv4(ip, dev.ip4);
		else
			goto err;
	}

	return 0;

err:
	LOG_ERR("error: invalid ip: %s\n", ip_str);
	errno = EINVAL;
	return -1;
}

int tpa_connect_to(const char *server, uint16_t port, const struct tpa_sock_opts *opts)
{
	struct tcp_sock *tsock;
	struct tpa_ip remote_ip;

	if (resolve_ip(server, &remote_ip, 0) < 0)
		return -1;

	if ((dev.ip4 == 0 && tpa_ip_is_ipv4(&remote_ip)) ||
	    (is_ip6_any(&dev.ip6.ip) && !tpa_ip_is_ipv4(&remote_ip))) {
		LOG_ERR("trying to connect to ipv4 remote %s on a ipv6 only machine, or vice versa", server);
		errno = EINVAL;
		return -1;
	}

	if (port == 0) {
		LOG_ERR("error: invalid port: %hu\n", port);
		errno = EINVAL;
		return -1;
	}

	tsock = sock_create(opts, !tpa_ip_is_ipv4(&remote_ip));
	if (!tsock)
		return -1;

	debug_assert(tsock->sid >= 0 && tsock->sid < tcp_cfg.nr_max_sock);
	LOG("connecting to: %d, %s:%u...", tsock->sid, server, port);

	if (tsock_bind(tsock, &remote_ip, port) < 0)
		goto free_tsock;

	if (tcp_connect(tsock) < 0)
		goto free_port;

	tsock->port_id = dev_port_id_get();

	return tsock->sid;

free_port:
	tsock_unbind(tsock);

free_tsock:
	tsock_free(tsock);

	return -1;
}

static int listen_ip_get(const char *local, struct tpa_ip *local_ip)
{
	if (!local) {
		*local_ip = (struct tpa_ip) {
			.u64 = { 0, 0 },
		};

		return 0;
	}

	if (resolve_ip(local, local_ip, 1) < 0)
		goto err;

	if (tpa_ip_is_ipv4(local_ip)) {
		if (tpa_ip_get_ipv4(local_ip) != dev.ip4)
			goto err;
	} else {
		if (!tpa_ip_equal(local_ip, &dev.ip6.ip))
			goto err;
	}

	return 0;

err:
	errno = EINVAL;
	return -1;
}

int tpa_listen_on(const char *local, uint16_t port, const struct tpa_sock_opts *opts)
{
	struct tcp_sock *tsock;
	struct tpa_ip local_ip;
	struct tpa_ip remote_ip;
	char buf[INET6_ADDRSTRLEN];

	if (listen_ip_get(local, &local_ip) < 0)
		return -1;

	if (port == 0) {
		errno = EINVAL;
		return -1;
	}

	memset(&remote_ip, 0, sizeof(remote_ip));
	if (port_alloc(port) == 0) {
		errno = EADDRINUSE;
		return -1;
	}

	tsock = sock_create(opts, !tpa_ip_is_ipv4(&local_ip));
	if (!tsock) {
		errno = ENFILE;
		port_free(port);
		return -1;
	}

	tpa_ip_to_str(&local_ip, buf, sizeof(buf));
	LOG("listen on: %s:%u...", buf, port, tsock->sid);

	tsock->local_port = htons(port);
	tsock->local_ip = local_ip;
	tsock->remote_ip = remote_ip;
	tsock->state = TCP_STATE_LISTEN;
	tsock->listen_sock = 1;

	tsock_trace_base_init(tsock);
	add_listen_sock(tsock);
	if (tsock_offload_create(tsock) < 0) {
		tsock_free(tsock);
		errno = EBUSY;
		return -1;
	}

	tsock->port_id = dev_port_id_get();

	return tsock->sid;
}

int tpa_accept_burst(struct tpa_worker *worker, int *sid, int nr_sid)
{
	struct tcp_sock *tsock;
	int nr_valid_sock = 0;

	while (nr_valid_sock < nr_sid) {
		tsock = FLEX_FIFO_POP_ENTRY(worker->accept, struct tcp_sock, accept_node);
		if (!tsock)
			break;

		if (tsock->sid < 0)
			continue;

		if (tsock->state != TCP_STATE_ESTABLISHED && tsock->state != TCP_STATE_CLOSE_WAIT)
			continue;

		sid[nr_valid_sock++]  = tsock->sid;
	}

	return nr_valid_sock;
}

ssize_t tpa_zreadv(int sid, struct tpa_iovec *iov, int nr_iov)
{
	struct tcp_sock *tsock;
	ssize_t ret;

	tsock = tsock_get_by_sid(sid);
	if (!tsock) {
		errno = EINVAL;
		return -1;
	}

	tsock_update_last_ts(tsock, LAST_TS_READ);
	ret = tsock_zreadv(tsock, iov, nr_iov);

	if (unlikely(ret < 0 && errno == EAGAIN)) {
		TSOCK_STATS_INC(tsock, READ_EAGAIN);
	}

	return ret;
}

ssize_t tpa_write(int cd, const void *buf, size_t size)
{
	struct tcp_sock *tsock;
	ssize_t ret;

	tsock = tsock_get_by_sid(cd);
	if (!tsock) {
		errno = EPIPE;
		return -1;
	}

	if (unlikely(size == 0))
		return 0;

	tsock_update_last_ts(tsock, LAST_TS_WRITE);
	ret = tsock_write(tsock, buf, size);

	if (unlikely(ret < 0 && errno == EAGAIN)) {
		TSOCK_STATS_INC(tsock, WRITE_EAGAIN);
	}

	return ret;
}

ssize_t tpa_zwritev(int sid, const struct tpa_iovec *iov, int nr_iov)
{
	struct tcp_sock *tsock;
	ssize_t ret;

	tsock = tsock_get_by_sid(sid);
	if (!tsock) {
		errno = EINVAL;
		return -1;
	}

	if (unlikely(nr_iov <= 0)) {
		if (nr_iov == 0) {
			ret = 0;
		} else {
			ret = -1;
			errno = EINVAL;
		}

		return ret;
	}

	tsock_update_last_ts(tsock, LAST_TS_WRITE);
	ret = tsock_zwritev(tsock, iov, nr_iov);
	if (unlikely(ret < 0 && errno == EAGAIN))
		TSOCK_STATS_INC(tsock, WRITE_EAGAIN);

	return ret;
}

void tpa_close(int sid)
{
	struct tcp_sock *tsock;
	char name[120];

	tsock = tsock_get_by_sid(sid);
	if (!tsock) {
		errno = EINVAL;
		return;
	}

	get_flow_name(tsock, name, sizeof(name));
	if (tsock->err)
		LOG("closing sock %s with error %s", name, strerror(tsock->err));
	else
		LOG("closing sock %s", name);

	if (tsock->close_issued == 0) {
		tsock->close_issued = 1;
		output_tsock_enqueue(tsock->worker, tsock);
	}
}

#define TSOCK_INFO_ASSIGN(x)	(info->x = tsock->x)

int tpa_sock_info_get(int sid, struct tpa_sock_info *info)
{
	struct tcp_sock *tsock;

	RTE_BUILD_BUG_ON(sizeof(*info) != 128);

	tsock = tsock_get_by_sid(sid);
	if (!tsock) {
		errno = EINVAL;
		return -1;
	}

	TSOCK_INFO_ASSIGN(worker);
	TSOCK_INFO_ASSIGN(local_ip);
	TSOCK_INFO_ASSIGN(remote_ip);
	TSOCK_INFO_ASSIGN(local_port);
	TSOCK_INFO_ASSIGN(remote_port);

	info->data = tsock->opts.data;

	return 0;
}

int listen_tsock_lookup(struct packet *pkt, struct tcp_sock **tsock_ptr)
{
	struct sock_key key;
	struct tcp_sock *tsock;

	memset(&key, 0, sizeof(key));
	key.local_port = ntohs(pkt->dst_port);

	tsock = sock_table_lookup_lock(&listen_sock_table, &key);
	if (!tsock)
		return -ERR_NO_SOCK;

	debug_assert(tsock->state == TCP_STATE_LISTEN);
	if (!tuple_matches(tsock, pkt))
		return -ERR_NO_SOCK;

	*tsock_ptr = tsock;

	return 0;
}

int tsock_lookup_slowpath(struct tpa_worker *worker, struct packet *pkt,
			  struct tcp_sock **tsock_ptr)
{
	struct sock_key key;
	struct tcp_sock *tsock;

	init_tpa_ip_from_pkt(pkt, &key.remote_ip, &key.local_ip);
	key.local_port  = ntohs(pkt->dst_port);
	key.remote_port = ntohs(pkt->src_port);

	tsock = sock_table_lookup(&worker->sock_table, &key);
	if (!tsock)
		return -ERR_NO_SOCK;

	if (tsock->sid < 0)
		return -WARN_STALE_PKT_TUPLE_MISMATCH;

	/* XXX: for bypassing WARN_STALE_PKT_WORKER_MISMATCH check */
	pkt->wid = worker->id;
	*tsock_ptr = tsock;

	return 0;
}

int sock_init_early(void)
{
	char path[PATH_MAX];
	size_t size;
	struct mem_file *mem_file;

	RTE_BUILD_BUG_ON((offsetof(struct sock_ctrl, socks) & 63) != 0);

	/* it may cfg tcp_cfg.nr_max_sock: need be done earlier */
	cfg_spec_register(tcp_cfg_specs, ARRAY_SIZE(tcp_cfg_specs));
	cfg_section_parse("tcp");

	if (tcp_cfg.keepalive < TCP_KEEPALIVE_MIN) {
		LOG_WARN("too small keepalive value: %d; keepalive is disabled", tcp_cfg.keepalive);
		tcp_cfg.keepalive = 0;
	}

	size = sizeof(struct sock_ctrl) + sizeof(struct tcp_sock) * tcp_cfg.nr_max_sock;

	tpa_snprintf(path, sizeof(path), "%s/%s", tpa_root_get(), "socks");
	tpa_cfg.sock_file = strdup(path);

	/* supports upto 10 million socks as memory allows */
	mem_file = mem_file_create_expandable(path, size, "sock-list",
					      sizeof(struct tcp_sock) * (10ul << 20));
	if (!mem_file)
		return -1;

	sock_ctrl = mem_file_data(mem_file);
	sock_ctrl->mem_file = mem_file;

	map_tsock_trace_file();

	return 0;
}

static void set_drop_ooo_threshold(void)
{
	struct rte_mempool *pool = packet_pool_get_mempool(generic_pkt_pool);

	if (tcp_cfg.drop_ooo_threshold)
		return;

	tcp_cfg.drop_ooo_threshold = (pool->size / tpa_cfg.nr_worker -
				      NR_RX_DESC * tpa_cfg.nr_dpdk_port) *
				     8 / 10;
}

/*
 * FIXME: regulate some cfgs based on the DPDK port capabilities.
 *
 * It's needed because of current the init order. So far we have:
 * - sock init early (which initializes the tcp cfg)
 * - dpdk init (which initializes the dpdk port capabilities)
 * - sock init (then regulates the some tcp cfgs)
 *
 */

#define REGULATE_TCP_CFG(option)		do {			\
	if (dev.option && tcp_cfg.option > dev.option) {		\
		LOG("%s (%u) is beyond the dev cap (%u); clamp it",	\
		    #option, tcp_cfg.option, dev.option);		\
		tcp_cfg.option = dev.option;				\
	}								\
} while (0)

static void sock_regulate_cfgs(void)
{
	REGULATE_TCP_CFG(pkt_max_chain);
	REGULATE_TCP_CFG(write_chunk_size);
}

static int tcp_cfg_set_with_regulation(struct cfg_spec *spec, const char *val)
{
	if (cfg_spec_set_num(spec, val) < 0)
		return -1;

	sock_regulate_cfgs();

	return 0;
}

int sock_init(void)
{
	int i;

	port_alloc_init();

	sock_table_init(&listen_sock_table);

	rte_spinlock_init(&sock_ctrl->lock);
	sock_ctrl->nr_max_sock = tcp_cfg.nr_max_sock;
	sock_ctrl->hz = rte_get_tsc_hz();
	sock_ctrl->workers = workers;
	rte_atomic32_set(&sock_ctrl->nr_sock, 0);

	for (i = 0; i < tcp_cfg.nr_max_sock; i++)
		sock_ctrl->socks[i].sid = TSOCK_SID_UNALLOCATED;

	tsock_trace_ctrl_init();

	set_drop_ooo_threshold();

	sock_regulate_cfgs();

	return 0;
}
