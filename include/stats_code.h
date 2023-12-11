/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
/*
 * Here we mix the error code with the regural stats, which may sound
 * a bit strange, but hey, error code should be also counted, say how
 * many pkts hit an error like "ERR_NO_SOCK".
 */
STATS(ERR_INVALID_STATS, "invalid error code")
STATS(ERR_NOT_IMPLEMENTED, "related function not implemented yet")

STATS(ERR_PKT_ALLOC_FAIL, "failed to allocate packet")
STATS(ERR_PKT_PREPEND_HDR, "failed to prepend protocol header")
STATS(ERR_PKT_INVALID_LEN, "invalid packet length")
STATS(ERR_PKT_NOT_TCP, "not tcp packet")

STATS(ERR_BAD_CSUM_IPV4, "ipv4 checksum error")
STATS(ERR_BAD_CSUM_TCP,  "tcp checksum error")
STATS(ERR_BAD_CSUM_L4,   "other l4(none-TCP) checksum error")

STATS(ERR_TCP_INVALID_SEQ,   "invalid seq")
STATS(ERR_TCP_INVALID_ACK,   "invalid ack")
STATS(ERR_TCP_INVALID_TS,    "invalid TS opt")
STATS(ERR_TCP_NO_ACK,        "the expected ACK bit is not set")
STATS(ERR_TCP_OLD_ACK,       "ACK something already ACKed; not a real error")
STATS(ERR_TCP_RXQ_ENQUEUE_FAIL,   "tcp rxq is full")
STATS(ERR_TCP_RCV_INVALID_STATE,  "invalid tcp state on receiving data")
STATS(ERR_TCP_RCV_OOO_LIMIT,  "too many out of order packets received")
STATS(ERR_TCP_RCV_OOO_DUP,  "out of order duplicated packets received")
STATS(ERR_INVALID_STATE_FOR_FIN, "got a FIN pkt while the state is invalid")

STATS(WARN_HALF_OPEN_DETECTED, "number of half open status detected")

STATS(TCP_RTO_TIME_OUT,   "number of times that RTO times out")
STATS(TCP_DACK_TIME_OUT,  "number of times that DACK times out")
STATS(TCP_WAIT_TIME_OUT,  "number of times that TIME_WAIT times out")
STATS(ERR_TCP_TIMER_INVALID_TYPE,  "invalid tcp timer type")
STATS(ERR_TCP_TIMEOUT_ON_CLOSED,  "got timeout events on close state")

STATS(ERR_NO_SOCK, "no sock found")
STATS(ERR_INVALID_ACK, "invalid ack")
STATS(ERR_INVALID_SYN_SENT_PROCESS, "unknown error met while handling SYN_XMIT state")
STATS(ERR_NO_SYN_AND_RST, "no syn nor rst flag found")
STATS(ERR_RST_WITH_NO_ACK, "rst flag is set while no ACK found")
STATS(WARN_GOT_RST_AT_TIME_WAIT, "got rst packet at TIME_WAIT state")

STATS(ERR_INVALID_TCP_OPT_TYPE, "invalid tcp option type")
STATS(ERR_INVALID_TCP_OPT_LEN, "invalid tcp option len")

STATS(ERR_DEV_TXQ_FULL, "net device txq is full")

STATS(ERR_FLOW_MARK_INVALID, "invalid flow mark")
STATS(WARN_MISSING_FLOW_MARK, "missing flow mark")
STATS(HAS_FLOW_MARK, "has flow mark")

STATS(ERR_CONN_REFUSED, "connection refused")

STATS(PKT_IP_FRAG, "number of ip fragments")

STATS(PKT_RECV,   "packets received")
STATS(BYTE_RECV,  "bytes received")
STATS(BYTE_RECV_FASTPATH,  "bytes received in fastpath")
STATS(PKT_RECV_OOO,   "out of order packets received")
STATS(PKT_RECV_OOO_PREDICT, "number of predicted out of order packets received")
STATS(PKT_RECV_AFTER_CLOSE, "packets received after close")

STATS(PKT_XMIT,   "packets transmitted")
STATS(BYTE_XMIT,  "bytes transmitted")

STATS(BYTE_FAST_RE_XMIT,    "bytes retransmitted triggered by fast retransmit")
STATS(BYTE_RE_XMIT,         "bytes retransmitted, with fast retrans included")
STATS(PKT_FAST_RE_XMIT,     "packets retransmitted triggered by fast retransmit")
STATS(PKT_FAST_RE_XMIT_ERR, "packets retransmitted failed by fast retransmit")
STATS(PKT_RE_XMIT,          "packets retransmitted, with fast retrans included")

STATS(PKT_HDR_ONLY,   "number of packets allocated for storing tcp hdr only")
STATS(ZWRITE_FALLBACK_PKTS, "packets fallbacked to memcpy when zero copy is expected")
STATS(ZWRITE_FALLBACK_BYTES, "bytes fallbacked to memcpy when zero copy is expected")

STATS(PURE_ACK_IN,   "pure ACK packets received")
STATS(PURE_ACK_OUT,  "pure ACK packets sent out")
STATS(WARN_QUICKACK_RESET, "number of times go back to quickack again")

STATS(SYN_XMIT, "SYN packets transmitted")
STATS(FIN_XMIT, "FIN packets transmitted")
STATS(RST_XMIT, "RST packets transmitted")
STATS(SIMULTANEOUS_CONNECT, "simultaneous connect")

STATS(WRITE_EAGAIN, "number of times EAGAIN returned in write path")
STATS(READ_EAGAIN,  "number of times EAGAIN returned in read path")

STATS(RECLAIM_HALF_OPEN_TSOCK,     "number of half-open socks reclaimed at startup")
STATS(ERR_RECLAIM_HALF_OPEN_TSOCK, "number of times reclaiming a half-open sock failed")

STATS(ARP_SOLICIT,       "number of arp solicitation sent")
STATS(ERR_ARP_SOLICIT,   "number of times we failed to send an arp solicitation")
STATS(ERR_NEIGH_ENQUEUE, "number of times we failed to enqueue a pkt waiting for neigh response")
STATS(ERR_NEIGH_FLUSH_ENQUEUE, "number of times we failed to enqueue a pkt to worker's neigh_flush_queue")
STATS(WARN_NEIGH_CHANGED, "number of neigh entry changed")

STATS(ERR_WRITE_TOO_MANY_IOV, "nr_iov provided by zwritev is too big")
STATS(ERR_WRITE_TOO_BIG_BUFF, "probably one of iov has too big buf size")

STATS(WARN_STALE_PKT_TUPLE_MISMATCH,  "pkts recv-ed that doesn't match the tsock tuple after offload flow destroy")
STATS(WARN_STALE_PKT_WORKER_MISMATCH, "pkts recv-ed that doesn't match the tsock's assigned worker after offload flow destroy")

STATS(WARN_RST_RECV, "number of rst pkts received")

STATS(NDP_SOLICIT,       "number of ndp solicitation sent")
STATS(ERR_NDP_SOLICIT,   "number of times we failed to send an ndp solicitation")

STATS(ERR_PKT_HAS_IPV6_OPT, "number of pkts have ipv6 options")

STATS(ZERO_WND_PROBE, "number of zero wnd probe sent")
STATS(WND_UPDATE, "number of wnd update")

STATS(SOCK_OFFLOAD_FAILURE, "failed to offload a connection")

STATS(WARN_ACK_AT_LISTEN, "number of pkts have ACK set at LISTEN state")
STATS(ERR_TOO_MANY_SOCKS, "too many socks created")

STATS(WARN_INVLIAD_PKT_AT_LISTEN, "got a pkt at listen state with no rst|ack|syn set")
STATS(WARN_INVLIAD_SYN_RCVD, "likely we rcved a dup syn")

STATS(PKT_RECV_MERGE, "number of incomping pkts merged")

STATS(TCP_KEEPALIVE_PROBE, "number of tcp keepalive probes")
STATS(TCP_KEEPALIVE_TIME_OUT, "tcp keepalive probe times out")

STATS(PORT_BLOCK_OFFLOAD_FAILURE, "failed to offload a port block")

STATS(OOO_MBUF_DROPPED, "number of out of order mbuf segments dropped")
STATS(ERR_TCP_SACK_INTERSECT, "number of tcp sack opts that have sack intersection")
