/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _TPA_ETH_H_
#define _TPA_ETH_H_

int eth_input(struct tpa_worker *worker, int port_id);
int parse_eth_ip(struct packet *pkt);

#endif
