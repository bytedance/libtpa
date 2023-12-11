/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

static uint32_t srtt;
static uint32_t rttvar;
static uint32_t rto;

static void rtt_measure(int rtt)
{
	printf("rtt=%-3u ", rtt);

	if (srtt) {
		rtt -= (srtt >> 3);
		srtt  += rtt;

		if (rtt < 0)
			rtt = -rtt;
		rtt -= (rttvar >> 2);
		rttvar += rtt;
	} else {
		srtt   = rtt << 3;
		rttvar = rtt << 1;
	}

	rto = (srtt >> 3) + rttvar;

	printf("srtt=%-3u rttvar=%-3u rto=%-3u\n",
	       srtt >> 3, rttvar >> 2, rto);
}

int main(int argc, char *argv[])
{
	int i;
	int size = 0;
	int rtt;

	if (argv[1])
		size = atoi(argv[1]);
	if (size == 0)
		size = 10;

	for (i = 0; i < size; i++) {
		rtt = 1 + rand() % 50;
		if (rand() % 100 <= 1)
			rtt += rand() % 50000;
		rtt_measure(rtt);
	}

	return 0;
}
