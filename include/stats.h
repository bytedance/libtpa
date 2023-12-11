/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _STATS_H_
#define _STATS_H_

#include <stdint.h>

#include "lib/utils.h"

#define __STATS(stats, desc)	stats,
#define STATS(stats, desc)	__STATS(stats, desc)

enum stats_code {
#include "stats_code.h"
	STATS_MAX = 128,
};

static inline int stats_code_check(int stats)
{
	if ((uint32_t)stats >= STATS_MAX)
		return ERR_INVALID_STATS;

	return stats;
}

#define STATS_ADD(base, stats, n)		do {	\
	(base)[stats_code_check(stats)] += n;		\
} while (0)

#define TSOCK_STATS_INC(tsock, stats)		STATS_ADD((tsock)->stats_base, stats, 1)
#define TSOCK_STATS_ADD(tsock, stats, n)	STATS_ADD((tsock)->stats_base, stats, n)
#define TSOCK_STATS_DEC(tsock, stats, n)	STATS_ADD((tsock)->stats_base, stats, -n)

#define WORKER_STATS_INC(worker, stats)		STATS_ADD((worker)->stats_base, stats, 1)
#define WORKER_STATS_ADD(worker, stats, n)	STATS_ADD((worker)->stats_base, stats, n)
#define WORKER_STATS_DEC(worker, stats, n)	STATS_ADD((worker)->stats_base, stats, -n)


#define WORKER_TSOCK_STATS_INC(worker, tsock, stats)		do {	\
	WORKER_STATS_INC(worker, stats);				\
	if (tsock)							\
		TSOCK_STATS_INC(tsock, stats);				\
} while (0)

#define WORKER_TSOCK_STATS_ADD(worker, tsock, stats, n)		do {	\
	WORKER_STATS_ADD(worker, stats, n);				\
	if (tsock)							\
		TSOCK_STATS_ADD(tsock, stats, n);			\
} while (0)


/*
 * The atomic version, which is needed for stats updating
 * that might be outside the worker (that race may happen).
 */
#define STATS_ADD_ATOMIC(base, stats, n)		do {		\
	__sync_fetch_and_add_8(&(base)[stats_code_check(stats)], n);	\
} while (0)

#define TSOCK_STATS_INC_ATOMIC(tsock, stats)		STATS_ADD_ATOMIC((tsock)->stats_base, stats, 1)
#define TSOCK_STATS_ADD_ATOMIC(tsock, stats, n)		STATS_ADD_ATOMIC((tsock)->stats_base, stats, n)
#define TSOCK_STATS_DEC_ATOMIC(tsock, stats, n)		STATS_ADD_ATOMIC((tsock)->stats_base, stats, -n)

#define WORKER_STATS_INC_ATOMIC(worker, stats)		STATS_ADD_ATOMIC((worker)->stats_base, stats, 1)
#define WORKER_STATS_ADD_ATOMIC(worker, stats, n)	STATS_ADD_ATOMIC((worker)->stats_base, stats, n)
#define WORKER_STATS_DEC_ATOMIC(worker, stats, n)	STATS_ADD_ATOMIC((worker)->stats_base, stats, -n)


#define WORKER_TSOCK_STATS_INC_ATOMIC(worker, tsock, stats)	do {	\
	WORKER_STATS_INC_ATOMIC(worker, stats);				\
	if (tsock)							\
		TSOCK_STATS_INC_ATOMIC(tsock, stats);			\
} while (0)

#define WORKER_TSOCK_STATS_ADD_ATOMIC(worker, tsock, stats, n)	do {	\
	WORKER_STATS_ADD_ATOMIC(worker, stats, n);			\
	if (tsock)							\
		TSOCK_STATS_ADD_ATOMIC(tsock, stats, n);		\
} while (0)

/* auto resets avg after every 256K samples */
#define VSTAT_COUNT_BITS	18
#define VSTAT_MAX_COUNT		(1<<VSTAT_COUNT_BITS)

/* verbose stats */
struct vstats {
	uint64_t reset_seq:8;
	uint64_t sum:56;
	uint64_t max:(64 - VSTAT_COUNT_BITS);
	uint64_t count:VSTAT_COUNT_BITS;
};

extern uint8_t vstats_reset_seq;

static inline void vstats_add(struct vstats *vstats, uint64_t val)
{
	if (vstats->reset_seq != vstats_reset_seq) {
		vstats->max = 0;
		vstats->count = 0;
		vstats->sum = 0;
		vstats->reset_seq = vstats_reset_seq;
	}

	vstats->count += 1;
	vstats->sum += val;

	if (vstats->max < val)
		vstats->max = val;

	if (vstats->count == 0) {
		vstats->sum /= VSTAT_MAX_COUNT;
		vstats->count = 1;
	}
}

static inline uint64_t vstats_avg(struct vstats *vstats)
{
	uint64_t count;

	/*
	 * an extra assignment is needed due to ACCESS_ONCE won't
	 * work with bit-fields.
	 */
	count = vstats->count;
	count = ACCESS_ONCE(count);

	return count == 0 ? 0 : vstats->sum / count;
}

/*
 * like vstats, with max only
 */
struct vstats8_max {
	uint8_t reset_seq;
	uint8_t max;
};

static inline void vstats8_max_add(struct vstats8_max *vstats, uint8_t val)
{
	if (vstats->reset_seq != vstats_reset_seq) {
		vstats->max = 0;
		vstats->reset_seq = vstats_reset_seq;
	}

	if (vstats->max < val)
		vstats->max = val;
}

static inline uint8_t vstats8_max_get(struct vstats8_max *vstats)
{
	return vstats->max;
}

const char *stats_name(int stats);
const char *stats_desc(int stats);

#endif
