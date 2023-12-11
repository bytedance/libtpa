/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/prctl.h>
#include <linux/limits.h>

#include "log.h"
#include "cfg.h"

#undef LOG_DEBUG
#undef LOG_ERR
#include <syslog.h>

struct log_ctrl {
	int level;
	char file[PATH_MAX];

	int fd;
	int pid;
	char program[64];
};

static struct log_ctrl log_ctrl = {
	.level = LOG_LEVEL_INFO,
	.fd = -1,
};

static struct cfg_spec log_cfg_specs[] = {
	{
		.name = "log.level",
		.type = CFG_TYPE_UINT,
		.data = &log_ctrl.level,
	}, {
		.name  = "log.file",
		.type  = CFG_TYPE_STR,
		.flags = CFG_FLAG_RDONLY,
		.data  = log_ctrl.file,
		.data_len = sizeof(log_ctrl.file),
	},
};

static int log_file_prefix(char *buf, int size)
{
	struct timeval now;
	int len;

	gettimeofday(&now, NULL);
	len = strftime(buf, size, "%Y-%m-%d %T", localtime(&now.tv_sec));
	len += tpa_snprintf(buf + len, size - len, ".%06lu [%d %s] ",
			   now.tv_usec % 1000000, log_ctrl.pid, log_ctrl.program);

	return len;
}

static void log_file_write(char *buf, int len, int size)
{
	int ret;

	if (len >= size - 1)
		len = size - 1;
	buf[len++] = '\n';

	ret = write(log_ctrl.fd, buf, len);
	if (ret != len) {
		syslog(LOG_WARNING, "failed to write to log file: %s: %s; fallback to syslog",
		       log_ctrl.file, strerror(errno));
		log_ctrl.fd = -1;
	}
}

static void log_file_init(void)
{
	char *file = log_ctrl.file;
	int fd;

	if (strlen(file) == 0)
		return;

	fd = open(file, O_WRONLY | O_CREAT | O_APPEND, 0600);
	if (fd < 0) {
		tpa_log(LOG_LEVEL_WARN, "failed to open log file: %s: %s",
			   file, strerror(errno));
		return;
	}

	log_ctrl.fd = fd;
	log_ctrl.pid = getpid();
	prctl(PR_GET_NAME, log_ctrl.program, sizeof(log_ctrl.program));
}

void tpa_log(int level, const char *fmt, ...)
{
	char buf[4096];
	int len = 0;
	va_list ap;
	int prio;

	if (level > log_ctrl.level || getenv("TPA_LOG_DISABLE"))
		return;

	va_start(ap, fmt);
	if (log_ctrl.fd >= 0)
		len = log_file_prefix(buf, sizeof(buf));
	len += tpa_snprintf(buf + len, sizeof(buf) - len, "tpa: ");
	len += vsnprintf(buf + len, sizeof(buf) - len, fmt, ap);
	va_end(ap);

	switch (level) {
	case LOG_LEVEL_ERR:
		prio = LOG_ERR;
		break;
	case LOG_LEVEL_WARN:
		prio = LOG_WARNING;
		break;
	case LOG_LEVEL_INFO:
		prio = LOG_INFO;
		break;
	case LOG_LEVEL_DEBUG:
		prio = LOG_DEBUG;
		break;
	default:
		prio = LOG_INFO;
		break;
	}

	if (log_ctrl.fd >= 0)
		log_file_write(buf, len, sizeof(buf));
	else
		syslog(prio, "%s", buf);
}

void log_init(void)
{
	cfg_spec_register(log_cfg_specs, ARRAY_SIZE(log_cfg_specs));
	cfg_section_parse("log");

	log_file_init();
}
