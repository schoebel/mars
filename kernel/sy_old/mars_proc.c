/*
 * MARS Long Distance Replication Software
 *
 * This file is part of MARS project: http://schoebel.github.io/mars/
 *
 * Copyright (C) 2010-2014 Thomas Schoebel-Theuer
 * Copyright (C) 2011-2014 1&1 Internet AG
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING
//#define IO_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include <linux/sysctl.h>
#include <linux/uaccess.h>

#include "strategy.h"
#include "mars_proc.h"
#include "../lib_mapfree.h"
#include "../mars_bio.h"
#include "../mars_aio.h"
#include "../mars_if.h"
#include "../mars_copy.h"
#include "../mars_client.h"
#include "../mars_server.h"
#include "../mars_trans_logger.h"

#include "../buildtag.h"

const char mars_version_string[] = BUILDTAG " (" BUILDHOST " " BUILDDATE ") "
#ifndef CONFIG_MARS_DEBUG
	"production"
#else
	"DEBUG"
#endif
#ifdef CONFIG_MARS_DEBUG_MEM
	" BAD_PERFORMANCE"
#endif
#ifdef CONFIG_MARS_DEBUG_ORDER0
	" EVIL_PERFORMANCE"
#endif
	;

mars_info_fn mars_info = NULL;

static
void interpret_user_message(char *msg)
{
	char cmd = msg[0];
	char *rest = msg + 1;

	while (*rest == ' ')
		rest++;

	switch (cmd) {
	case 'l': /* write to syslog via say logging */
		MARS_INF("%s\n", rest);
		break;

	case 'L': /* write to syslog via printk */
		printk("%s\n", rest);
		break;

	case 't': /* new trigger code conventions */
	{
		int code = 0;

		sscanf(rest, "%d", &code);
		mars_remote_trigger(code);
		break;
	}

	default:
		MARS_DBG("unknown user message '%s'\n", msg);
	}
}

static
int trigger_sysctl_handler(
	struct ctl_table *table,
	int write, 
	void __user *buffer,
	size_t *length,
	loff_t *ppos)
{
	ssize_t res = 0;
	size_t len = *length;

	MARS_DBG("write = %d len = %ld pos = %lld\n", write, len, *ppos);

	if (len <= 0 || *ppos > 0) {
		goto done;
	}

	if (write) {
		char *tmp = brick_string_alloc(len + 1);

		res = len; // fake consumption of all data

		if (copy_from_user(tmp, buffer, len)) {
			MARS_ERR("cannot read %ld bytes from trigger\n", len);
			goto dealloc;
		}

		tmp[len] = '\0';
		/* Deprecated, to disappear */
		if (tmp[0] == ' ' ||
		    (tmp[0] >= '0' && tmp[0] <= '9')) {
			int code = 0;

			sscanf(tmp, "%d", &code);
			/* Compatible to old bahviour.
			 * Please use the new "t" codes instead.
			 */
			if (code >= 8) {
				mars_remote_trigger(MARS_TRIGGER_LOCAL | MARS_TRIGGER_FROM_REMOTE | MARS_TRIGGER_TO_REMOTE_ALL | MARS_TRIGGER_FULL);
			} else if (code >= 3) {
				mars_remote_trigger(MARS_TRIGGER_LOCAL | MARS_TRIGGER_FROM_REMOTE | MARS_TRIGGER_TO_REMOTE_ALL);
			} else if (code >= 2) {
				mars_remote_trigger(MARS_TRIGGER_LOCAL | MARS_TRIGGER_TO_REMOTE);
			} else if (code >= 1) {
				mars_remote_trigger(MARS_TRIGGER_LOCAL);
			}
		} else {
			interpret_user_message(tmp);
		}
	dealloc:
		brick_string_free(tmp);	
	} else {
		char *answer = "MARS module not operational\n";
		char *tmp = NULL;
		int mylen;

		if (mars_info) {
			answer = "internal error while determining mars_info\n";
			tmp = mars_info();
			if (tmp)
				answer = tmp;
		}

		mylen = strlen(answer);
		if (len > mylen)
			len = mylen;
		res = len;
		if (copy_to_user(buffer, answer, len)) {
			MARS_ERR("write %ld bytes at %p failed\n", len, buffer);
			res = -EFAULT;
		}
		brick_string_free(tmp);
	}

done:
	MARS_DBG("res = %ld\n", res);
	*length = res;
	if (res >= 0) {
	        *ppos += res;
		return 0;
	}
	return res;
}

static
int lamport_sysctl_handler(
	struct ctl_table *table,
	int write, 
	void __user *buffer,
	size_t *length,
	loff_t *ppos)
{
	ssize_t res = 0;
	size_t len = *length;

	MARS_DBG("write = %d len = %ld pos = %lld\n", write, len, *ppos);

	if (!len || *ppos > 0) {
		goto done;
	}

	if (write) {
		return -EINVAL;
	} else {
		int my_len = 128;
		char *tmp = brick_string_alloc(my_len);
		struct lamport_time know;
		struct lamport_time lnow;

		get_lamport(&know, &lnow);
		
		res = scnprintf(tmp, my_len,
			       "CURRENT_TIME=%ld.%09ld\n"
			       "lamport_now=%ld.%09ld\n",
			       know.tv_sec, know.tv_nsec,
			       lnow.tv_sec, lnow.tv_nsec
			);

		if (copy_to_user(buffer, tmp, res)) {
			MARS_ERR("write %ld bytes at %p failed\n", res, buffer);
			res = -EFAULT;
		}
		brick_string_free(tmp);
	}

done:
	MARS_DBG("res = %ld\n", res);
	*length = res;
	if (res >= 0) {
	        *ppos += res;
		return 0;
	}
	return res;
}

#ifdef CTL_UNNUMBERED
#define _CTL_NAME 		.ctl_name       = CTL_UNNUMBERED,
#define _CTL_STRATEGY(handler)	.strategy       = &handler,
#else
#define _CTL_NAME 		/*empty*/
#define _CTL_STRATEGY(handler)	/*empty*/
#endif

#define VEC_ENTRY(NAME,VAR,MODE,COUNT)			\
	{						\
		_CTL_NAME				\
		.procname	= NAME,			\
		.data           = &(VAR),		\
		.maxlen         = sizeof(int) * (COUNT),\
		.mode		= MODE,			\
		.proc_handler	= &proc_dointvec,	\
		_CTL_STRATEGY(sysctl_intvec)		\
	}

#define INT_ENTRY(NAME,VAR,MODE)			\
	VEC_ENTRY(NAME, VAR, MODE, 1)

#define LIMITER_ENTRIES(VAR, PREFIX, SUFFIX)				\
	INT_ENTRY(PREFIX "_total_ops",          (VAR)->lim_total_ops,    0400), \
	INT_ENTRY(PREFIX "_total_" SUFFIX,      (VAR)->lim_total_amount, 0400), \
	INT_ENTRY(PREFIX "_ratelimit_ops",      (VAR)->lim_max_ops_rate, 0600), \
	INT_ENTRY(PREFIX "_ratelimit_" SUFFIX,  (VAR)->lim_max_amount_rate, 0600), \
	INT_ENTRY(PREFIX "_maxdelay_ms",   (VAR)->lim_max_delay,0600),	\
	INT_ENTRY(PREFIX "_minwindow_ms",  (VAR)->lim_min_window,0600),	\
	INT_ENTRY(PREFIX "_maxwindow_ms",  (VAR)->lim_max_window,0600),	\
	INT_ENTRY(PREFIX "_cumul_ops",     (VAR)->lim_ops_cumul,       0600),	\
	INT_ENTRY(PREFIX "_cumul_" SUFFIX, (VAR)->lim_amount_cumul,    0600),	\
	INT_ENTRY(PREFIX "_rate_ops",      (VAR)->lim_ops_rate,        0400), \
	INT_ENTRY(PREFIX "_rate_"  SUFFIX, (VAR)->lim_amount_rate,     0400)	\

#define THRESHOLD_ENTRIES(VAR, PREFIX)					\
	INT_ENTRY(PREFIX "_threshold_us",   (VAR)->thr_limit,    0600),	\
	INT_ENTRY(PREFIX "_factor_percent", (VAR)->thr_factor,   0600),	\
	INT_ENTRY(PREFIX "_plus_us",        (VAR)->thr_plus,     0600),	\
	INT_ENTRY(PREFIX "_max_ms",         (VAR)->thr_max,      0600),	\
	INT_ENTRY(PREFIX "_triggered",      (VAR)->thr_triggered,0400), \
	INT_ENTRY(PREFIX "_true_hit",       (VAR)->thr_true_hit, 0400)	\

static
struct ctl_table traffic_tuning_table[] = {
	LIMITER_ENTRIES(&client_limiter,    "client_role_traffic",    "kb"),
	LIMITER_ENTRIES(&server_limiter,    "server_role_traffic",    "kb"),
	{}
};

static
struct ctl_table io_tuning_table[] = {
	LIMITER_ENTRIES(&global_writeback.limiter, "writeback",       "kb"),
	INT_ENTRY("writeback_until_percent", global_writeback.until_percent, 0600),
	THRESHOLD_ENTRIES(&global_io_threshold,  "global_io"),
	INT_ENTRY("bio_nr_requests", bio_nr_requests, 0600),
	THRESHOLD_ENTRIES(&bio_submit_threshold, "bio_submit"),
	THRESHOLD_ENTRIES(&bio_io_threshold[0],  "bio_io_r"),
	THRESHOLD_ENTRIES(&bio_io_threshold[1],  "bio_io_w"),
	THRESHOLD_ENTRIES(&aio_submit_threshold, "aio_submit"),
	THRESHOLD_ENTRIES(&aio_io_threshold[0],  "aio_io_r"),
	THRESHOLD_ENTRIES(&aio_io_threshold[1],  "aio_io_w"),
	THRESHOLD_ENTRIES(&aio_sync_threshold,   "aio_sync"),
	INT_ENTRY("if_nr_requests", if_nr_requests, 0600),
	{}
};

#define TCP_ENTRY(NAME,TRAFFIC_TYPE)				\
	INT_ENTRY(#NAME, mars_tcp_params[TRAFFIC_TYPE].NAME, 0600)

#define make_tcp_tuning_table(TRAFFIC_TYPE)			\
static								\
struct ctl_table tcp_tuning_table_##TRAFFIC_TYPE[] = {		\
	TCP_ENTRY(ip_tos, TRAFFIC_TYPE),			\
	TCP_ENTRY(tcp_window_size, TRAFFIC_TYPE),		\
	TCP_ENTRY(tcp_nodelay, TRAFFIC_TYPE),			\
	TCP_ENTRY(tcp_timeout, TRAFFIC_TYPE),			\
	TCP_ENTRY(tcp_keepcnt, TRAFFIC_TYPE),	       		\
	TCP_ENTRY(tcp_keepintvl, TRAFFIC_TYPE),	       		\
	TCP_ENTRY(tcp_keepidle, TRAFFIC_TYPE),	       		\
	{}							\
}

make_tcp_tuning_table(MARS_TRAFFIC_META);
make_tcp_tuning_table(MARS_TRAFFIC_REPLICATION);
make_tcp_tuning_table(MARS_TRAFFIC_SYNC);

static
struct ctl_table mars_table[] = {
	{
		_CTL_NAME
		.procname	= "version",
		.data           = (char*)mars_version_string,
		.maxlen         = sizeof(mars_version_string),
		.mode		= 0400,
		.proc_handler	= &proc_dostring,
	},
	{
		_CTL_NAME
		.procname	= "trigger",
		.mode		= 0200,
		.proc_handler	= &trigger_sysctl_handler,
	},
	{
		_CTL_NAME
		.procname	= "info",
		.mode		= 0400,
		.proc_handler	= &trigger_sysctl_handler,
	},
	{
		_CTL_NAME
		.procname	= "lamport_clock",
		.mode		= 0400,
		.proc_handler	= &lamport_sysctl_handler,
	},
	INT_ENTRY("max_lamport_future",   max_lamport_future,     0600),
	INT_ENTRY("show_log_messages",    brick_say_logging,      0600),
	INT_ENTRY("show_debug_messages",  brick_say_debug,        0600),
	INT_ENTRY("show_statistics_global", global_show_statist,  0600),
	INT_ENTRY("show_statistics_server", server_show_statist,  0600),
	INT_ENTRY("show_connections",     global_show_connections, 0600),
	INT_ENTRY("aio_sync_mode",        aio_sync_mode,          0600),
#ifdef CONFIG_MARS_DEBUG
	INT_ENTRY("debug_crash_mode",     mars_crash_mode,        0600),
	INT_ENTRY("debug_hang_mode",      mars_hang_mode,         0600),
#endif
	INT_ENTRY("logger_completion_semantics", trans_logger_completion_semantics, 0600),
	INT_ENTRY("logger_do_crc",        trans_logger_do_crc,    0600),
	INT_ENTRY("logger_allow_compress", trans_logger_allow_compress, 0600),
	INT_ENTRY("zlib_compress_level",  mars_zlib_compression_level, 0600),
	INT_ENTRY("syslog_min_class",     brick_say_syslog_min,   0600),
	INT_ENTRY("syslog_max_class",     brick_say_syslog_max,   0600),
	INT_ENTRY("syslog_flood_class",   brick_say_syslog_flood_class, 0600),
	INT_ENTRY("syslog_flood_limit",   brick_say_syslog_flood_limit, 0600),
	INT_ENTRY("syslog_flood_recovery_s", brick_say_syslog_flood_recovery, 0600),
	INT_ENTRY("delay_say_on_overflow",delay_say_on_overflow,  0600),
	INT_ENTRY("mapfree_period_sec",   mapfree_period_sec,     0600),
	INT_ENTRY("mapfree_grace_keep_mb", mapfree_grace_keep_mb, 0600),
	INT_ENTRY("logger_pressure_limit", trans_logger_pressure_limit, 0600),
	INT_ENTRY("logger_disable_pressure", trans_logger_disable_pressure, 0600),
	INT_ENTRY("logger_writeback_maxage_s", trans_logger_writeback_maxage, 0600),
	INT_ENTRY("logger_report_interval_s", trans_logger_report_interval, 0600),
	INT_ENTRY("logger_max_interleave", trans_logger_max_interleave, 0600),
	INT_ENTRY("logger_resume",        trans_logger_resume,    0600),
	INT_ENTRY("logger_replay_timeout_sec", trans_logger_replay_timeout, 0600),
	INT_ENTRY("mem_limit_percent",    mars_mem_percent,       0600),
	INT_ENTRY("mem_limit_gb",         mars_mem_gb,            0600),
	INT_ENTRY("logger_mem_used_kb",   trans_logger_mem_usage, 0400),
	INT_ENTRY("mem_used_raw_kb",      brick_global_block_used,0400),
#ifdef CONFIG_MARS_MEM_PREALLOC
	INT_ENTRY("mem_allow_freelist",   brick_allow_freelist,   0600),
	VEC_ENTRY("mem_freelist_max",     brick_mem_freelist_max,  0600, BRICK_MAX_ORDER+1),
	VEC_ENTRY("mem_alloc_count",      brick_mem_alloc_count,  0400, BRICK_MAX_ORDER+1),
	VEC_ENTRY("mem_alloc_max",        brick_mem_alloc_count,  0600, BRICK_MAX_ORDER+1),
#endif
	INT_ENTRY("io_flying_count",      mars_global_io_flying,  0400),
	INT_ENTRY("copy_overlap",         mars_copy_overlap,      0600),
	INT_ENTRY("copy_strict_write_order", mars_copy_strict_write_order, 0600),
	INT_ENTRY("copy_timeout",         mars_copy_timeout,      0600),
	INT_ENTRY("copy_read_prio",       mars_copy_read_prio,    0600),
	INT_ENTRY("copy_write_prio",      mars_copy_write_prio,   0600),
	INT_ENTRY("copy_read_max_fly",    mars_copy_read_max_fly, 0600),
	INT_ENTRY("copy_write_max_fly",   mars_copy_write_max_fly,0600),
	INT_ENTRY("statusfiles_rollover_sec", mars_rollover_interval, 0600),
	INT_ENTRY("scan_interval_sec",    mars_scan_interval,     0600),
	INT_ENTRY("propagate_interval_sec", mars_propagate_interval, 0600),
	INT_ENTRY("sync_flip_interval_sec", mars_sync_flip_interval, 0600),
	INT_ENTRY("additional_peers_running", mars_running_additional_peers, 0400),
	INT_ENTRY("additional_peers_to_run", mars_run_additional_peers, 0600),
	INT_ENTRY("peer_abort",           mars_peer_abort,        0600),
	INT_ENTRY("client_abort",         mars_client_abort,      0600),
	INT_ENTRY("do_fast_fullsync",     mars_fast_fullsync,     0600),
	INT_ENTRY("logrot_auto_gb",       global_logrot_auto,     0600),
	INT_ENTRY("remaining_space_kb",   global_remaining_space, 0400),
	INT_ENTRY("required_total_space_0_gb", global_free_space_0, 0600),
	INT_ENTRY("required_free_space_1_gb", global_free_space_1, 0600),
	INT_ENTRY("required_free_space_2_gb", global_free_space_2, 0600),
	INT_ENTRY("required_free_space_3_gb", global_free_space_3, 0600),
	INT_ENTRY("required_free_space_4_gb", global_free_space_4, 0600),
	INT_ENTRY("sync_nr",              global_sync_nr,         0400),
	INT_ENTRY("sync_limit",           global_sync_limit,      0600),
	INT_ENTRY("handler_dent_limit",    dent_limit,             0600),
	INT_ENTRY("handler_dent_retry",    dent_retry,             0600),
	INT_ENTRY("handler_limit",         handler_limit,          0600),
	INT_ENTRY("mars_emergency_mode",  mars_emergency_mode,    0600),
	INT_ENTRY("mars_reset_emergency", mars_reset_emergency,   0600),
	INT_ENTRY("mars_keep_msg_s",      mars_keep_msg,          0600),
	INT_ENTRY("write_throttle_start_percent", mars_throttle_start,    0600),
	INT_ENTRY("write_throttle_end_percent",   mars_throttle_end,      0600),
	INT_ENTRY("write_throttle_size_threshold_kb", if_throttle_start_size, 0400),
	LIMITER_ENTRIES(&if_throttle,     "write_throttle",       "kb"),
	// changing makes no sense because the server will immediately start upon modprobe
	INT_ENTRY("mars_port",            mars_net_default_port,  0400),
	INT_ENTRY("network_io_timeout",   global_net_io_timeout,  0600),
	INT_ENTRY("client_info_timeout",  mars_client_info_timeout, 0600),
	INT_ENTRY("parallel_connections", max_client_channels,    0600),
	INT_ENTRY("parallel_bulk_feed",   max_client_bulk,        0600),
	{
		_CTL_NAME
		.procname	= "traffic_tuning",
		.mode		= 0500,
		.child = traffic_tuning_table,
	},
	{
		_CTL_NAME
		.procname	= "io_tuning",
		.mode		= 0500,
		.child = io_tuning_table,
	},
	{
		_CTL_NAME
		.procname	= "tcp_tuning_0_meta_traffic",
		.mode		= 0500,
		.child = tcp_tuning_table_MARS_TRAFFIC_META,
	},
	{
		_CTL_NAME
		.procname	= "tcp_tuning_1_replication_traffic",
		.mode		= 0500,
		.child = tcp_tuning_table_MARS_TRAFFIC_REPLICATION,
	},
	{
		_CTL_NAME
		.procname	= "tcp_tuning_2_sync_traffic",
		.mode		= 0500,
		.child = tcp_tuning_table_MARS_TRAFFIC_SYNC,
	},
	{}
};

static
struct ctl_table mars_root_table[] = {
	{
		_CTL_NAME
		.procname	= "mars",
		.mode		= 0500,
		.child = mars_table,
	},
	{}
};

////////////////// module init stuff /////////////////////////

static struct ctl_table_header *header = NULL;

int __init init_mars_proc(void)
{

	MARS_INF("init_proc()\n");

	header = register_sysctl_table(mars_root_table);

	return 0;
}

void exit_mars_proc(void)
{
	MARS_INF("exit_proc()\n");
	if (header) {
		unregister_sysctl_table(header);
		header = NULL;
	}
}
