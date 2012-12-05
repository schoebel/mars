// (c) 2011 Thomas Schoebel-Theuer / 1&1 Internet AG

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
#include "../mars_bio.h"
#include "../mars_aio.h"
#include "../mars_client.h"
#include "../mars_server.h"
#include "../mars_trans_logger.h"

mars_info_fn mars_info = NULL;

static
int trigger_sysctl_handler(
	ctl_table *table,
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
		char tmp[8] = {};
		int code = 0;

		res = len; // fake consumption of all data

		if (len > 7)
			len = 7;
		if (!copy_from_user(tmp, buffer, len)) {
			sscanf(tmp, "%d", &code);
			if (code) {
				mars_trigger();
				mars_remote_trigger();
			}
		}
	} else {
		char *answer = "MARS module not loaded\n";
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
	ctl_table *table,
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
		char *tmp = brick_string_alloc(len);
		struct timespec now = CURRENT_TIME;
		
		res = snprintf(tmp, len,
			       "CURRENT_TIME=%ld.%09ld\n"
			       "lamport_now=%ld.%09ld\n",
			       now.tv_sec, now.tv_nsec,
			       lamport_now.tv_sec, lamport_now.tv_nsec
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

#ifdef CONFIG_MARS_LOADAVG_LIMIT
int mars_max_loadavg = 0;
EXPORT_SYMBOL_GPL(mars_max_loadavg);
#endif

#ifdef CTL_UNNUMBERED
#define _CTL_NAME 		.ctl_name       = CTL_UNNUMBERED,
#define _CTL_STRATEGY(handler)	.strategy       = &handler,
#else
#define _CTL_NAME 		/*empty*/
#define _CTL_STRATEGY(handler)	/*empty*/
#endif

#define INT_ENTRY(NAME,VAR,MODE)			\
	{						\
		_CTL_NAME				\
		.procname	= NAME,			\
		.data           = &(VAR),		\
		.maxlen         = sizeof(int),		\
		.mode		= MODE,			\
		.proc_handler	= &proc_dointvec,	\
		_CTL_STRATEGY(sysctl_intvec)		\
	}

#define LIMITER_ENTRIES(VAR, PREFIX, SUFFIX)				\
	INT_ENTRY(PREFIX "_limit_" SUFFIX, (VAR)->lim_max_rate, 0600),	\
	INT_ENTRY(PREFIX "_rate_"  SUFFIX, (VAR)->lim_rate,     0400)	\

#define THRESHOLD_ENTRIES(VAR, PREFIX)					\
	INT_ENTRY(PREFIX "_threshold_us",   (VAR)->thr_limit,    0600),	\
	INT_ENTRY(PREFIX "_factor_percent", (VAR)->thr_factor,   0600),	\
	INT_ENTRY(PREFIX "_plus_us",        (VAR)->thr_plus,     0600),	\
	INT_ENTRY(PREFIX "_triggered",      (VAR)->thr_triggered,0400), \
	INT_ENTRY(PREFIX "_true_hit",       (VAR)->thr_true_hit, 0400)	\

static
ctl_table tuning_table[] = {
	LIMITER_ENTRIES(&client_limiter,           "traffic",         "kb"),
	LIMITER_ENTRIES(&server_limiter,           "server_io",       "kb"),
	LIMITER_ENTRIES(&global_writeback.limiter, "writeback",       "kb"),
	INT_ENTRY("writeback_until_percent", global_writeback.until_percent, 0600),
	THRESHOLD_ENTRIES(&bio_submit_threshold, "bio_submit"),
	THRESHOLD_ENTRIES(&bio_io_threshold[0],  "bio_io_r"),
	THRESHOLD_ENTRIES(&bio_io_threshold[1],  "bio_io_w"),
	THRESHOLD_ENTRIES(&aio_submit_threshold, "aio_submit"),
	THRESHOLD_ENTRIES(&aio_io_threshold[0],  "aio_io_r"),
	THRESHOLD_ENTRIES(&aio_io_threshold[1],  "aio_io_w"),
	THRESHOLD_ENTRIES(&aio_sync_threshold,   "aio_sync"),
	{}
};

static
ctl_table mars_table[] = {
	{
		_CTL_NAME
		.procname	= "trigger",
		.mode		= 0200,
		.proc_handler	= &trigger_sysctl_handler,
	},
	{
		_CTL_NAME
		.procname	= "lamport_clock",
		.mode		= 0400,
		.proc_handler	= &lamport_sysctl_handler,
	},
	INT_ENTRY("syslog_min_class",     brick_say_syslog_min,   0600),
	INT_ENTRY("syslog_max_class",     brick_say_syslog_max,   0600),
	INT_ENTRY("delay_say_on_overflow",delay_say_on_overflow,  0600),
	INT_ENTRY("mem_limit_percent",    mars_mem_percent,       0600),
	INT_ENTRY("logger_mem_used_kb",   trans_logger_mem_usage, 0400),
	INT_ENTRY("mem_used_raw_kb",      brick_global_block_used,0400),
	INT_ENTRY("io_flying_count",      mars_global_io_flying,  0400),
	INT_ENTRY("statusfiles_rollover_sec", rollover_time,      0600),
	INT_ENTRY("logrot_auto_gb",       global_logrot_auto,     0600),
	INT_ENTRY("logdel_auto_gb",       global_logdel_auto,     0600),
	INT_ENTRY("free_space_mb",        global_free_space,      0600),
#ifdef CONFIG_MARS_LOADAVG_LIMIT
	INT_ENTRY("loadavg_limit",        mars_max_loadavg,       0600),
#endif
	INT_ENTRY("network_io_timeout",   global_net_io_timeout,  0600),
	{
		_CTL_NAME
		.procname	= "tuning",
		.mode		= 0500,
		.child = tuning_table,
	},
	{}
};

static
ctl_table mars_root_table[] = {
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

void __exit exit_mars_proc(void)
{
	MARS_INF("exit_proc()\n");
	if (header) {
		unregister_sysctl_table(header);
		header = NULL;
	}
}

#ifndef CONFIG_MARS_HAVE_BIGMODULE
MODULE_DESCRIPTION("MARS /proc/ infrastructure");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_mars_proc);
module_exit(exit_mars_proc);
#endif
