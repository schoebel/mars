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
#include "../mars_client.h"
#include "../mars_server.h"

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
int _proc_sysctl_handler(
	int class,
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
		res = len; // fake consumption of all data
	} else {
		int len;
		const char *answer = proc_say_get(class, &len);

		if (answer) {
			res = len;
			if (copy_to_user(buffer, answer, len)) {
				MARS_ERR("write %d bytes at %p failed\n", len, answer);
				res = -EFAULT;
			}
		}
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
int warnings_sysctl_handler(
	ctl_table *table,
	int write, 
	void __user *buffer,
	size_t *length,
	loff_t *ppos)
{
	return _proc_sysctl_handler(0, write, buffer, length, ppos);
}

static
int errors_sysctl_handler(
	ctl_table *table,
	int write, 
	void __user *buffer,
	size_t *length,
	loff_t *ppos)
{
	return _proc_sysctl_handler(1, write, buffer, length, ppos);
}

#ifdef CONFIG_MARS_LOADAVG_LIMIT
int mars_max_loadavg = 0;
EXPORT_SYMBOL_GPL(mars_max_loadavg);
#endif

static
ctl_table mars_table[] = {
	{
		.ctl_name       = CTL_UNNUMBERED,
		.procname	= "trigger",
		.mode		= 0200,
		.proc_handler	= &trigger_sysctl_handler,
	},
	{
		.ctl_name       = CTL_UNNUMBERED,
		.procname	= "warnings",
		.mode		= 0400,
		.proc_handler	= &warnings_sysctl_handler,
	},
	{
		.ctl_name       = CTL_UNNUMBERED,
		.procname	= "errors",
		.mode		= 0400,
		.proc_handler	= &errors_sysctl_handler,
	},
	{
		.ctl_name       = CTL_UNNUMBERED,
		.procname	= "percent_mem_limit_kb",
		.data           = &mars_mem_percent,
		.maxlen         = sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
		.strategy       = &sysctl_intvec,
	},
	{
		.ctl_name       = CTL_UNNUMBERED,
		.procname	= "logrot_auto_gb",
		.data           = &global_logrot_auto,
		.maxlen         = sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
		.strategy       = &sysctl_intvec,
	},
	{
		.ctl_name       = CTL_UNNUMBERED,
		.procname	= "logdel_auto_gb",
		.data           = &global_logdel_auto,
		.maxlen         = sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
		.strategy       = &sysctl_intvec,
	},
	{
		.ctl_name       = CTL_UNNUMBERED,
		.procname	= "free_space_mb",
		.data           = &global_free_space,
		.maxlen         = sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
		.strategy       = &sysctl_intvec,
	},
#ifdef CONFIG_MARS_LOADAVG_LIMIT
	{
		.ctl_name       = CTL_UNNUMBERED,
		.procname	= "loadavg_limit",
		.data           = &mars_max_loadavg,
		.maxlen         = sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
		.strategy       = &sysctl_intvec,
	},
#endif
	{
		.ctl_name       = CTL_UNNUMBERED,
		.procname	= "network_traffic_limit_kb",
		.data           = &client_limiter.lim_max_rate,
		.maxlen         = sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
		.strategy       = &sysctl_intvec,
	},
	{
		.ctl_name       = CTL_UNNUMBERED,
		.procname	= "server_io_limit_mb",
		.data           = &server_limiter.lim_max_rate,
		.maxlen         = sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
		.strategy       = &sysctl_intvec,
	},
	{}
};

static
ctl_table mars_root_table[] = {
	{
		.ctl_name       = CTL_UNNUMBERED,
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
