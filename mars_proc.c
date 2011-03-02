// (c) 2011 Thomas Schoebel-Theuer / 1&1 Internet AG

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING
//#define IO_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include <linux/sysctl.h>
#include <linux/uaccess.h>

#define _STRATEGY
#include "mars.h"
#include "mars_proc.h"

mars_info_fn mars_info = NULL;

static
int mars_sysctl_handler(ctl_table *table,
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
		if (tmp)
			kfree(tmp);
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
ctl_table mars_table[] = {
	{
		.ctl_name       = CTL_UNNUMBERED,
		.procname	= "mars",
		.mode		= 0600,
		.proc_handler	= &mars_sysctl_handler,
	},
	{}
};

////////////////// module init stuff /////////////////////////

static struct ctl_table_header *header = NULL;

static int __init _init_proc(void)
{

	MARS_INF("init_proc()\n");
	
	header = register_sysctl_table(mars_table);

	return 0;
}

static void __exit _exit_proc(void)
{
	MARS_INF("exit_proc()\n");
	if (header) {
		unregister_sysctl_table(header);
		header = NULL;
	}
}

MODULE_DESCRIPTION("MARS /proc/ infrastructure");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(_init_proc);
module_exit(_exit_proc);
