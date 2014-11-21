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

#include "strategy.h"
#include "../mars_net.h"

static
char *_mars_translate_hostname(const char *name)
{
	struct mars_global *global = mars_global;
	char *res = brick_strdup(name);
	struct mars_dent *test;
	char *tmp;

	if (unlikely(!global)) {
		goto done;
	}

	for (tmp = res; *tmp; tmp++) {
		if (*tmp == ':') {
			*tmp = '\0';
			break;
		}
	}

	tmp = path_make("/mars/ips/ip-%s", res);
	if (unlikely(!tmp)) {
		goto done;
	}

	test = mars_find_dent(global, tmp);
	if (test && test->new_link) {
		MARS_DBG("'%s' => '%s'\n", tmp, test->new_link);
		brick_string_free(res);
		res = brick_strdup(test->new_link);
	} else {
		MARS_DBG("no translation for '%s'\n", tmp);
	}
	brick_string_free(tmp);

done:
	return res;
}

int mars_send_dent_list(struct mars_socket *sock, struct list_head *anchor)
{
	struct list_head *tmp;
	struct mars_dent *dent;
	int status = 0;
	for (tmp = anchor->next; tmp != anchor; tmp = tmp->next) {
		dent = container_of(tmp, struct mars_dent, dent_link);
		status = mars_send_struct(sock, dent, mars_dent_meta);
		if (status < 0)
			break;
	}
	if (status >= 0) { // send EOR
		status = mars_send_struct(sock, NULL, mars_dent_meta);
	}
	return status;
}
EXPORT_SYMBOL_GPL(mars_send_dent_list);

int mars_recv_dent_list(struct mars_socket *sock, struct list_head *anchor)
{
	int status;
	for (;;) {
		struct mars_dent *dent = brick_zmem_alloc(sizeof(struct mars_dent));
		if (!dent)
			return -ENOMEM;

		//MARS_IO("\n");

		INIT_LIST_HEAD(&dent->dent_link);
		INIT_LIST_HEAD(&dent->brick_list);

		status = mars_recv_struct(sock, dent, mars_dent_meta);
		if (status <= 0) {
			mars_free_dent(dent);
			goto done;
		}
		list_add_tail(&dent->dent_link, anchor);
	}
done:
	return status;
}
EXPORT_SYMBOL_GPL(mars_recv_dent_list);


////////////////// module init stuff /////////////////////////


int __init init_sy_net(void)
{
	MARS_INF("init_sy_net()\n");
	mars_translate_hostname = _mars_translate_hostname;
	return 0;
}

void exit_sy_net(void)
{
	MARS_INF("exit_sy_net()\n");
}

#ifndef CONFIG_MARS_HAVE_BIGMODULE
MODULE_DESCRIPTION("MARS network infrastructure");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@{schoebel-theuer,1und1}.de>");
MODULE_LICENSE("GPL");

module_init(init_sy_net);
module_exit(exit_sy_net);
#endif
