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

#ifndef MARS_NET_H
#define MARS_NET_H

#include <net/sock.h>
#include <net/ipconfig.h>
#include <net/tcp.h>

#include "brick.h"

extern int mars_net_default_port;
extern bool mars_net_is_alive;

#define MAX_FIELD_LEN   32
#define MAX_DESC_CACHE  16

struct mars_desc_cache {
	u64   cache_sender_cookie;
	u64   cache_recver_cookie;
	s32   cache_items;
};

struct mars_desc_item {
	char  field_name[MAX_FIELD_LEN];
	s32   field_type;
	s32   field_size;
	s32   field_sender_offset;
	s32   field_recver_offset;
};

/* The original struct socket has no refcount. This leads to problems
 * during long-lasting system calls when racing with socket shutdown.
 *
 * The original idea of struct mars_socket was just a small wrapper
 * adding a refcount and some debugging aid.
 * Later, some buffering was added in order to take advantage of
 * kernel_sendpage().
 * Caching of meta description has also been added.
 */
struct mars_socket {
	struct socket *s_socket;
	void *s_buffer;
	atomic_t s_count;
	int s_pos;
	int s_debug_nr;
	int s_send_abort;
	int s_recv_abort;
	int s_send_cnt;
	int s_recv_cnt;
	bool s_shutdown_on_err;
	bool s_alive;
	bool s_connected;
	struct mars_desc_cache *s_desc_send[MAX_DESC_CACHE];
	struct mars_desc_cache *s_desc_recv[MAX_DESC_CACHE];
};

struct mars_tcp_params {
	int ip_tos;
	int tcp_window_size;
	int tcp_nodelay;
	int tcp_timeout;
	int tcp_keepcnt;
	int tcp_keepintvl;
	int tcp_keepidle;
};

enum mars_traffic_types {
	MARS_TRAFFIC_META,
	MARS_TRAFFIC_REPLICATION,
	MARS_TRAFFIC_SYNC,
	MARS_TRAFFIC_MAX /* this must come last */
};

extern struct mars_tcp_params mars_tcp_params[MARS_TRAFFIC_MAX];

enum {
	CMD_NOP,
	CMD_NOTIFY,
	CMD_CONNECT,
	CMD_GETINFO,
	CMD_GETENTS,
	CMD_MREF,
	CMD_CB,
};

#define CMD_FLAG_MASK     255
#define CMD_FLAG_HAS_DATA 256

struct mars_cmd {
	struct timespec cmd_stamp; // for automatic lamport clock
	int cmd_code;
	int cmd_int1;
	//int cmd_int2;
	//int cmd_int3;
	char *cmd_str1;
	//char *cmd_str2;
	//char *cmd_str3;
};

extern const struct meta mars_cmd_meta[];

extern char *(*mars_translate_hostname)(const char *name);

/* Low-level network traffic
 */
extern int mars_create_sockaddr(struct sockaddr_storage *addr, const char *spec);

extern int mars_create_socket(struct mars_socket *msock,
			      struct sockaddr_storage *addr,
			      struct mars_tcp_params *params,
			      bool is_server);
extern int mars_accept_socket(struct mars_socket *new_msock,
			      struct mars_socket *old_msock,
			      struct mars_tcp_params *params);
extern bool mars_get_socket(struct mars_socket *msock);
extern void mars_put_socket(struct mars_socket *msock);
extern void mars_shutdown_socket(struct mars_socket *msock);
extern bool mars_socket_is_alive(struct mars_socket *msock);
extern long mars_socket_send_space_available(struct mars_socket *msock);

extern int mars_send_raw(struct mars_socket *msock, const void *buf, int len, bool cork);
extern int mars_recv_raw(struct mars_socket *msock, void *buf, int minlen, int maxlen);

/* Mid-level generic field data exchange
 */
extern int mars_send_struct(struct mars_socket *msock, const void *data, const struct meta *meta, bool cork);
#define mars_recv_struct(_sock_,_data_,_meta_)				\
	({								\
		_mars_recv_struct(_sock_, _data_, _meta_, __LINE__); \
	})
extern int _mars_recv_struct(struct mars_socket *msock, void *data, const struct meta *meta, int line);

/* High-level transport of mars structures
 */
extern int mars_send_dent_list(struct mars_socket *msock, struct list_head *anchor);
extern int mars_recv_dent_list(struct mars_socket *msock, struct list_head *anchor);

extern int mars_send_mref(struct mars_socket *msock, struct mref_object *mref, bool cork);
extern int mars_recv_mref(struct mars_socket *msock, struct mref_object *mref, struct mars_cmd *cmd);
extern int mars_send_cb(struct mars_socket *msock, struct mref_object *mref, bool cork);
extern int mars_recv_cb(struct mars_socket *msock, struct mref_object *mref, struct mars_cmd *cmd);

/////////////////////////////////////////////////////////////////////////

// init

extern int init_mars_net(void);
extern void exit_mars_net(void);


#endif
