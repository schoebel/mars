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

#ifndef XIO_NET_H
#define XIO_NET_H

#include <net/sock.h>
#include <net/ipconfig.h>
#include <net/tcp.h>

#include "brick.h"

extern int xio_net_compress_data;

extern int xio_net_default_port;
extern int xio_net_bind_before_listen;
extern int xio_net_bind_before_connect;

extern bool xio_net_is_alive;

#define MAX_DESC_CACHE			16

/* The original struct socket has no refcount. This leads to problems
 * during long-lasting system calls when racing with socket shutdown.
 *
 * The original idea of struct xio_socket was just a small wrapper
 * adding a refcount and some debugging aid.
 * Later, some buffering was added in order to take advantage of
 * kernel_sendpage().
 * Caching of meta description has also been added.
 *
 * Notice: we have a slightly restricted parallelism model.
 * One sender and one receiver thread may work in parallel
 * on the same socket instance. At low level, there must not exist
 * multiple readers in parallel to each other, or multiple
 * writers in parallel to each other. Otherwise, higher level
 * protocol sequences would be disturbed anyway.
 * When needed, you may achieve higher parallelism by doing your own
 * semaphore locking around xio_{send, recv}_struct() or even longer
 * sequences of subsets of your high-level protocol.
 */
struct xio_socket {
	struct socket *s_socket;

	u64 s_send_bytes;
	u64 s_recv_bytes;
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

	u8   s_send_proto;
	u8   s_recv_proto;
	u16  s_send_flags;
	u16  s_recv_flags;
	struct xio_desc_cache *s_desc_send[MAX_DESC_CACHE];
	struct xio_desc_cache *s_desc_recv[MAX_DESC_CACHE];
};

struct xio_tcp_params {
	int ip_tos;
	int tcp_window_size;
	int tcp_nodelay;
	int tcp_timeout;
	int tcp_keepcnt;
	int tcp_keepintvl;
	int tcp_keepidle;
};

extern struct xio_tcp_params default_tcp_params;

enum {
	CMD_NOP,
	CMD_NOTIFY,
	CMD_CONNECT,
	CMD_GETINFO,
	CMD_GETENTS,
	CMD_AIO,
	CMD_CB,
};

#define CMD_FLAG_MASK			255
#define CMD_FLAG_HAS_DATA		256

struct xio_cmd {
	struct timespec cmd_stamp; /*  for automatic lamport clock */
	int cmd_code;
	int cmd_int1;

	/* int cmd_int2; */
	/* int cmd_int3; */
	char *cmd_str1;

	/* char *cmd_str2; */
	/* char *cmd_str3; */
};

extern const struct meta xio_cmd_meta[];

extern char *(*xio_translate_hostname)(const char *name);

extern char *my_id(void);

/* Low-level network traffic
 */
extern int xio_create_sockaddr(struct sockaddr_storage *addr, const char *spec);

extern int xio_create_socket(struct xio_socket *msock,
	struct sockaddr_storage *src_addr,
	struct sockaddr_storage *dst_addr);

extern int xio_accept_socket(struct xio_socket *new_msock, struct xio_socket *old_msock);
extern bool xio_get_socket(struct xio_socket *msock);
extern void xio_put_socket(struct xio_socket *msock);
extern void xio_shutdown_socket(struct xio_socket *msock);
extern bool xio_socket_is_alive(struct xio_socket *msock);
extern long xio_socket_send_space_available(struct xio_socket *msock);

extern int xio_send_raw(struct xio_socket *msock, const void *buf, int len, bool cork);
extern int xio_recv_raw(struct xio_socket *msock, void *buf, int minlen, int maxlen);

int xio_send_compressed(struct xio_socket *msock, const void *buf, s32 len, int compress, bool cork);
int xio_recv_compressed(struct xio_socket *msock, void *buf, int minlen, int maxlen);

/* Mid-level generic field data exchange
 */
extern int xio_send_struct(struct xio_socket *msock, const void *data, const struct meta *meta);
#define xio_recv_struct(_sock_, _data_, _meta_)				\
	({								\
		_xio_recv_struct(_sock_, _data_, _meta_, __LINE__);	\
	})
extern int _xio_recv_struct(struct xio_socket *msock, void *data, const struct meta *meta, int line);

/* High-level transport of xio structures
 */
extern int xio_send_dent_list(struct xio_socket *msock, struct list_head *anchor);
extern int xio_recv_dent_list(struct xio_socket *msock, struct list_head *anchor);

extern int xio_send_aio(struct xio_socket *msock, struct aio_object *aio);
extern int xio_recv_aio(struct xio_socket *msock, struct aio_object *aio, struct xio_cmd *cmd);
extern int xio_send_cb(struct xio_socket *msock, struct aio_object *aio);
extern int xio_recv_cb(struct xio_socket *msock, struct aio_object *aio, struct xio_cmd *cmd);

/*	remove_this */
/***********************************************************************/

#ifdef CONFIG_MARS_NET_COMPAT
extern int use_old_format;
int desc_send_struct_old(struct xio_socket *msock, const void *data, const struct meta *meta, bool cork);
int desc_recv_struct_old(struct xio_socket *msock, void *data, const struct meta *meta, int line);

#endif

/*	end_remove_this */
/***********************************************************************/

/*  init */

extern int init_xio_net(void);
extern void exit_xio_net(void);

#endif
