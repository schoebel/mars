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
//#define LOWLEVEL_DEBUGGING

#ifdef LOWLEVEL_DEBUGGING
#define MARS_LOW MARS_IO
#else
#define MARS_LOW(args...) /*empty*/
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/moduleparam.h>

#include "mars.h"
#include "mars_net.h"

#undef USE_SENDPAGE // FIXME: does not work, leads to data corruption (probably due to races with asynchrous sending)
#define USE_BUFFERING

/* Low-level network traffic
 */

int mars_net_default_port = CONFIG_MARS_DEFAULT_PORT;
EXPORT_SYMBOL_GPL(mars_net_default_port);
module_param_named(mars_port, mars_net_default_port, int, 0);

/* TODO: allow binding to specific source addresses instead of catch-all.
 * TODO: make all the socket options configurable.
 * TODO: implement signal handling.
 * TODO: add authentication.
 * TODO: add compression / encryption.
 */

struct mars_tcp_params default_tcp_params = {
	.ip_tos = IPTOS_LOWDELAY,
	.tcp_window_size = 8 * 1024 * 1024, // for long distance replications
	.tcp_nodelay = 0,
	.tcp_timeout = 2,
	.tcp_keepcnt = 3,
	.tcp_keepintvl = 3, // keepalive ping time
	.tcp_keepidle = 4,
};
EXPORT_SYMBOL(default_tcp_params);

static
void __setsockopt(struct socket *sock, int level, int optname, char *optval, int optsize)
{
	int status = kernel_setsockopt(sock, level, optname, optval, optsize);
	if (status < 0) {
		MARS_WRN("cannot set %d socket option %d to value %d, status = %d\n",
			 level, optname, *(int*)optval, status);
	}
}

#define _setsockopt(sock,level,optname,val) __setsockopt(sock, level, optname, (char*)&(val), sizeof(val))

int mars_create_sockaddr(struct sockaddr_storage *addr, const char *spec)
{
	struct sockaddr_in *sockaddr = (void*)addr;
	const char *new_spec;
	const char *tmp_spec;
	int status = 0;

	memset(addr, 0, sizeof(*addr));
	sockaddr->sin_family = AF_INET;
	sockaddr->sin_port = htons(mars_net_default_port);

	/* Try to translate hostnames to IPs if possible.
	 */
	if (mars_translate_hostname) {
		new_spec = mars_translate_hostname(spec);
	} else {
		new_spec = brick_strdup(spec);
	}
	tmp_spec = new_spec;

	/* This is PROVISIONARY!
	 * TODO: add IPV6 syntax and many more features :)
	 */
	if (!*tmp_spec)
		goto done;
	if (*tmp_spec != ':') {
		unsigned char u0 = 0, u1 = 0, u2 = 0, u3 = 0;
		status = sscanf(tmp_spec, "%hhu.%hhu.%hhu.%hhu", &u0, &u1, &u2, &u3);
		if (status != 4) {
			MARS_ERR("invalid sockaddr IP syntax '%s', status = %d\n", tmp_spec, status);
			status = -EINVAL;
			goto done;
		}
		MARS_DBG("decoded IP = %u.%u.%u.%u\n", u0, u1, u2, u3);
		sockaddr->sin_addr.s_addr = (__be32)u0 | (__be32)u1 << 8 | (__be32)u2 << 16 | (__be32)u3 << 24;
	}
	// deocde port number (when present)
	tmp_spec = spec;
	while (*tmp_spec && *tmp_spec++ != ':')
		/*empty*/;
	if (*tmp_spec) {
		int port = 0;
		status = sscanf(tmp_spec, "%d", &port);
		if (status != 1) {
			MARS_ERR("invalid sockaddr PORT syntax '%s', status = %d\n", tmp_spec, status);
			status = -EINVAL;
			goto done;
		}
		MARS_DBG("decoded PORT = %d\n", port);
		sockaddr->sin_port = htons(port);
	}
	status = 0;
 done:
	brick_string_free(new_spec);
	return status;
}
EXPORT_SYMBOL_GPL(mars_create_sockaddr);

static int current_debug_nr = 0; // no locking, just for debugging

static
void _set_socketopts(struct socket *sock)
{
	struct timeval t = {
		.tv_sec = default_tcp_params.tcp_timeout,
	};
	int x_true = 1;
	/* TODO: improve this by a table-driven approach
	 */
	sock->sk->sk_rcvtimeo = sock->sk->sk_sndtimeo = default_tcp_params.tcp_timeout * HZ;
	sock->sk->sk_reuse = 1;
	_setsockopt(sock, SOL_SOCKET, SO_SNDBUFFORCE, default_tcp_params.tcp_window_size);
	_setsockopt(sock, SOL_SOCKET, SO_RCVBUFFORCE, default_tcp_params.tcp_window_size);
	_setsockopt(sock, SOL_IP, SO_PRIORITY, default_tcp_params.ip_tos);
	_setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, default_tcp_params.tcp_nodelay);
	_setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, x_true);
	_setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, default_tcp_params.tcp_keepcnt);
	_setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, default_tcp_params.tcp_keepintvl);
	_setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, default_tcp_params.tcp_keepidle);
	_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, t);
	_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, t);

	if (sock->file) { // switch back to blocking mode
		sock->file->f_flags &= ~O_NONBLOCK;
	}
}

int mars_create_socket(struct mars_socket *msock, struct sockaddr_storage *addr, bool is_server)
{
	struct socket *sock;
	struct sockaddr *sockaddr = (void*)addr;
	int status = -EEXIST;

	if (unlikely(atomic_read(&msock->s_count))) {
		MARS_ERR("#%d socket already in use\n", msock->s_debug_nr);
		goto final;
	}
	if (unlikely(msock->s_socket)) {
		MARS_ERR("#%d socket already open\n", msock->s_debug_nr);
		goto final;
	}
	atomic_set(&msock->s_count, 1);

	status = sock_create_kern(AF_INET, SOCK_STREAM, IPPROTO_TCP, &msock->s_socket);
	if (unlikely(status < 0 || !msock->s_socket)) {
		msock->s_socket = NULL;
		MARS_WRN("cannot create socket, status = %d\n", status);
		goto final;
	}
	msock->s_debug_nr = ++current_debug_nr;
	sock = msock->s_socket;
	CHECK_PTR(sock, done);
	msock->s_alive = true;

	_set_socketopts(sock);

	if (is_server) {
		status = kernel_bind(sock, sockaddr, sizeof(*sockaddr));
		if (unlikely(status < 0)) {
			MARS_WRN("#%d bind failed, status = %d\n", msock->s_debug_nr, status);
			goto done;
		}
		status = kernel_listen(sock, 16);
		if (status < 0) {
			MARS_WRN("#%d listen failed, status = %d\n", msock->s_debug_nr, status);
		}
	} else {
		status = kernel_connect(sock, sockaddr, sizeof(*sockaddr), 0);
		/* Treat non-blocking connects as successful.
		 * Any potential errors will show up later during traffic.
		 */
		if (status == -EINPROGRESS) {
			MARS_DBG("#%d connect in progress\n", msock->s_debug_nr);
			status = 0;
		}
		if (status < 0) {
			MARS_DBG("#%d connect failed, status = %d\n", msock->s_debug_nr, status);
		}
	}

done:
	if (status < 0) {
		mars_put_socket(msock);
	} else {
		MARS_DBG("successfully created socket #%d\n", msock->s_debug_nr);
	}
final:
	return status;
}
EXPORT_SYMBOL_GPL(mars_create_socket);

int mars_accept_socket(struct mars_socket *new_msock, struct mars_socket *old_msock)
{
	int status = -ENOENT;
	struct socket *new_socket = NULL;
	bool ok;

	ok = mars_get_socket(old_msock);
	if (likely(ok)) {
		struct socket *sock = old_msock->s_socket;
		if (unlikely(!sock)) {
			goto err;
		}

		status = kernel_accept(sock, &new_socket, O_NONBLOCK);
		if (unlikely(status < 0)) {
			goto err;
		}
		if (unlikely(!new_socket)) {
			status = -EBADF;
			goto err;
		}

		MARS_IO("old#%d status = %d file = %p flags = 0x%x\n", old_msock->s_debug_nr, status, new_socket->file, new_socket->file ? new_socket->file->f_flags : 0);

		_set_socketopts(new_socket);

		memset(new_msock, 0, sizeof(struct mars_socket));
		new_msock->s_socket = new_socket;
		atomic_set(&new_msock->s_count, 1);
		new_msock->s_alive = true;
		new_msock->s_debug_nr = ++current_debug_nr;
		MARS_DBG("#%d successfully accepted socket #%d\n", old_msock->s_debug_nr, new_msock->s_debug_nr);
		status = 0;
err:
		mars_put_socket(old_msock);
	}
	return status;
}
EXPORT_SYMBOL_GPL(mars_accept_socket);

bool mars_get_socket(struct mars_socket *msock)
{
	MARS_LOW("#%d get socket %p s_count=%d\n", msock->s_debug_nr, msock->s_socket, atomic_read(&msock->s_count));
	if (unlikely(atomic_read(&msock->s_count) <= 0)) {
		MARS_ERR("#%d bad nesting on msock = %p\n", msock->s_debug_nr, msock);
		return false;
	}

	atomic_inc(&msock->s_count);

	if (unlikely(!msock->s_socket || !msock->s_alive)) {
		mars_put_socket(msock);
		return false;
	}
	MARS_LOW("#%d got socket\n", msock->s_debug_nr);
	return true;
}
EXPORT_SYMBOL_GPL(mars_get_socket);

void mars_put_socket(struct mars_socket *msock)
{
	MARS_LOW("#%d put socket %p s_count=%d\n", msock->s_debug_nr, msock->s_socket, atomic_read(&msock->s_count));
	if (unlikely(atomic_read(&msock->s_count) <= 0)) {
		MARS_ERR("#%d bad nesting on msock = %p sock = %p\n", msock->s_debug_nr, msock, msock->s_socket);
	} else if (atomic_dec_and_test(&msock->s_count)) {
		struct socket *sock = msock->s_socket;
		int i;

		MARS_DBG("#%d closing socket %p\n", msock->s_debug_nr, sock);
		if (likely(sock && cmpxchg(&msock->s_alive, true, false))) {
			kernel_sock_shutdown(sock, SHUT_WR);
		}
		if (likely(sock && !msock->s_alive)) {
			MARS_DBG("#%d releasing socket %p\n", msock->s_debug_nr, sock);
			sock_release(sock);
		}
		for (i = 0; i < MAX_DESC_CACHE; i++) {
			if (msock->s_desc_send[i])
				brick_block_free(msock->s_desc_send[i], PAGE_SIZE);
			if (msock->s_desc_recv[i])
				brick_block_free(msock->s_desc_recv[i], PAGE_SIZE);
		}
		brick_block_free(msock->s_buffer, PAGE_SIZE);
		memset(msock, 0, sizeof(struct mars_socket));
	}
}
EXPORT_SYMBOL_GPL(mars_put_socket);

void mars_shutdown_socket(struct mars_socket *msock)
{
	MARS_IO("#%d shutdown socket %p s_count=%d\n", msock->s_debug_nr, msock->s_socket, atomic_read(&msock->s_count));

	if (msock->s_socket) {
		bool ok = mars_get_socket(msock);
		if (likely(ok)) {
			struct socket *sock = msock->s_socket;
			if (likely(sock && cmpxchg(&msock->s_alive, true, false))) {
				MARS_DBG("#%d shutdown socket %p\n", msock->s_debug_nr, sock);
				kernel_sock_shutdown(sock, SHUT_WR);
			}
			mars_put_socket(msock);
		}
	}
}
EXPORT_SYMBOL_GPL(mars_shutdown_socket);

bool mars_socket_is_alive(struct mars_socket *msock)
{
	bool res = false;
	if (!msock->s_socket || !msock->s_alive)
		goto done;
	if (unlikely(atomic_read(&msock->s_count) <= 0)) {
		MARS_ERR("#%d bad nesting on msock = %p sock = %p\n", msock->s_debug_nr, msock, msock->s_socket);
		goto done;
	}
	res = true;
done:
	MARS_LOW("#%d %p s_count = %d\n", msock->s_debug_nr, msock->s_socket, atomic_read(&msock->s_count));
	return res;
}
EXPORT_SYMBOL_GPL(mars_socket_is_alive);

static
int _mars_send_raw(struct mars_socket *msock, const void *buf, int len)
{
	int sleeptime = 1000 / HZ;
	int sent = 0;
	int status = 0;

	msock->s_send_cnt = 0;
	while (len > 0) {
		int this_len = len;
		struct socket *sock = msock->s_socket;

		if (unlikely(!sock || !mars_net_is_alive || brick_thread_should_stop())) {
			MARS_WRN("interrupting, sent = %d\n", sent);
			status = -EIDRM;
			break;
		}

#ifdef USE_SENDPAGE // FIXME: does not work, leads to data corruption (probably due to races with asynchrous sending)
		{
			int page_offset = 0;
			struct page *page;
			int flags = MSG_NOSIGNAL;
			page = brick_iomap(buf, &page_offset, &this_len);
			if (unlikely(!page)) {
				MARS_ERR("cannot iomap() kernel address %p\n", buf);
				status = -EINVAL;
				break;
			}

			if (this_len < len)
				flags |= MSG_MORE;
			
			status = kernel_sendpage(sock, page, page_offset, this_len, flags);
			if (status > 0 && status != this_len) {
				MARS_WRN("#%d status = %d this_len = %d\n", msock->s_debug_nr, status, this_len);
			}
		}
#else // spare code, activate in case of problems with sendpage()
		{
			struct kvec iov = {
				.iov_base = (void*)buf,
				.iov_len  = this_len,
			};
			struct msghdr msg = {
				.msg_iov = (struct iovec*)&iov,
				.msg_flags = 0 | MSG_NOSIGNAL,
			};
			status = kernel_sendmsg(sock, &msg, &iov, 1, this_len);
		}
#endif

		if (status == -EAGAIN) {
			if (msock->s_send_abort > 0 && ++msock->s_send_cnt > msock->s_send_abort) {
				MARS_WRN("#%d reached send abort %d\n", msock->s_debug_nr, msock->s_send_abort);
				status = -EINTR;
				break;
			}
			brick_msleep(sleeptime);
			// linearly increasing backoff
			if (sleeptime < 100) {
				sleeptime += 1000 / HZ;
			}
			continue;
		}
		msock->s_send_cnt = 0;
		if (unlikely(status == -EINTR)) { // ignore it
			flush_signals(current);
			MARS_IO("#%d got signal\n", msock->s_debug_nr);
			brick_msleep(50);
			continue;
		}
		if (unlikely(!status)) {
			MARS_WRN("#%d EOF from socket upon send_page()\n", msock->s_debug_nr);
			brick_msleep(50);
			status = -ECOMM;
			break;
		}
		if (unlikely(status < 0)) {
			MARS_WRN("#%d bad socket sendmsg, len=%d, this_len=%d, sent=%d, status = %d\n", msock->s_debug_nr, len, this_len, sent, status);
			break;
		}

		len -= status;
		buf += status;
		sent += status;
		sleeptime = 1000 / HZ;
	}

	if (status >= 0)
		status = sent;

	return status;
}

int mars_send_raw(struct mars_socket *msock, const void *buf, int len, bool cork)
{
#ifdef USE_BUFFERING
	int sent = 0;
	int rest = len;
#endif
	int status = -EINVAL;

	if (!mars_get_socket(msock))
		goto final;

	MARS_IO("#%d cork=%d sending len=%d bytes\n", msock->s_debug_nr, cork, len);

#ifdef USE_BUFFERING
restart:
	while (!msock->s_buffer) {
		msock->s_pos = 0;
		msock->s_buffer = brick_block_alloc(0, PAGE_SIZE);
		if (unlikely(!msock->s_buffer))
			brick_msleep(100);
	}

	if (msock->s_pos + rest < PAGE_SIZE) {
		memcpy(msock->s_buffer + msock->s_pos, buf, rest);
		msock->s_pos += rest;
		sent += rest;
		rest = 0;
		status = sent;
		if (cork)
			goto done;
	}

	if (msock->s_pos > 0) {
		status = _mars_send_raw(msock, msock->s_buffer, msock->s_pos);
		MARS_IO("#%d buffer send %d bytes status=%d\n", msock->s_debug_nr, msock->s_pos, status);
		if (status < 0)
			goto done;
		
		brick_block_free(msock->s_buffer, PAGE_SIZE);
		msock->s_buffer = NULL;
		msock->s_pos = 0;
	}

	if (rest >= PAGE_SIZE) {
		status = _mars_send_raw(msock, buf, rest);
		MARS_IO("#%d bulk send %d bytes status=%d\n", msock->s_debug_nr, rest, status);
		goto done;
	} else if (rest > 0) {
		goto restart;
	}
	status = sent;

done:
#else
	status = _mars_send_raw(msock, buf, len);
#endif
	if (status < 0 && msock->s_shutdown_on_err)
		mars_shutdown_socket(msock);

	mars_put_socket(msock);

final:
	return status;
}
EXPORT_SYMBOL_GPL(mars_send_raw);

/**
 * mars_recv_raw() - Get [min,max] number of bytes
 * @msock:	socket to read from
 * @buf:	buffer to put the data in
 * @minlen:	minimum number of bytes to read
 * @maxlen:	maximum number of bytes to read
 *
 * Returns a negative error code or a number between [@minlen,@maxlen].
 * Short reads are mapped to an error.
 *
 * Hint: by setting @minlen to 1, you can read any number up to @maxlen.
 * However, the most important use case is @minlen == @maxlen.
 *
 * Note: buf may be NULL. In this case, the data is simply consumed,
 * like /dev/null
 */
int mars_recv_raw(struct mars_socket *msock, void *buf, int minlen, int maxlen)
{
	void *dummy = NULL;
	int sleeptime = 1000 / HZ;
	int status = -EIDRM;
	int done = 0;

	if (!buf) {
		buf = dummy = brick_block_alloc(0, maxlen);
	}
	if (!buf) {
		MARS_WRN("#%d bad receive buffer\n", msock->s_debug_nr);
		return -EINVAL;
	}

	if (!mars_get_socket(msock))
		goto final;

	if (minlen < maxlen) {
		struct socket *sock = msock->s_socket;
		if (sock && sock->file) {
			/* Use nonblocking reads to consume as much data
			 * as possible
			 */
			sock->file->f_flags |= O_NONBLOCK;
		}
	}

	MARS_IO("#%d receiving len=%d/%d bytes\n", msock->s_debug_nr, minlen, maxlen);

	msock->s_recv_cnt = 0;
	while (done < minlen || (!minlen && !done)) {
		struct kvec iov = {
			.iov_base = buf + done,
			.iov_len = maxlen - done,
		};
		struct msghdr msg = {
			.msg_iovlen = 1,
			.msg_iov = (struct iovec*)&iov,
			.msg_flags = MSG_NOSIGNAL,
		};
		struct socket *sock = msock->s_socket;

		if (unlikely(!sock)) {
			MARS_WRN("#%d socket has disappeared\n", msock->s_debug_nr);
			status = -EIDRM;
			goto err;
		}

		if (!mars_net_is_alive || brick_thread_should_stop()) {
			MARS_WRN("#%d interrupting, done = %d\n", msock->s_debug_nr, done);
			status = -EIDRM;
			goto err;
		}

		MARS_LOW("#%d done %d, fetching %d bytes\n", msock->s_debug_nr, done, maxlen-done);

		status = kernel_recvmsg(sock, &msg, &iov, 1, maxlen-done, msg.msg_flags);

		MARS_LOW("#%d status = %d\n", msock->s_debug_nr, status);

		if (!mars_net_is_alive || brick_thread_should_stop()) {
			MARS_WRN("#%d interrupting, done = %d\n", msock->s_debug_nr, done);
			status = -EIDRM;
			goto err;
		}

		if (status == -EAGAIN) {
			if (msock->s_recv_abort > 0 && ++msock->s_recv_cnt > msock->s_recv_abort) {
				MARS_WRN("#%d reached recv abort %d\n", msock->s_debug_nr, msock->s_recv_abort);
				status = -EINTR;
				goto err;
			}
			brick_msleep(sleeptime);
			if (minlen <= 0)
				break;
			// linearly increasing backoff
			if (sleeptime < 100) {
				sleeptime += 1000 / HZ;
			}
			continue;
		}
		msock->s_recv_cnt = 0;
		if (!status) { // EOF
			MARS_WRN("#%d got EOF from socket (done=%d, req_size=%d)\n", msock->s_debug_nr, done, maxlen - done);
			status = -EPIPE;
			goto err;
		}
		if (status < 0) {
			MARS_WRN("#%d bad recvmsg, status = %d\n", msock->s_debug_nr, status);
			goto err;
		}
		done += status;
		sleeptime = 1000 / HZ;
	}
	status = done;

	MARS_IO("#%d got %d bytes\n", msock->s_debug_nr, done);

err:
	if (status < 0 && msock->s_shutdown_on_err)
		mars_shutdown_socket(msock);
	mars_put_socket(msock);
final:
	if (dummy)
		brick_block_free(dummy, maxlen);
	return status;
}
EXPORT_SYMBOL_GPL(mars_recv_raw);

///////////////////////////////////////////////////////////////////////

/* Mid-level field data exchange
 */

static
int _add_fields(struct mars_desc_item *mi, const struct meta *meta, int offset, const char *prefix, int maxlen)
{
	int count = 0;
	for (; meta->field_name != NULL; meta++) {
		const char *new_prefix;
		int new_offset;
		int len;

		new_prefix = mi->field_name;
		new_offset = offset + meta->field_offset;

		MARS_IO("input  field_name='%s' field_type=%d\n", meta->field_name, meta->field_type);

		if (unlikely(maxlen < sizeof(struct mars_desc_item))) {
			MARS_ERR("desc cache item overflow\n");
			count = -1;
			goto done;
		}
		
		len = scnprintf(mi->field_name, MAX_FIELD_LEN, "%s.%s", prefix, meta->field_name);
		if (unlikely(len >= MAX_FIELD_LEN)) {
			MARS_ERR("field len overflow on '%s.%s'\n", prefix, meta->field_name);
			count = -1;
			goto done;
		}
		mi->field_type = meta->field_type;
		mi->field_size = meta->field_size;
		mi->field_sender_offset = new_offset;
		mi->field_recver_offset = -1;

		MARS_IO("output field_name='%s' field_type=%d\n", mi->field_name, mi->field_type);

		mi++;
		maxlen -= sizeof(struct mars_desc_item);
		count++;

		if (meta->field_type == FIELD_SUB) {
			int sub_count;
			sub_count = _add_fields(mi, meta->field_ref, new_offset, new_prefix, maxlen);
			if (sub_count < 0)
				return sub_count;

			mi += sub_count;
			count += sub_count;
			maxlen -= sub_count * sizeof(struct mars_desc_item);
		}
	}
done:
	MARS_IO("count=%d\n", count);
	return count;
}

static
struct mars_desc_cache *make_sender_cache(struct mars_socket *msock, const struct meta *meta, int *cache_index)
{
	int orig_len = PAGE_SIZE;
	int maxlen = orig_len;
	struct mars_desc_cache *mc;
	struct mars_desc_item *mi;
	int i;
	int status;

	for (i = 0; i < MAX_DESC_CACHE; i++) {
		mc = msock->s_desc_send[i];
		if (!mc)
			break;
		if (mc->cache_sender_cookie == (u64)meta)
			goto done;
	}

	MARS_IO("#%d meta=%p i=%d\n", msock->s_debug_nr, meta, i);

	if (unlikely(i >= MAX_DESC_CACHE - 1)) {
		MARS_ERR("#%d desc cache overflow\n", msock->s_debug_nr);
		return NULL;
	}

	mc = brick_block_alloc(0, maxlen);
	if (unlikely(!mc)) {
		MARS_ERR("#%d desc cache alloc error\n", msock->s_debug_nr);
		goto done;
	}

	memset(mc, 0, maxlen);
	mc->cache_sender_cookie = (u64)meta;

	maxlen -= sizeof(struct mars_desc_cache);
	mi = (void*)(mc + 1);

	status = _add_fields(mi, meta, 0, "", maxlen);

	if (likely(status > 0)) {
		mc->cache_items = status;
		msock->s_desc_send[i] = mc;
		*cache_index = i;
	} else {
		brick_block_free(mc, orig_len);
		mc = NULL;
	}

done:
	return mc;
}

static
void _make_recver_cache(struct mars_desc_cache *mc, const struct meta *meta, int offset, const char *prefix)
{
	char *tmp = brick_string_alloc(MAX_FIELD_LEN);
	int i;

	for (; meta->field_name != NULL; meta++) {
		snprintf(tmp, MAX_FIELD_LEN, "%s.%s", prefix, meta->field_name);
		for (i = 0; i < mc->cache_items; i++) {
			struct mars_desc_item *mi = ((struct mars_desc_item*)(mc + 1)) + i;
			if (meta->field_type == mi->field_type &&
			    !strcmp(tmp, mi->field_name)) {
				mi->field_recver_offset = offset + meta->field_offset;
				if (meta->field_type == FIELD_SUB) {
					_make_recver_cache(mc, meta->field_ref, mi->field_recver_offset, tmp);
				}
				goto found;
			}
		}
		MARS_WRN("field '%s' is missing\n", meta->field_name);
	found:;
	}
	brick_string_free(tmp);
}

static
void make_recver_cache(struct mars_desc_cache *mc, const struct meta *meta)
{
	int i;

	_make_recver_cache(mc, meta, 0, "");

	for (i = 0; i < mc->cache_items; i++) {
		struct mars_desc_item *mi = ((struct mars_desc_item*)(mc + 1)) + i;
		if (unlikely(mi->field_recver_offset < 0)) {
			MARS_WRN("field '%s' is not transferred\n", mi->field_name);
		}
	}
}

static
int _desc_send_item(struct mars_socket *msock, const void *data, const struct mars_desc_cache *mc, int index, bool cork)
{
	struct mars_desc_item *mi = ((struct mars_desc_item*)(mc + 1)) + index;
	const void *item = data + mi->field_sender_offset;
	int len = mi->field_size;
	int status;
	int res = -1;

	MARS_IO("#%d cork=%d mc=%p field_name='%s' field_type=%d\n", msock->s_debug_nr, cork, mc, mi->field_name, mi->field_type);

	switch (mi->field_type) {
	case FIELD_REF:
		MARS_ERR("NYI\n");
		goto done;
	case FIELD_SUB:
		/* skip this */
		res = 0;
		break;
	case FIELD_STRING:
		item = *(void**)item;
		len = 0;
		if (item)
			len = strlen(item) + 1;

		status = mars_send_raw(msock, &len, sizeof(len), cork || len > 0);
		if (unlikely(status < 0))
			goto done;
		/* fallthrough */
	default:
		if (likely(len > 0)) {
			status = mars_send_raw(msock, item, len, cork);
			if (unlikely(status < 0))
				goto done;
		}
		res = len;
	}
done:
	return res;
}

static
int _desc_recv_item(struct mars_socket *msock, void *data, const struct mars_desc_cache *mc, int index, int line)
{
	struct mars_desc_item *mi = ((struct mars_desc_item*)(mc + 1)) + index;
	void *item = NULL;
	int len = mi->field_size;
	int status;
	int res = -1;

	if (likely(data && mi->field_recver_offset >= 0)) {
		item = data + mi->field_recver_offset;
	}

	switch (mi->field_type) {
	case FIELD_REF:
		MARS_ERR("NYI\n");
		goto done;
	case FIELD_SUB:
		/* skip this */
		res = 0;
		break;
	case FIELD_STRING:
		len = 0;
		status = mars_recv_raw(msock, &len, sizeof(len), sizeof(len));
		if (unlikely(status < 0))
			goto done;

		if (len > 0 && item) {
			char *str = _brick_string_alloc(len, line);
			if (unlikely(!str)) {
				MARS_ERR("#%d string alloc error\n", msock->s_debug_nr);
				goto done;
			}
			*(void**)item = str;
			item = str;
		}

		/* fallthrough */
	default:
		if (likely(len > 0)) {
			status = mars_recv_raw(msock, item, len, len);
			if (unlikely(status < 0))
				goto done;
		}
		res = len;
	}
done:
	return res;
}

#define MARS_DESC_MAGIC 0x73f0A2ec6148f48dll

struct mars_desc_header {
	u64 h_magic;
	u64 h_cookie;
	s16 h_meta_len;
	s16 h_index;
};

static inline
int _desc_send_struct(struct mars_socket *msock, int cache_index, const void *data, int h_meta_len, bool cork)
{
	const struct mars_desc_cache *mc = msock->s_desc_send[cache_index];
	struct mars_desc_header header = {
		.h_magic = MARS_DESC_MAGIC,
		.h_cookie = mc->cache_sender_cookie,
		.h_meta_len = h_meta_len,
		.h_index = data ? cache_index : -1,
	};
	int index;
	int count = 0;
	int status = 0;

	MARS_IO("#%d cork=%d mc=%p h_meta_len=%d\n", msock->s_debug_nr, cork, mc, h_meta_len);

	status = mars_send_raw(msock, &header, sizeof(header), cork || data);
	if (unlikely(status < 0))
		goto err;

	if (unlikely(h_meta_len > 0)) {
		status = mars_send_raw(msock, mc, h_meta_len, true);
		MARS_IO("#%d sent mc=%p h_meta_len=%d status=%d\n", msock->s_debug_nr, mc, h_meta_len, status);
		if (unlikely(status < 0))
			goto err;
	}

	if (likely(data)) {
		for (index = 0; index < mc->cache_items; index++) {
			status = _desc_send_item(msock, data, mc, index, cork || index < mc->cache_items-1);
			if (unlikely(status < 0))
				goto err;
			count++;
		}
	}

	if (status >= 0)
		status = count;
err:
	return status;
}

static
int desc_send_struct(struct mars_socket *msock, const void *data, const struct meta *meta, bool cork)
{
	struct mars_desc_cache *mc;
	int i;
	int h_meta_len = 0;
	int status = -EINVAL;

	for (i = 0; i < MAX_DESC_CACHE; i++) {
		mc = msock->s_desc_send[i];
		if (!mc)
			break;
		if (mc->cache_sender_cookie == (u64)meta)
			goto found;
	}

	mc = make_sender_cache(msock, meta, &i);
	if (unlikely(!mc))
		goto done;

	h_meta_len = mc->cache_items * sizeof(struct mars_desc_item) + sizeof(struct mars_desc_cache);

found:
	status = _desc_send_struct(msock, i, data, h_meta_len, cork);

done:
	return status;
}

static
int desc_recv_struct(struct mars_socket *msock, void *data, const struct meta *meta, int line)
{
	struct mars_desc_header header = {};
	struct mars_desc_cache *mc;
	int cache_index; 
	int index;
	int count = 0;
	int status = 0;

	status = mars_recv_raw(msock, &header, sizeof(header), sizeof(header));
	if (unlikely(status < 0))
		goto err;

	if (unlikely(header.h_magic != MARS_DESC_MAGIC)) {
		MARS_WRN("#%d called from line %d bad packet header magic = %llx\n", msock->s_debug_nr, line, header.h_magic);
		status = -ENOMSG;
		goto err;
	}

	cache_index = header.h_index;
	if (cache_index < 0) { // EOR
		goto done;
	}
	if (unlikely(cache_index >= MAX_DESC_CACHE - 1)) {
		MARS_WRN("#%d called from line %d bad cache index %d\n", msock->s_debug_nr, line, cache_index);
		status = -EBADF;
		goto err;
	}

	mc = msock->s_desc_recv[cache_index];
	if (unlikely(!mc)) {
		if (unlikely(header.h_meta_len <= 0)) {
			MARS_WRN("#%d called from line %d missing meta information\n", msock->s_debug_nr, line);
			status = -ENOMSG;
			goto err;
		}

		mc = _brick_block_alloc(0, PAGE_SIZE, line);
		if (unlikely(!mc)) {
			MARS_WRN("#%d called from line %d out of memory\n", msock->s_debug_nr, line);
			status = -ENOMEM;
			goto err;
		}

		status = mars_recv_raw(msock, mc, header.h_meta_len, header.h_meta_len);
		MARS_IO("#%d got mc=%p h_meta_len=%d status=%d\n", msock->s_debug_nr, mc, header.h_meta_len, status);
		if (unlikely(status < 0)) {
			brick_block_free(mc, PAGE_SIZE);
			goto err;
		}

		make_recver_cache(mc, meta);
		msock->s_desc_recv[cache_index] = mc;
	} else if (unlikely(header.h_meta_len > 0)) {
		MARS_WRN("#%d called from line %d has %d unexpected meta bytes\n", msock->s_debug_nr, line, header.h_meta_len);
	}

	for (index = 0; index < mc->cache_items; index++) {
		status = _desc_recv_item(msock, data, mc, index, line);
		if (unlikely(status < 0))
			goto err;
		count++;
	}

done:
	if (status >= 0)
		status = count;
err:
	return status;
}

int mars_send_struct(struct mars_socket *msock, const void *data, const struct meta *meta)
{
	MARS_IO("#%d meta=%p\n", msock->s_debug_nr, meta);
	return desc_send_struct(msock, data, meta, false);
}
EXPORT_SYMBOL_GPL(mars_send_struct);

int _mars_recv_struct(struct mars_socket *msock, void *data, const struct meta *meta, int line)
{
	MARS_IO("#%d meta=%p called from line %d\n", msock->s_debug_nr, meta, line);
	return desc_recv_struct(msock, data, meta, line);
}
EXPORT_SYMBOL_GPL(_mars_recv_struct);

///////////////////////////////////////////////////////////////////////

/* High-level transport of mars structures
 */

const struct meta mars_cmd_meta[] = {
	META_INI_SUB(cmd_stamp, struct mars_cmd, mars_timespec_meta),
	META_INI(cmd_code, struct mars_cmd, FIELD_INT),
	META_INI(cmd_int1, struct mars_cmd, FIELD_INT),
	META_INI(cmd_str1, struct mars_cmd, FIELD_STRING),
	{}
};
EXPORT_SYMBOL_GPL(mars_cmd_meta);


int mars_send_mref(struct mars_socket *msock, struct mref_object *mref)
{
	struct mars_cmd cmd = {
		.cmd_code = CMD_MREF,
		.cmd_int1 = mref->ref_id,
	};
	int seq = 0;
	int status;

	if (mref->ref_rw != 0 && mref->ref_data && mref->ref_cs_mode < 2)
		cmd.cmd_code |= CMD_FLAG_HAS_DATA;

	get_lamport(&cmd.cmd_stamp);

	status = desc_send_struct(msock, &cmd, mars_cmd_meta, true);
	if (status < 0)
		goto done;

	seq = 0;
	status = desc_send_struct(msock, mref, mars_mref_meta, cmd.cmd_code & CMD_FLAG_HAS_DATA);
	if (status < 0)
		goto done;

	if (cmd.cmd_code & CMD_FLAG_HAS_DATA) {
		status = mars_send_raw(msock, mref->ref_data, mref->ref_len, false);
	}
done:
	return status;
}
EXPORT_SYMBOL_GPL(mars_send_mref);

int mars_recv_mref(struct mars_socket *msock, struct mref_object *mref, struct mars_cmd *cmd)
{
	int status;

	status = desc_recv_struct(msock, mref, mars_mref_meta, __LINE__);
	if (status < 0)
		goto done;

	set_lamport(&cmd->cmd_stamp);

	if (cmd->cmd_code & CMD_FLAG_HAS_DATA) {
		if (!mref->ref_data)
			mref->ref_data = brick_zmem_alloc(mref->ref_len);
		if (!mref->ref_data) {
			status = -ENOMEM;
			goto done;
		}
		status = mars_recv_raw(msock, mref->ref_data, mref->ref_len, mref->ref_len);
		if (status < 0)
			MARS_WRN("#%d mref_len = %d, status = %d\n", msock->s_debug_nr, mref->ref_len, status);
	}
done:
	return status;
}
EXPORT_SYMBOL_GPL(mars_recv_mref);

int mars_send_cb(struct mars_socket *msock, struct mref_object *mref)
{
	struct mars_cmd cmd = {
		.cmd_code = CMD_CB,
		.cmd_int1 = mref->ref_id,
	};
	int seq = 0;
	int status;

	if (mref->ref_rw == 0 && mref->ref_data && mref->ref_cs_mode < 2)
		cmd.cmd_code |= CMD_FLAG_HAS_DATA;

	get_lamport(&cmd.cmd_stamp);

	status = desc_send_struct(msock, &cmd, mars_cmd_meta, true);
	if (status < 0)
		goto done;

	seq = 0;
	status = desc_send_struct(msock, mref, mars_mref_meta, cmd.cmd_code & CMD_FLAG_HAS_DATA);
	if (status < 0)
		goto done;

	if (cmd.cmd_code & CMD_FLAG_HAS_DATA) {
		MARS_IO("#%d sending blocklen = %d\n", msock->s_debug_nr, mref->ref_len);
		status = mars_send_raw(msock, mref->ref_data, mref->ref_len, false);
	}
done:
	return status;
}
EXPORT_SYMBOL_GPL(mars_send_cb);

int mars_recv_cb(struct mars_socket *msock, struct mref_object *mref, struct mars_cmd *cmd)
{
	int status;

	status = desc_recv_struct(msock, mref, mars_mref_meta, __LINE__);
	if (status < 0)
		goto done;

	set_lamport(&cmd->cmd_stamp);

	if (cmd->cmd_code & CMD_FLAG_HAS_DATA) {
		if (!mref->ref_data) {
			MARS_WRN("#%d no internal buffer available\n", msock->s_debug_nr);
			status = -EINVAL;
			goto done;
		}
		MARS_IO("#%d receiving blocklen = %d\n", msock->s_debug_nr, mref->ref_len);
		status = mars_recv_raw(msock, mref->ref_data, mref->ref_len, mref->ref_len);
	}
done:
	return status;
}
EXPORT_SYMBOL_GPL(mars_recv_cb);

////////////////// module init stuff /////////////////////////

char *(*mars_translate_hostname)(const char *name) = NULL;
EXPORT_SYMBOL_GPL(mars_translate_hostname);

bool mars_net_is_alive = false;
EXPORT_SYMBOL_GPL(mars_net_is_alive);

int __init init_mars_net(void)
{
	MARS_INF("init_net()\n");
	mars_net_is_alive = true;
	return 0;
}

void exit_mars_net(void)
{
	mars_net_is_alive = false;
	MARS_INF("exit_net()\n");
}

#ifndef CONFIG_MARS_HAVE_BIGMODULE
MODULE_DESCRIPTION("MARS network infrastructure");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@{schoebel-theuer,1und1}.de>");
MODULE_LICENSE("GPL");

module_init(init_mars_net);
module_exit(exit_mars_net);
#endif
