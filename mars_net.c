// (c) 2011 Thomas Schoebel-Theuer / 1&1 Internet AG

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING
//#define IO_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include "mars.h"
#include "mars_net.h"

static
void mars_check_meta(const struct meta *meta, void *data);

/* Low-level network traffic
 */

/* TODO: allow binding to specific source addresses instead of catch-all.
 * TODO: make all the socket options configurable.
 * TODO: implement signal handling.
 * TODO: add authentication.
 * TODO: add compression / encryption.
 */

struct mars_tcp_params default_tcp_params = {
	.window_size = 8 * 1024 * 1024, // for long distance replications
	.tcp_timeout = 20,
	.tcp_keepcnt = 6,
	.tcp_keepintvl = 10, // keepalive ping time
	.tcp_keepidle = 10,
	.tos = IPTOS_LOWDELAY,
};
EXPORT_SYMBOL(default_tcp_params);

static
void _check(int status)
{
	if (status < 0) {
		MARS_WRN("cannot set socket option, status = %d\n", status);
	}
}

int mars_create_sockaddr(struct sockaddr_storage *addr, const char *spec)
{
	struct sockaddr_in *sockaddr = (void*)addr;
	char *new_spec;
	char *tmp_spec;
	int status = 0;

	memset(addr, 0, sizeof(*addr));
	sockaddr->sin_family = AF_INET;
	sockaddr->sin_port = htons(MARS_DEFAULT_PORT);

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
			status = -EINVAL;
			goto done;
		}
		sockaddr->sin_addr.s_addr = (__be32)u0 | (__be32)u1 << 8 | (__be32)u2 << 16 | (__be32)u3 << 24;
	}
	while (*tmp_spec && *tmp_spec++ != ':')
		/*empty*/;
	if (*tmp_spec) {
		int port = 0;
		status = sscanf(tmp_spec, "%d", &port);
		if (status != 1) {
			status = -EINVAL;
			goto done;
		}
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
	int x_true = 1;
	int status;
	/* TODO: improve this by a table-driven approach
	 */
	sock->sk->sk_rcvtimeo = sock->sk->sk_sndtimeo = default_tcp_params.tcp_timeout * HZ;
	sock->sk->sk_reuse = 1;
	status = kernel_setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*)&default_tcp_params.window_size, sizeof(default_tcp_params.window_size));
	_check(status);
	status = kernel_setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)&default_tcp_params.window_size, sizeof(default_tcp_params.window_size));
	_check(status);
	status = kernel_setsockopt(sock, SOL_IP, SO_PRIORITY, (char*)&default_tcp_params.tos, sizeof(default_tcp_params.tos));
	_check(status);
#if 0
	status = kernel_setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&x_true, sizeof(x_true));
#endif
	_check(status);
	status = kernel_setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char*)&x_true, sizeof(x_true));
	_check(status);
	status = kernel_setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, (char*)&default_tcp_params.tcp_keepcnt, sizeof(default_tcp_params.tcp_keepcnt));
	_check(status);
	status = kernel_setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, (char*)&default_tcp_params.tcp_keepintvl, sizeof(default_tcp_params.tcp_keepintvl));
	_check(status);
	status = kernel_setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, (char*)&default_tcp_params.tcp_keepidle, sizeof(default_tcp_params.tcp_keepidle));
	_check(status);

#if 1
	{
		struct timeval t = {
			.tv_sec = default_tcp_params.tcp_timeout,
		};
		status = kernel_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&t, sizeof(t));
		status = kernel_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&t, sizeof(t));
		_check(status);
	}
#endif

#if 0 // do not use for now
	if (!do_block && sock->file) { // switch back to blocking mode
		sock->file->f_flags &= ~O_NONBLOCK;
	}
#endif
}

int mars_create_socket(struct mars_socket *msock, struct sockaddr_storage *addr, bool is_server)
{
	struct socket *sock;
	struct sockaddr *sockaddr = (void*)addr;
	int status = -EEXIST;

	if (unlikely(atomic_read(&msock->s_count))) {
		MARS_WRN("#%d socket already in use\n", msock->s_debug_nr);
		goto final;
	}
	if (unlikely(msock->s_socket)) {
		MARS_WRN("#%d socket already open\n", msock->s_debug_nr);
		goto final;
	}
	status = sock_create_kern(AF_INET, SOCK_STREAM, IPPROTO_TCP, &msock->s_socket);
	if (unlikely(status < 0)) {
		msock->s_socket = NULL;
		MARS_WRN("cannot create socket, status = %d\n", status);
		goto final;
	}
	atomic_set(&msock->s_count, 1);
	msock->s_debug_nr = ++current_debug_nr;
	sock = msock->s_socket;
	CHECK_PTR(sock, done);

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

int mars_accept_socket(struct mars_socket *new_msock, struct mars_socket *old_msock, bool do_block)
{
	int status = -ENOENT;
	struct socket *new_socket = NULL;
	bool ok;

	ok = mars_get_socket(old_msock);
	if (likely(ok)) {
		status = kernel_accept(old_msock->s_socket, &new_socket, do_block ? 0 : O_NONBLOCK);
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
	MARS_IO("try socket #%d %p s_dead = %d s_count=%d\n", msock->s_debug_nr, msock->s_socket, msock->s_dead, atomic_read(&msock->s_count));
	if (unlikely(atomic_read(&msock->s_count) <= 0))
		return false;
	atomic_inc(&msock->s_count);
	if (unlikely(!msock->s_socket || msock->s_dead)) {
		mars_put_socket(msock);
		return false;
	}
	MARS_IO("got socket #%d\n", msock->s_debug_nr);
	return true;
}
EXPORT_SYMBOL_GPL(mars_get_socket);

void mars_put_socket(struct mars_socket *msock)
{
	MARS_IO("try socket #%d %p s_dead = %d s_count=%d\n", msock->s_debug_nr, msock->s_socket, msock->s_dead, atomic_read(&msock->s_count));
	if (unlikely(atomic_read(&msock->s_count) <= 0)) {
		MARS_ERR("bad nesting on msock = %p\n", msock);
	} else if (atomic_dec_and_test(&msock->s_count)) {
		struct socket *sock = msock->s_socket;
		MARS_DBG("closing socket #%d %p\n", msock->s_debug_nr, sock);
		if (likely(sock)) {
			kernel_sock_shutdown(sock, SHUT_WR);
			sock_release(sock);
		}
		memset(msock, 0, sizeof(struct mars_socket));
	}
}
EXPORT_SYMBOL_GPL(mars_put_socket);

void mars_shutdown_socket(struct mars_socket *msock)
{
	struct socket *sock = msock->s_socket;
	MARS_IO("try socket #%d %p s_dead = %d s_count=%d\n", msock->s_debug_nr, msock->s_socket, msock->s_dead, atomic_read(&msock->s_count));
	if (likely(sock)) {
		if (unlikely(atomic_read(&msock->s_count) <= 0)) {
			MARS_ERR("bad nesting on msock = %p sock = %p\n", msock, sock);
		}
		if (!msock->s_dead) {
			msock->s_dead = true;
			MARS_DBG("shutdown socket #%d %p\n", msock->s_debug_nr, sock);
			kernel_sock_shutdown(sock, SHUT_WR);
		}
	}
}
EXPORT_SYMBOL_GPL(mars_shutdown_socket);

bool mars_socket_is_alive(struct mars_socket *msock)
{
	bool res = false;
	if (!msock->s_socket)
		goto done;
	if (unlikely(atomic_read(&msock->s_count) <= 0)) {
		MARS_ERR("bad nesting on msock = %p\n", msock);
		goto done;
	}
	if (msock->s_dead)
		goto done;
	res = true;
done:
	MARS_IO("#%d %p s_count = %d s_dead = %d\n", msock->s_debug_nr, msock->s_socket, atomic_read(&msock->s_count), msock->s_dead);
	return res;
}
EXPORT_SYMBOL_GPL(mars_socket_is_alive);

int mars_send_raw(struct mars_socket *msock, void *buf, int len, bool cork)
{
	struct kvec iov = {
		.iov_base = buf,
		.iov_len  = len,
	};
	struct msghdr msg = {
		.msg_iov = (struct iovec*)&iov,
		.msg_flags = 0 | MSG_NOSIGNAL,
	};
	int status = -EIDRM;
	int sent = 0;

	if (!mars_get_socket(msock))
		goto final;

#if 0 // leads to obscure effects (short reads at other end)
	if (cork)
		msg.msg_flags |= TCP_CORK;
#endif

	MARS_IO("#%d buf = %p, len = %d, cork = %d\n", msock->s_debug_nr, buf, len, cork);
	while (sent < len) {
		if (unlikely(msock->s_dead)) {
			MARS_WRN("#%d socket has disappeared\n", msock->s_debug_nr);
			msleep(50);
			status = -EIDRM;
			goto done;
		}

		status = kernel_sendmsg(msock->s_socket, &msg, &iov, 1, len);
		MARS_IO("#%d sendmsg status = %d\n", msock->s_debug_nr, status);

		if (status == -EAGAIN) {
			msleep(50);
			continue;
		}

		if (status == -EINTR) { // ignore it
			flush_signals(current);
			MARS_IO("#%d got signal\n", msock->s_debug_nr);
			msleep(50);
			continue;
		}

		if (status < 0) {
			MARS_WRN("#%d bad socket sendmsg, len=%d, iov_len=%d, sent=%d, status = %d\n", msock->s_debug_nr, len, (int)iov.iov_len, sent, status);
			msleep(50);
			goto done;
		}

		if (!status) {
			MARS_WRN("#%d EOF from socket upon sendmsg\n", msock->s_debug_nr);
			msleep(50);
			status = -ECOMM;
			goto done;
		}

		iov.iov_base += status;
		iov.iov_len  -= status;
		sent += status;
	}
	status = sent;
	MARS_IO("#%d sent %d\n", msock->s_debug_nr, sent);

done:
	if (status < 0 && msock->s_shutdown_on_err)
		mars_shutdown_socket(msock);
	mars_put_socket(msock);
final:
	return status;
}
EXPORT_SYMBOL_GPL(mars_send_raw);

int mars_recv_raw(struct mars_socket *msock, void *buf, int minlen, int maxlen)
{
	int sleeptime = 1000 / HZ;
	int status = -EIDRM;
	int done = 0;

	if (!buf) {
		MARS_WRN("#%d bad receive buffer\n", msock->s_debug_nr);
		return -EINVAL;
	}

	if (!mars_get_socket(msock))
		goto final;

	while (done < minlen) {
		struct kvec iov = {
			.iov_base = buf + done,
			.iov_len = maxlen - done,
		};
		struct msghdr msg = {
			.msg_iovlen = 1,
			.msg_iov = (struct iovec*)&iov,
			.msg_flags = 0 | MSG_WAITALL | MSG_NOSIGNAL,
		};

		if (unlikely(msock->s_dead)) {
			MARS_WRN("#%d socket has disappeared\n", msock->s_debug_nr);
			status = -EIDRM;
			goto err;
		}

		MARS_IO("#%d done %d, fetching %d bytes\n", msock->s_debug_nr, done, maxlen-done);

		status = kernel_recvmsg(msock->s_socket, &msg, &iov, 1, maxlen-done, msg.msg_flags);

		MARS_IO("#%d status = %d\n", msock->s_debug_nr, status);

		if (status == -EAGAIN) {
			// linearly increasing backoff
			if (sleeptime < 100)
				sleeptime++;
			msleep(sleeptime);
			continue;
		}
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

err:
	if (status < 0 && msock->s_shutdown_on_err)
		mars_shutdown_socket(msock);
	mars_put_socket(msock);
final:
	return status;
}
EXPORT_SYMBOL_GPL(mars_recv_raw);

///////////////////////////////////////////////////////////////////////

/* Mid-level field data exchange
 */

/* TODO: make this bytesex-aware
 */
#define MARS_NET_MAGIC 0x63f0A2ec6148f48cll
#define MAX_FIELD_LEN 32


struct mars_net_header {
	u64 h_magic;
	u16 h_seq;
	u16 h_len;
	char h_name[MAX_FIELD_LEN];
};

int _mars_send_struct(struct mars_socket *msock, void *data, const struct meta *meta, int *seq, bool cork)
{
	int count = 0;
	int status = 0;

	if (!data) { // directly send EOR
		goto done;
	}
	for (; meta->field_name != NULL; meta++) {
		struct mars_net_header header = {
			.h_magic = MARS_NET_MAGIC,
			.h_seq = ++(*seq),
		};
		void *item = data + meta->field_offset;
		int len = meta->field_size;
#if 1
		if (len > 16 * PAGE_SIZE) {
			MARS_WRN("#%d implausible len=%d, \n", msock->s_debug_nr, len);
			msleep(30000);
			status = -EINVAL;
			break;
		}
#endif

		/* Automatically keep the lamport clock correct.
		 */
		mars_check_meta(meta, data);

		status = 0;
		switch (meta->field_type) {
		case FIELD_STRING:
			item = *(void**)item;
			len = 0;
			if (item)
				len = strlen(item) + 1;
			break;
		case FIELD_REF:
			if (!meta->field_ref) {
				MARS_WRN("#%d improper FIELD_REF definition\n", msock->s_debug_nr);
				status = -EINVAL;
				break;
			}
			item = *(void**)item;
			len = meta->field_ref->field_size;
			if (!item)
				len = 0;
			break;
		case FIELD_DONE:
			len = 0;
		case FIELD_SUB:
		case FIELD_RAW:
		case FIELD_INT:
		case FIELD_UINT:
			// all ok
			break;
		default:
			MARS_WRN("#%d invalid field type %d\n", msock->s_debug_nr, meta->field_type);
			status = -EINVAL;
			break;
		}
		if (status < 0)
			break;

		header.h_len = len;
		strncpy(header.h_name, meta->field_name, MAX_FIELD_LEN);
		header.h_name[MAX_FIELD_LEN-1] = '\0';

		MARS_IO("#%d sending header %d '%s' len = %d\n", msock->s_debug_nr, header.h_seq, header.h_name, len);
		status = mars_send_raw(msock, &header, sizeof(header), true);
		if (status < 0)
			break;

		switch (meta->field_type) {
		case FIELD_REF:
		case FIELD_SUB:
			if (len > 0) {
				status = _mars_send_struct(msock, item, meta->field_ref, seq, true);
				if (status > 0)
					count += status;
			}
			break;
		default:
			if (len > 0) {
				MARS_IO("#%d sending extra %d\n", msock->s_debug_nr, len);
				status = mars_send_raw(msock, item, len, true);
				if (status > 0)
					count++;
			}
		}

		if (status < 0) {
			break;
		}
	}
done:
	if (status >= 0) { // send EOR
		struct mars_net_header header = {
			.h_magic = MARS_NET_MAGIC,
			.h_seq = ++(*seq),
			// .h_name is left empty
		};
		status = mars_send_raw(msock, &header, sizeof(header), cork);
	}
	if (status >= 0)
		status = count;
	return status;
}

int mars_send_struct(struct mars_socket *msock, void *data, const struct meta *meta)
{
	int seq = 0;
	return _mars_send_struct(msock, data, meta, &seq, false);
}
EXPORT_SYMBOL_GPL(mars_send_struct);

int _mars_recv_struct(struct mars_socket *msock, void *data, const struct meta *meta, int *seq, int line)
{
	int count = 0;
	int status = -EINVAL;

	MARS_IO("#%d called from line %d\n", msock->s_debug_nr, line);
	if (!data) {
		goto done;
	}
	for (;;) {
		struct mars_net_header header = {};
		const struct meta *tmp;
		void *item;
		void *mem;
		status = mars_recv_raw(msock, &header, sizeof(header), sizeof(header));
		if (status == -EAGAIN) {
			msleep(50);
			continue;
		}
		if (status < 0) {
			MARS_WRN("#%d called from line %d status = %d\n", msock->s_debug_nr, line, status);
			break;
		}
		MARS_IO("#%d called from line %d got header %d '%s' len = %d\n", msock->s_debug_nr, line, header.h_seq, header.h_name, header.h_len);
		if (status != sizeof(header)) {
			MARS_WRN("#%d called from line %d bad header len = %d (required=%d)\n", msock->s_debug_nr, line, status, (int)sizeof(header));
			break;
		}
		if (header.h_magic != MARS_NET_MAGIC) {
			MARS_WRN("#%d called from line %d bad packet header magic = %llx\n", msock->s_debug_nr, line, header.h_magic);
			status = -ENOMSG;
			break;
		}
		if (!header.h_name[0]) { // got EOR
			status = 0;
			break;
		};
		if (header.h_seq <= *seq) {
			MARS_WRN("#%d called from line %d unexpected packet data, seq=%d (expected=%d)\n", msock->s_debug_nr, line, header.h_seq, (*seq) + 1);
			status = -ENOMSG;
			break;
		}
		*seq = header.h_seq;

		if (!header.h_name[0]) { // end of record (EOR)
			status = 0;
			break;
		}

		tmp = find_meta(meta, header.h_name);
		if (unlikely(!tmp)) {
			MARS_WRN("#%d called from line %d unknown field '%s'\n", msock->s_debug_nr, line, header.h_name);
			if (header.h_len > 0) { // try to continue by skipping the rest of data
				void *dummy = brick_mem_alloc(header.h_len);
				status = -ENOMEM;
				if (!dummy)
					break;
				status = mars_recv_raw(msock, dummy, header.h_len, header.h_len);
				brick_mem_free(dummy);
				if (status < 0)
					break;
			}
			continue;
		}

		status = 0;
		item = data + tmp->field_offset;
		switch (tmp->field_type) {
		case FIELD_REF:
		case FIELD_STRING:
			if (header.h_len <= 0) {
				mem = NULL;
			} else {
				if (tmp->field_type == FIELD_STRING) {
					mem = _brick_string_alloc(header.h_len + 1, line);
				} else {
					mem = brick_zmem_alloc(header.h_len + 1);
				}
				if (!mem) {
					status = -ENOMEM;
					goto done;
				}
			}
			*(void**)item = mem;
			item = mem;
			break;
		}

		switch (tmp->field_type) {
		case FIELD_REF:
		case FIELD_SUB:
			if (!item) {
				MARS_WRN("#%d called from line %d bad item\n", msock->s_debug_nr, line);
				status = -EINVAL;
				break;
			}

			if (header.h_len > 0) {
				MARS_IO("#%d called from line %d starting recursive structure\n", msock->s_debug_nr, line);
				status = _mars_recv_struct(msock, item, tmp->field_ref, seq, line);
				MARS_IO("#%d called from line %d ending recursive structure, status = %d\n", msock->s_debug_nr, line, status);

				if (status > 0)
					count += status;
			}
			break;
		default:
			if (header.h_len > 0) {
				if (!item) {
					MARS_WRN("#%d called from line %d bad item\n", msock->s_debug_nr, line);
					status = -EINVAL;
					break;
				}
				MARS_IO("#%d called from line %d reading extra %d\n", msock->s_debug_nr, line, header.h_len);
				status = mars_recv_raw(msock, item, header.h_len, header.h_len);
				while (status == -EAGAIN) {
					msleep(50);
					status = mars_recv_raw(msock, item, header.h_len, header.h_len);
				}
				if (status >= 0) {
					//MARS_IO("#%d got data len = %d status = %d\n", msock->s_debug_nr, header.h_len, status);
					count++;
				} else {
					MARS_WRN("#%d called from line %d len = %d, status = %d\n", msock->s_debug_nr, line, header.h_len, status);
				}
			}
		}
		if (status < 0)
			break;
	}
done:
	if (status >= 0) {
		status = count;
		mars_check_meta(meta, data);
	} else {
		MARS_WRN("#%d called from line %d status = %d\n", msock->s_debug_nr, line, status);
	}
	return status;
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

static
void mars_check_meta(const struct meta *meta, void *data)
{
	/* Automatically keep the lamport clock correct.
	 */
	if (meta == mars_cmd_meta) {
		struct timespec *stamp = &((struct mars_cmd*)data)->cmd_stamp;
		get_lamport(stamp);
	} else if (meta == mars_timespec_meta) {
		set_lamport(data);
	}

}


int mars_send_mref(struct mars_socket *msock, struct mref_object *mref)
{
	struct mars_cmd cmd = {
		.cmd_code = CMD_MREF,
		.cmd_int1 = mref->ref_id,
	};
	int seq = 0;
	int status;

	status = _mars_send_struct(msock, &cmd, mars_cmd_meta, &seq, true);
	if (status < 0)
		goto done;

	seq = 0;
	status = _mars_send_struct(msock, mref, mars_mref_meta, &seq, mref->ref_rw != 0);
	if (status < 0)
		goto done;

	if (mref->ref_rw != 0) {
		status = mars_send_raw(msock, mref->ref_data, mref->ref_len, false);
	}
done:
	return status;
}
EXPORT_SYMBOL_GPL(mars_send_mref);

int mars_recv_mref(struct mars_socket *msock, struct mref_object *mref)
{
	int seq = 0;
	int status;

	status = _mars_recv_struct(msock, mref, mars_mref_meta, &seq, __LINE__);
	if (status < 0)
		goto done;
	if (mref->ref_rw) {
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

	status = _mars_send_struct(msock, &cmd, mars_cmd_meta, &seq, true);
	if (status < 0)
		goto done;

	seq = 0;
	status = _mars_send_struct(msock, mref, mars_mref_meta, &seq, !mref->ref_rw);
	if (status < 0)
		goto done;

	if (!mref->ref_rw) {
		MARS_IO("#%d sending blocklen = %d\n", msock->s_debug_nr, mref->ref_len);
		status = mars_send_raw(msock, mref->ref_data, mref->ref_len, false);
	}
done:
	return status;
}
EXPORT_SYMBOL_GPL(mars_send_cb);

int mars_recv_cb(struct mars_socket *msock, struct mref_object *mref)
{
	int seq = 0;
	int status;

	status = _mars_recv_struct(msock, mref, mars_mref_meta, &seq, __LINE__);
	if (status < 0)
		goto done;
	if (!mref->ref_rw) {
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

int __init init_mars_net(void)
{
	MARS_INF("init_net()\n");
	return 0;
}

void __exit exit_mars_net(void)
{
	MARS_INF("exit_net()\n");
}

#ifndef CONFIG_MARS_HAVE_BIGMODULE
MODULE_DESCRIPTION("MARS network infrastructure");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_mars_net);
module_exit(exit_mars_net);
#endif
