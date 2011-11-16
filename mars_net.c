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

static void _check(int status)
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

/* The original struct socket has no refcount. This leads to problems
 * during long-lasting system calls when racing with socket shutdown.
 * This is just a small wrapper adding a refcount.
 */
struct mars_socket {
	atomic_t s_count;
	struct socket *s_socket;
	bool s_dead;
};

struct mars_socket *mars_create_socket(struct sockaddr_storage *addr, bool is_server)
{
	struct mars_socket *msock;
	struct socket *sock;
	struct sockaddr *sockaddr = (void*)addr;
	int x_true = 1;
	int status = -ENOMEM;

	msock = brick_zmem_alloc(sizeof(struct mars_socket));
	if (!msock)
		goto done;

	status = sock_create_kern(AF_INET, SOCK_STREAM, IPPROTO_TCP, &msock->s_socket);
	if (unlikely(status < 0)) {
		MARS_WRN("cannot create socket, status = %d\n", status);
		goto done;
	}
	atomic_set(&msock->s_count, 1);
	sock = msock->s_socket;
	status = -EINVAL;
	CHECK_PTR(sock, done);

	/* TODO: improve this by a table-driven approach
	 */
	sock->sk->sk_rcvtimeo = sock->sk->sk_sndtimeo = default_tcp_params.tcp_timeout * HZ;
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

	if (is_server) {
		status = kernel_bind(sock, sockaddr, sizeof(*sockaddr));
		if (unlikely(status < 0)) {
			MARS_WRN("bind failed, status = %d\n", status);
			goto done;
		}
		status = kernel_listen(sock, 16);
		if (status < 0) {
			MARS_WRN("listen failed, status = %d\n", status);
		}
	} else {
		status = kernel_connect(sock, sockaddr, sizeof(*sockaddr), 0);
		if (status < 0) {
			MARS_DBG("connect failed, status = %d\n", status);
		}
	}

done:
	if (status < 0) {
		mars_put_socket(msock);
		msock = ERR_PTR(status);
	}
	return msock;
}
EXPORT_SYMBOL_GPL(mars_create_socket);

struct mars_socket *mars_accept_socket(struct mars_socket *msock, bool do_block)
{
	int status = -ENOENT;
	if (likely(msock)) {
		struct mars_socket *new_msock;
		struct socket *new_socket = NULL;

		mars_get_socket(msock);
		status = kernel_accept(msock->s_socket, &new_socket, do_block ? 0 : O_NONBLOCK);
		mars_put_socket(msock);
		if (unlikely(status < 0)) {
			goto err;
		}
		if (unlikely(!new_socket)) {
			status = -EBADF;
			goto err;
		}

#if 0 // do not use for now
		if (!do_block && new_socket->file) { // switch back to blocking mode
			new_socket->file->f_flags &= ~O_NONBLOCK;
		}
#endif
		
		status = -ENOMEM;
		new_msock = brick_zmem_alloc(sizeof(struct mars_socket));
		if (!new_msock) {
			kernel_sock_shutdown(new_socket, SHUT_WR);
			sock_release(new_socket);
			goto err;
		}
		atomic_set(&new_msock->s_count, 1);
		new_msock->s_socket = new_socket;
		return new_msock;
	}
err:
	return ERR_PTR(status);
}
EXPORT_SYMBOL_GPL(mars_accept_socket);

struct mars_socket *mars_get_socket(struct mars_socket *msock)
{
	if (likely(msock)) {
		atomic_inc(&msock->s_count);
	}
	return msock;
}
EXPORT_SYMBOL_GPL(mars_get_socket);

void mars_put_socket(struct mars_socket *msock)
{
	if (likely(msock)) {
		if (atomic_dec_and_test(&msock->s_count)) {
			struct socket *sock = msock->s_socket;
			if (sock) {
				if (!msock->s_dead) {
					msock->s_dead = true;
					kernel_sock_shutdown(sock, SHUT_WR);
				}
				sock_release(sock);
			}
			brick_mem_free(msock);
		}
	}
}
EXPORT_SYMBOL_GPL(mars_put_socket);

void mars_shutdown_socket(struct mars_socket *msock)
{
	if (likely(msock)) {
		struct socket *sock = msock->s_socket;
		if (sock && !msock->s_dead) {
			msock->s_dead = true;
			kernel_sock_shutdown(sock, SHUT_WR);
		}
	}
}
EXPORT_SYMBOL_GPL(mars_shutdown_socket);

bool mars_socket_is_alive(struct mars_socket *msock)
{
	if (!msock || msock->s_dead)
		return false;
	return true;
}
EXPORT_SYMBOL_GPL(mars_socket_is_alive);

int mars_send(struct mars_socket *msock, void *buf, int len)
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
		goto done;

	//MARS_IO("buf = %p, len = %d\n", buf, len);
	while (sent < len) {
		if (unlikely(msock->s_dead)) {
			MARS_WRN("socket has disappeared\n");
			status = -EIDRM;
			goto done;
		}

		status = kernel_sendmsg(msock->s_socket, &msg, &iov, 1, len);

		if (status == -EAGAIN) {
			msleep(50);
			continue;
		}

		if (status == -EINTR) { // ignore it
			flush_signals(current);
			msleep(50);
			continue;
		}

		if (status < 0) {
			MARS_WRN("bad socket sendmsg, len=%d, iov_len=%d, sent=%d, status = %d\n", len, (int)iov.iov_len, sent, status);
			goto done;
		}

		if (!status) {
			MARS_WRN("EOF from socket upon sendmsg\n");
			status = -ECOMM;
			goto done;
		}

		iov.iov_base += status;
		iov.iov_len  -= status;
		sent += status;
	}
	status = sent;

done:
	mars_put_socket(msock);
	return status;
}
EXPORT_SYMBOL_GPL(mars_send);

int mars_recv(struct mars_socket *msock, void *buf, int minlen, int maxlen)
{
	int sleeptime = 1000 / HZ;
	int status = -EIDRM;
	int done = 0;

	if (!buf) {
		MARS_WRN("bad receive buffer\n");
		return -EINVAL;
	}

	if (!mars_get_socket(msock))
		goto err;

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
			MARS_WRN("socket has disappeared\n");
			status = -EIDRM;
			goto err;
		}

		MARS_IO("done %d, fetching %d bytes\n", done, maxlen-done);

		status = kernel_recvmsg(msock->s_socket, &msg, &iov, 1, maxlen-done, msg.msg_flags);

		if (status == -EAGAIN) {
			// linearly increasing backoff
			if (sleeptime < 100)
				sleeptime++;
			msleep(sleeptime);
			continue;
		}
		if (!status) { // EOF
			MARS_WRN("got EOF from socket (done=%d, req_size=%d)\n", done, maxlen - done);
			status = -EPIPE;
			goto err;
		}
		if (status < 0) {
			MARS_WRN("bad recvmsg, status = %d\n", status);
			goto err;
		}
		done += status;
		sleeptime = 1000 / HZ;
	}
	status = done;

err:
	mars_put_socket(msock);
	return status;
}
EXPORT_SYMBOL_GPL(mars_recv);

///////////////////////////////////////////////////////////////////////

/* Mid-level field data exchange
 */

/* TODO: make this bytesex-aware
 */
#define MARS_NET_MAGIC 0x63f092ec6048f48cll
#define MAX_FIELD_LEN 32


struct mars_net_header {
	u64 h_magic;
	char h_name[MAX_FIELD_LEN];
	u16 h_seq;
	u16 h_len;
};

int _mars_send_struct(struct mars_socket *msock, void *data, const struct meta *meta, int *seq)
{
	int count = 0;
	int status = 0;
	if (!data) { // send EOR
		struct mars_net_header header = {
			.h_magic = MARS_NET_MAGIC,
			.h_seq = -1,
		};
		return mars_send(msock, &header, sizeof(header));
	}
	for (; ; meta++) {
		struct mars_net_header header = {
			.h_magic = MARS_NET_MAGIC,
			.h_seq = ++(*seq),
		};
		void *item = data + meta->field_offset;
		int len = meta->field_size;
#if 1
		if (len > 16 * PAGE_SIZE) {
			MARS_WRN("implausible len=%d, \n", len);
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
				MARS_WRN("improper FIELD_REF definition\n");
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
			MARS_WRN("invalid field type %d\n", meta->field_type);
			status = -EINVAL;
			break;
		}
		if (status < 0)
			break;

		header.h_len = len;
		if (meta->field_name) {
			strncpy(header.h_name, meta->field_name, MAX_FIELD_LEN);
			header.h_name[MAX_FIELD_LEN-1] = '\0';
		}

		MARS_IO("sending header %d '%s' len = %d\n", header.h_seq, header.h_name, len);
		status = mars_send(msock, &header, sizeof(header));
		if (status < 0 || !meta->field_name) { // EOR
			break;
		}

		switch (meta->field_type) {
		case FIELD_REF:
		case FIELD_SUB:
			status = _mars_send_struct(msock, item, meta->field_ref, seq);
			if (status > 0)
				count += status;
			break;
		default:
			if (len > 0) {
				MARS_IO("sending extra %d\n", len);
				status = mars_send(msock, item, len);
				if (status > 0)
					count++;
			}
		}

		if (status < 0) {
			break;
		}
	}
	if (status >= 0)
		status = count;
	return status;
}

int mars_send_struct(struct mars_socket *msock, void *data, const struct meta *meta)
{
	int seq = 0;
	return _mars_send_struct(msock, data, meta, &seq);
}
EXPORT_SYMBOL_GPL(mars_send_struct);

int _mars_recv_struct(struct mars_socket *msock, void *data, const struct meta *meta, int *seq, int line)
{
	int count = 0;
	int status = -EINVAL;

	//MARS_IO("\n");
	if (!data) {
		goto done;
	}
	for (;;) {
		struct mars_net_header header = {};
		const struct meta *tmp;
		void *item;
		void *mem;
		status = mars_recv(msock, &header, sizeof(header), sizeof(header));
		if (status == -EAGAIN) {
			msleep(50);
			continue;
		}
		if (status < 0) {
			MARS_WRN("status = %d\n", status);
			break;
		}
		MARS_IO("got header %d '%s' len = %d\n", header.h_seq, header.h_name, header.h_len);
		if (header.h_magic != MARS_NET_MAGIC) {
			MARS_WRN("bad packet header magic = %llx\n", header.h_magic);
			status = -ENOMSG;
			break;
		}
		if (header.h_seq == -1) { // got EOR
			status = 0;
			break;
		};
		if (header.h_seq <= *seq) {
			MARS_WRN("unexpected packet data, seq=%d (expected=%d)\n", header.h_seq, (*seq) + 1);
			status = -ENOMSG;
			break;
		}
		*seq = header.h_seq;

		if (!header.h_name[0]) { // end of record (EOR)
			status = 0;
			break;
		}

		tmp = find_meta(meta, header.h_name);
		if (!tmp) {
			MARS_WRN("unknown field '%s'\n", header.h_name);
			if (header.h_len > 0) { // try to continue by skipping the rest of data
				void *dummy = brick_mem_alloc(header.h_len);
				status = -ENOMEM;
				if (!dummy)
					break;
				status = mars_recv(msock, dummy, header.h_len, header.h_len);
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
				MARS_WRN("bad item\n");
				status = -EINVAL;
				break;
			}

			MARS_IO("starting recursive structure\n");
			status = _mars_recv_struct(msock, item, tmp->field_ref, seq, line);
			MARS_IO("ending recursive structure, status = %d\n", status);

			if (status > 0)
				count += status;
			break;
		default:
			if (header.h_len > 0) {
				if (!item) {
					MARS_WRN("bad item\n");
					status = -EINVAL;
					break;
				}
				MARS_IO("reading extra %d\n", header.h_len);
				status = mars_recv(msock, item, header.h_len, header.h_len);
				while (status == -EAGAIN) {
					msleep(50);
					status = mars_recv(msock, item, header.h_len, header.h_len);
				}
				if (status >= 0) {
					//MARS_IO("got data len = %d status = %d\n", header.h_len, status);
					count++;
				} else {
					MARS_WRN("len = %d, status = %d\n", header.h_len, status);
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
		MARS_WRN("status = %d\n", status);
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
	int status;

	status = mars_send_struct(msock, &cmd, mars_cmd_meta);
	if (status < 0)
		goto done;

	status = mars_send_struct(msock, mref, mars_mref_meta);
	if (status < 0)
		goto done;

	if (mref->ref_rw) {
		status = mars_send(msock, mref->ref_data, mref->ref_len);
	}
done:
	return status;
}
EXPORT_SYMBOL_GPL(mars_send_mref);

int mars_recv_mref(struct mars_socket *msock, struct mref_object *mref)
{
	int status;
	status = mars_recv_struct(msock, mref, mars_mref_meta);
	if (status < 0)
		goto done;
	if (mref->ref_rw) {
		if (!mref->ref_data)
			mref->ref_data = brick_zmem_alloc(mref->ref_len);
		if (!mref->ref_data) {
			status = -ENOMEM;
			goto done;
		}
		status = mars_recv(msock, mref->ref_data, mref->ref_len, mref->ref_len);
		if (status < 0)
			MARS_WRN("mref_len = %d, status = %d\n", mref->ref_len, status);
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
	int status;
	status = mars_send_struct(msock, &cmd, mars_cmd_meta);
	if (status < 0)
		goto done;
	status = mars_send_struct(msock, mref, mars_mref_meta);
	if (status < 0)
		goto done;
	if (!mref->ref_rw) {
		MARS_IO("sending blocklen = %d\n", mref->ref_len);
		status = mars_send(msock, mref->ref_data, mref->ref_len);
	}
done:
	return status;
}
EXPORT_SYMBOL_GPL(mars_send_cb);

int mars_recv_cb(struct mars_socket *msock, struct mref_object *mref)
{
	int status;
	status = mars_recv_struct(msock, mref, mars_mref_meta);
	if (status < 0)
		goto done;
	if (!mref->ref_rw) {
		if (!mref->ref_data) {
			MARS_WRN("no internal buffer available\n");
			status = -EINVAL;
			goto done;
		}
		MARS_IO("receiving blocklen = %d\n", mref->ref_len);
		status = mars_recv(msock, mref->ref_data, mref->ref_len, mref->ref_len);
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
