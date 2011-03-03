// (c) 2011 Thomas Schoebel-Theuer / 1&1 Internet AG

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING
//#define IO_DEBUGGING

#ifdef IO_DEBUGGING
#define MARS_IO MARS_DBG
#else
#define MARS_IO(args...) /*empty*/
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#define _STRATEGY
#include "mars.h"
#include "mars_net.h"

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

char *mars_translate_hostname(struct mars_global *global, const char *name)
{
	const char *res = name;
	struct mars_dent *test;
	char *tmp;

	if (unlikely(!global)) {
		goto done;
	}
	tmp = path_make("/mars/ips/ip-%s", name);
	if (unlikely(!tmp)) {
		goto done;
	}

	test = mars_find_dent(global, tmp);
	if (test && test->new_link) {
		MARS_DBG("'%s' => '%s'\n", tmp, test->new_link);
		res = test->new_link;
	}
	kfree(tmp);

done:
	return kstrdup(res, GFP_MARS);
}
EXPORT_SYMBOL_GPL(mars_translate_hostname);


static void _check(int status)
{
	if (status < 0) {
		MARS_ERR("cannot set socket option, status = %d\n", status);
	}
}

int mars_create_sockaddr(struct sockaddr_storage *addr, const char *spec)
{
	struct sockaddr_in *sockaddr = (void*)addr;
	char *new_spec;
	char *tmp_spec;
	int status = 0;

	memset(addr, sizeof(*addr), 0);
	sockaddr->sin_family = AF_INET;
	sockaddr->sin_port = htons(MARS_DEFAULT_PORT);

	/* Try to translate hostnames to IPs if possible.
	 */
	new_spec = mars_translate_hostname(mars_global, spec);
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
	if (new_spec)
		kfree(new_spec);
	return status;
}
EXPORT_SYMBOL_GPL(mars_create_sockaddr);

int mars_create_socket(struct socket **sock, struct sockaddr_storage *addr, bool is_server)
{
	struct sockaddr null_bind = {};
	struct sockaddr *sockaddr = (void*)addr;
	int x_true = 1;
	int status;

	if (!is_server) {
		sockaddr = &null_bind;
	}

	status = sock_create_kern(AF_INET, SOCK_STREAM, IPPROTO_TCP, sock);
	if (status < 0) {
		*sock = NULL;
		MARS_ERR("cannot create socket, status = %d\n", status);
		return status;
	}

	/* TODO: improve this by a table-driven approach
	 */
	(*sock)->sk->sk_rcvtimeo = (*sock)->sk->sk_sndtimeo = default_tcp_params.tcp_timeout * HZ;
	status = kernel_setsockopt(*sock, SOL_SOCKET, SO_SNDBUF, (char*)&default_tcp_params.window_size, sizeof(default_tcp_params.window_size));
	_check(status);
	status = kernel_setsockopt(*sock, SOL_SOCKET, SO_RCVBUF, (char*)&default_tcp_params.window_size, sizeof(default_tcp_params.window_size));
	_check(status);
	status = kernel_setsockopt(*sock, SOL_IP, SO_PRIORITY, (char*)&default_tcp_params.tos, sizeof(default_tcp_params.tos));
	_check(status);
	status = kernel_setsockopt(*sock, IPPROTO_TCP, TCP_NODELAY, (char*)&x_true, sizeof(x_true));
	_check(status);
	status = kernel_setsockopt(*sock, SOL_SOCKET, SO_KEEPALIVE, (char*)&x_true, sizeof(x_true));
	_check(status);
	status = kernel_setsockopt(*sock, IPPROTO_TCP, TCP_KEEPCNT, (char*)&default_tcp_params.tcp_keepcnt, sizeof(default_tcp_params.tcp_keepcnt));
	_check(status);
	status = kernel_setsockopt(*sock, IPPROTO_TCP, TCP_KEEPINTVL, (char*)&default_tcp_params.tcp_keepintvl, sizeof(default_tcp_params.tcp_keepintvl));
	_check(status);
	status = kernel_setsockopt(*sock, IPPROTO_TCP, TCP_KEEPIDLE, (char*)&default_tcp_params.tcp_keepidle, sizeof(default_tcp_params.tcp_keepidle));
	_check(status);
	
	status = kernel_bind(*sock, sockaddr, sizeof(*sockaddr));
	if (status < 0) {
		MARS_ERR("bind failed, status = %d\n", status);
		return status;
	}

	if (!is_server) {
		sockaddr = (void*)addr;
		status = kernel_connect(*sock, sockaddr, sizeof(*sockaddr), 0);
		if (status < 0) {
			MARS_ERR("connect failed, status = %d\n", status);
		}
	}

	return status;
}
EXPORT_SYMBOL_GPL(mars_create_socket);

int mars_send(struct socket **sock, void *buf, int len)
{
	struct kvec iov = {
		.iov_base = buf,
		.iov_len  = len,
	};
	struct msghdr msg = {
		.msg_iov = (struct iovec*)&iov,
		.msg_flags = 0 /* | MSG_NOSIGNAL*/,
	};
	int status = -EIDRM;
	int sent = 0;

	//MARS_IO("buf = %p, len = %d\n", buf, len);
	while (sent < len) {
		if (unlikely(!*sock)) {
			MARS_ERR("socket has disappeared\n");
			status = -EIDRM;
			goto done;
		}

		status = kernel_sendmsg(*sock, &msg, &iov, 1, len);

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
			MARS_ERR("bad socket sendmsg, len=%d, iov_len=%d, sent=%d, status = %d\n", len, (int)iov.iov_len, sent, status);
			goto done;
		}

		if (!status) {
			MARS_ERR("EOF from socket upon sendmsg\n");
			status = -ECOMM;
			goto done;
		}

		iov.iov_base += status;
		iov.iov_len  -= status;
		sent += status;
	}
	status = sent;
done:
	return status;
}
EXPORT_SYMBOL_GPL(mars_send);

int mars_recv(struct socket **sock, void *buf, int minlen, int maxlen)
{
	int status = -EIDRM;
	int done = 0;

	if (!buf) {
		MARS_ERR("bad receive buffer\n");
		return -EINVAL;
	}

	while (done < minlen) {
		struct kvec iov = {
			.iov_base = buf + done,
			.iov_len = maxlen - done,
		};
		struct msghdr msg = {
			.msg_iovlen = 1,
			.msg_iov = (struct iovec*)&iov,
			.msg_flags = 0 | MSG_WAITALL /*| MSG_NOSIGNAL*/,
		};

		if (unlikely(!*sock)) {
			MARS_ERR("socket has disappeared\n");
			status = -EIDRM;
			goto err;
		}

		MARS_IO("done %d, fetching %d bytes\n", done, maxlen-done);

		status = kernel_recvmsg(*sock, &msg, &iov, 1, maxlen-done, msg.msg_flags);

		if (status == -EAGAIN) {
#if 0
			if (!done)
				goto err;
#endif
			msleep(50);
			continue;
		}
		if (!status) { // EOF
			MARS_ERR("got EOF (done=%d, req_size=%d)\n", done, maxlen-done);
			status = -EPIPE;
			goto err;
		}
		if (status < 0) {
			MARS_ERR("bad recvmsg, status = %d\n", status);
			goto err;
		}
		done += status;
	}
	status = done;

err:
	return status;
}
EXPORT_SYMBOL_GPL(mars_recv);

///////////////////////////////////////////////////////////////////////

/* Mid-level field data exchange
 */

/* TODO: make this bytesex-aware
 */
#define MARS_NET_MAGIC 0x63f092ec6048f48cll

struct mars_net_header {
	u64 h_magic;
	char h_name[MAX_FIELD_LEN];
	u16 h_seq;
	u16 h_len;
};

int _mars_send_struct(struct socket **sock, void *data, const struct meta *meta, int *seq)
{
	int count = 0;
	int status = 0;
	if (!data) { // send EOF
		struct mars_net_header header = {
			.h_magic = MARS_NET_MAGIC,
			.h_seq = -1,
		};
		return mars_send(sock, &header, sizeof(header));
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
			MARS_ERR("implausible len=%d, \n", len);
			msleep(30000);
			status = -EINVAL;
			break;
		}
#endif

		/* Automatically keep the lamport clock correct.
		 */
		if (meta == mars_cmd_meta) {
			struct timespec *stamp = &((struct mars_cmd*)data)->cmd_stamp;
			get_lamport(stamp);
		} else if (meta == mars_timespec_meta) {
			set_lamport(data);
		}

		status = 0;
		switch (meta->field_type) {
		case FIELD_STRING:
			item = *(void**)item;
			len = 0;
			if (item)
				len = strlen(item);
			break;
		case FIELD_REF:
			if (!meta->field_ref) {
				MARS_ERR("improper FIELD_REF definition\n");
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
			MARS_ERR("invalid field type %d\n", meta->field_type);
			status = -EINVAL;
			break;
		}
		if (status < 0)
			break;

		header.h_len = len;
		strncpy(header.h_name, meta->field_name, MAX_FIELD_LEN);

		MARS_IO("sending header %d '%s' len = %d\n", header.h_seq, meta->field_name, len);
		status = mars_send(sock, &header, sizeof(header));
		if (status < 0 || !meta->field_name[0]) { // EOR
			break;
		}

		switch (meta->field_type) {
		case FIELD_REF:
		case FIELD_SUB:
			status = _mars_send_struct(sock, item, meta->field_ref, seq);
			if (status > 0)
				count += status;
			break;
		default:
			if (len > 0) {
				MARS_IO("sending extra %d\n", len);
				status = mars_send(sock, item, len);
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

int mars_send_struct(struct socket **sock, void *data, const struct meta *meta)
{
	int seq = 0;
	return _mars_send_struct(sock, data, meta, &seq);
}
EXPORT_SYMBOL_GPL(mars_send_struct);

int _mars_recv_struct(struct socket **sock, void *data, const struct meta *meta, int *seq)
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
		status = mars_recv(sock, &header, sizeof(header), sizeof(header));
		if (status == -EAGAIN) {
			msleep(50);
			continue;
		}
		if (status < 0) {
			MARS_ERR("status = %d\n", status);
			break;
		}
		MARS_IO("got header %d '%s' len = %d\n", header.h_seq, header.h_name, header.h_len);
		if (header.h_magic != MARS_NET_MAGIC) {
			MARS_ERR("bad packet header magic = %llx\n", header.h_magic);
			status = -ENOMSG;
			break;
		}
		if (header.h_seq == -1) { // got EOF
			status = 0;
			break;
		};
		if (header.h_seq <= *seq) {
			MARS_ERR("unexpected packet data, seq=%d (expected=%d)\n", header.h_seq, (*seq) + 1);
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
			MARS_ERR("unknown field '%s'\n", header.h_name);
			if (header.h_len > 0) { // try to continue by skipping the rest of data
				void *dummy = kmalloc(header.h_len, GFP_MARS);
				status = -ENOMEM;
				if (!dummy)
					break;
				status = mars_recv(sock, dummy, header.h_len, header.h_len);
				kfree(dummy);
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
				mem = kzalloc(header.h_len + 1, GFP_MARS);
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
				MARS_ERR("bad item\n");
				status = -EINVAL;
				break;
			}

			MARS_IO("starting recursive structure\n");
			status = _mars_recv_struct(sock, item, tmp->field_ref, seq);
			MARS_IO("ending recursive structure, status = %d\n", status);

			if (status > 0)
				count += status;
			break;
		default:
			if (header.h_len > 0) {
				if (!item) {
					MARS_ERR("bad item\n");
					status = -EINVAL;
					break;
				}
				MARS_IO("reading extra %d\n", header.h_len);
				status = mars_recv(sock, item, header.h_len, header.h_len);
				while (status == -EAGAIN) {
					msleep(50);
					status = mars_recv(sock, item, header.h_len, header.h_len);
				}
				if (status >= 0) {
					//MARS_IO("got data len = %d status = %d\n", header.h_len, status);
					count++;
				} else {
					MARS_ERR("len = %d, status = %d\n", header.h_len, status);
				}
			}
		}
		if (status < 0)
			break;
	}
done:
	if (status >= 0) {
		status = count;
		if (meta == mars_timespec_meta)
			set_lamport(data);
	} else {
		MARS_ERR("status = %d\n", status);
	}
	return status;
}

int mars_recv_struct(struct socket **sock, void *data, const struct meta *meta)
{
	int seq = 0;
	return _mars_recv_struct(sock, data, meta, &seq);
}
EXPORT_SYMBOL_GPL(mars_recv_struct);

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

int mars_send_dent_list(struct socket **sock, struct list_head *anchor)
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
	if (status >= 0) { // send EOF
		status = mars_send_struct(sock, NULL, mars_dent_meta);
	}
	return status;
}
EXPORT_SYMBOL_GPL(mars_send_dent_list);

int mars_recv_dent_list(struct socket **sock, struct list_head *anchor)
{
	int status;
	for (;;) {
		struct mars_dent *dent = kzalloc(sizeof(struct mars_dent), GFP_MARS);
		if (!dent)
			return -ENOMEM;

		//MARS_IO("\n");

		status = mars_recv_struct(sock, dent, mars_dent_meta);
		if (status <= 0) {
			kfree(dent);
			goto done;
		}
		list_add_tail(&dent->dent_link, anchor);
		INIT_LIST_HEAD(&dent->brick_list);
	}
done:
	return status;
}
EXPORT_SYMBOL_GPL(mars_recv_dent_list);


int mars_send_mref(struct socket **sock, struct mref_object *mref)
{
	struct mars_cmd cmd = {
		.cmd_code = CMD_MREF,
		.cmd_int1 = mref->ref_id,
	};
	int status;

	status = mars_send_struct(sock, &cmd, mars_cmd_meta);
	if (status < 0)
		goto done;

	status = mars_send_struct(sock, mref, mars_mref_meta);
	if (status < 0)
		goto done;

	if (mref->ref_rw) {
		status = mars_send(sock, mref->ref_data, mref->ref_len);
	}
done:
	return status;
}
EXPORT_SYMBOL_GPL(mars_send_mref);

int mars_recv_mref(struct socket **sock, struct mref_object *mref)
{
	int status;
	status = mars_recv_struct(sock, mref, mars_mref_meta);
	if (status < 0)
		goto done;
	if (mref->ref_rw) {
		if (!mref->ref_data)
			mref->ref_data = kzalloc(mref->ref_len, GFP_MARS);
		if (!mref->ref_data) {
			status = -ENOMEM;
			goto done;
		}
		status = mars_recv(sock, mref->ref_data, mref->ref_len, mref->ref_len);
		if (status < 0)
			MARS_ERR("mref_len = %d, status = %d\n", mref->ref_len, status);
	}
done:
	return status;
}
EXPORT_SYMBOL_GPL(mars_recv_mref);

int mars_send_cb(struct socket **sock, struct mref_object *mref)
{
	struct mars_cmd cmd = {
		.cmd_code = CMD_CB,
		.cmd_int1 = mref->ref_id,
	};
	int status;
	status = mars_send_struct(sock, &cmd, mars_cmd_meta);
	if (status < 0)
		goto done;
	status = mars_send_struct(sock, mref, mars_mref_meta);
	if (status < 0)
		goto done;
	if (!mref->ref_rw) {
		MARS_IO("sending blocklen = %d\n", mref->ref_len);
		status = mars_send(sock, mref->ref_data, mref->ref_len);
	}
done:
	return status;
}
EXPORT_SYMBOL_GPL(mars_send_cb);

int mars_recv_cb(struct socket **sock, struct mref_object *mref)
{
	int status;
	status = mars_recv_struct(sock, mref, mars_mref_meta);
	if (status < 0)
		goto done;
	if (!mref->ref_rw) {
		if (!mref->ref_data) {
			MARS_ERR("no internal buffer available\n");
			status = -EINVAL;
			goto done;
		}
		MARS_IO("receiving blocklen = %d\n", mref->ref_len);
		status = mars_recv(sock, mref->ref_data, mref->ref_len, mref->ref_len);
	}
done:
	return status;
}
EXPORT_SYMBOL_GPL(mars_recv_cb);

////////////////// module init stuff /////////////////////////

static int __init _init_net(void)
{
	MARS_INF("init_net()\n");
	return 0;
}

static void __exit _exit_net(void)
{
	MARS_INF("exit_net()\n");
}

MODULE_DESCRIPTION("MARS network infrastructure");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(_init_net);
module_exit(_exit_net);
