// (c) 2011 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_NET_H
#define MARS_NET_H

#include <net/sock.h>
#include <net/ipconfig.h>
#include <net/tcp.h>

#include "brick.h"

#define MARS_DEFAULT_PORT 7777

/* The original struct socket has no refcount. This leads to problems
 * during long-lasting system calls when racing with socket shutdown.
 * This is just a small wrapper adding a refcount and some debugging aid.
 */
struct mars_socket {
	struct socket *s_socket;
	atomic_t s_count;
	int s_debug_nr;
	bool s_dead;
};

struct mars_tcp_params {
	int tcp_timeout;
	int window_size;
	int tcp_keepcnt;
	int tcp_keepintvl;
	int tcp_keepidle;
	char tos;
};

extern struct mars_tcp_params default_tcp_params;

enum {
	CMD_NOP,
	CMD_NOTIFY,
	CMD_CONNECT,
	CMD_GETINFO,
	CMD_GETENTS,
	CMD_MREF,
	CMD_CB,
};

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

extern int mars_create_socket(struct mars_socket *msock, struct sockaddr_storage *addr, bool is_server);
extern int mars_accept_socket(struct mars_socket *new_msock, struct mars_socket *old_msock, bool do_block);
extern bool mars_get_socket(struct mars_socket *msock);
extern void mars_put_socket(struct mars_socket *msock);
extern void mars_shutdown_socket(struct mars_socket *msock);
extern bool mars_socket_is_alive(struct mars_socket *msock);

extern int mars_send_raw(struct mars_socket *msock, void *buf, int len, bool cork);
extern int mars_recv_raw(struct mars_socket *msock, void *buf, int minlen, int maxlen);

/* Mid-level generic field data exchange
 */
extern int mars_send_struct(struct mars_socket *msock, void *data, const struct meta *meta);
#define mars_recv_struct(_sock_,_data_,_meta_)				\
	({								\
		int seq = 0;						\
		_mars_recv_struct(_sock_, _data_, _meta_, &seq, __LINE__); \
	})
extern int _mars_recv_struct(struct mars_socket *msock, void *data, const struct meta *meta, int *seq, int line);

/* High-level transport of mars structures
 */
extern int mars_send_dent_list(struct mars_socket *msock, struct list_head *anchor);
extern int mars_recv_dent_list(struct mars_socket *msock, struct list_head *anchor);

extern int mars_send_mref(struct mars_socket *msock, struct mref_object *mref);
extern int mars_recv_mref(struct mars_socket *msock, struct mref_object *mref);
extern int mars_send_cb(struct mars_socket *msock, struct mref_object *mref);
extern int mars_recv_cb(struct mars_socket *msock, struct mref_object *mref);

/////////////////////////////////////////////////////////////////////////

// init

extern int init_mars_net(void);
extern void exit_mars_net(void);


#endif
