// (c) 2011 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_NET_H
#define MARS_NET_H

#include <net/sock.h>
#include <net/ipconfig.h>
#include <net/tcp.h>

#include "brick.h"

#define MARS_DEFAULT_PORT 7777

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
	CMD_STATUS,
	CMD_GETINFO,
	CMD_GETENTS,
	CMD_CONNECT,
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

/* Low-level network traffic
 */
extern int mars_create_sockaddr(struct sockaddr_storage *addr, const char *spec);
extern int mars_create_socket(struct socket **sock, struct sockaddr_storage *addr, bool is_server);
extern int mars_send(struct socket **sock, void *buf, int len);
extern int mars_recv(struct socket **sock, void *buf, int minlen, int maxlen);

/* Mid-level generic field data exchange
 */
extern int mars_send_struct(struct socket **sock, void *data, const struct meta *meta);
extern int mars_recv_struct(struct socket **sock, void *data, const struct meta *meta);

/* High-level transport of mars structures
 */
extern int mars_send_dent_list(struct socket **sock, struct list_head *anchor);
extern int mars_recv_dent_list(struct socket **sock, struct list_head *anchor);

extern int mars_send_mref(struct socket **sock, struct mref_object *mref);
extern int mars_recv_mref(struct socket **sock, struct mref_object *mref);
extern int mars_send_cb(struct socket **sock, struct mref_object *mref);
extern int mars_recv_cb(struct socket **sock, struct mref_object *mref);


#endif
