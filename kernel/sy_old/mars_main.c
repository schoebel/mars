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
#define MARS_DEBUGGING
//#define IO_DEBUGGING

/* This MUST be updated whenever INCOMPATIBLE changes are made to the
 * symlink tree in /mars/ .
 *
 * Just adding a new symlink is usually not "incompatible", if
 * other tools like marsadm just ignore it.
 *
 * "incompatible" means that something may BREAK.
 */
#define SYMLINK_TREE_VERSION "0.1"

// disable this only for debugging!
#define RUN_PEERS
#define RUN_DATA
#define RUN_LOGINIT
#define RUN_PRIMARY
#define RUN_SYNCSTATUS
#define RUN_LOGFILES
#define RUN_REPLAY
#define RUN_DEVICE

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include <linux/major.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>

#include "strategy.h"
#include "../buildtag.h"

#include <linux/wait.h>

#include "../lib_mapfree.h"

// used brick types
#include "../mars_server.h"
#include "../mars_client.h"
#include "../mars_copy.h"
#include "../mars_bio.h"
#include "../mars_sio.h"
#include "../mars_aio.h"
#include "../mars_trans_logger.h"
#include "../mars_if.h"
#include "mars_proc.h"
#ifdef CONFIG_MARS_DEBUG // otherwise currently unused
#include "../mars_dummy.h"
#include "../mars_check.h"
#include "../mars_buf.h"
#include "../mars_usebuf.h"
#endif

int usable_features_version = 0;
int usable_strategy_version = 0;

__u32 disabled_log_digests = 0;
__u32 disabled_net_digests = 0;

static int _tmp_features_version = OPTIONAL_FEATURES_VERSION;
static int _tmp_strategy_version = OPTIONAL_STRATEGY_VERSION;

static __u32 _tmp_digest_mask    = MREF_CHKSUM_MD5_OLD;
static __u32 _tmp_compression_mask = MREF_COMPRESS_ANY;

/* Portability: can we use get_random_int() in a module? */
#include <linux/string_helpers.h>
#ifdef UNESCAPE_SPACE /* Commit 16c7fa05829e8b91db48e3539c5d6ff3c2b18a23 */
#define HAS_GET_RANDOM_INT
#endif

#define REPLAY_TOLERANCE (PAGE_SIZE + OVERHEAD)

#if 0
#define inline __attribute__((__noinline__))
#endif

// TODO: add human-readable timestamps
#define MARS_INF_TO(channel, fmt, args...)				\
	({								\
		say_to(channel, SAY_INFO, "%s: " fmt, say_class[SAY_INFO], ##args); \
		MARS_INF(fmt, ##args);					\
	})

#define MARS_WRN_TO(channel, fmt, args...)				\
	({								\
		say_to(channel, SAY_WARN, "%s: " fmt, say_class[SAY_WARN], ##args); \
		MARS_WRN(fmt, ##args);					\
	})

#define MARS_ERR_TO(channel, fmt, args...)				\
	({								\
		say_to(channel, SAY_ERROR, "%s: " fmt, say_class[SAY_ERROR], ##args); \
		MARS_ERR(fmt, ##args);					\
	})

struct lamport_time modprobe_stamp;

loff_t raw_total_space = 0;
loff_t global_total_space = 0;
EXPORT_SYMBOL_GPL(global_total_space);

loff_t raw_remaining_space = 0;
loff_t global_remaining_space = 0;
EXPORT_SYMBOL_GPL(global_remaining_space);


int global_logrot_auto = CONFIG_MARS_LOGROT_AUTO;
EXPORT_SYMBOL_GPL(global_logrot_auto);

int global_free_space_0 = CONFIG_MARS_MIN_SPACE_0;
EXPORT_SYMBOL_GPL(global_free_space_0);

int global_free_space_1 = CONFIG_MARS_MIN_SPACE_1;
EXPORT_SYMBOL_GPL(global_free_space_1);

int global_free_space_2 = CONFIG_MARS_MIN_SPACE_2;
EXPORT_SYMBOL_GPL(global_free_space_2);

int global_free_space_3 = CONFIG_MARS_MIN_SPACE_3;
EXPORT_SYMBOL_GPL(global_free_space_3);

int global_free_space_4 = CONFIG_MARS_MIN_SPACE_4;
EXPORT_SYMBOL_GPL(global_free_space_4);

int _global_sync_nr;
int global_sync_nr = 0;
EXPORT_SYMBOL_GPL(global_sync_nr);

int global_sync_limit = 0;
EXPORT_SYMBOL_GPL(global_sync_limit);

int mars_rollover_interval = CONFIG_MARS_ROLLOVER_INTERVAL;
EXPORT_SYMBOL_GPL(mars_rollover_interval);

int mars_scan_interval = CONFIG_MARS_SCAN_INTERVAL;
EXPORT_SYMBOL_GPL(mars_scan_interval);

int mars_propagate_interval = CONFIG_MARS_PROPAGATE_INTERVAL;
EXPORT_SYMBOL_GPL(mars_propagate_interval);

int mars_sync_flip_interval = CONFIG_MARS_SYNC_FLIP_INTERVAL;
EXPORT_SYMBOL_GPL(mars_sync_flip_interval);

int mars_peer_abort = 7;
EXPORT_SYMBOL_GPL(mars_peer_abort);

int mars_running_additional_peers = 0;
int mars_run_additional_peers = 3;

int mars_fast_fullsync =
#ifdef CONFIG_MARS_FAST_FULLSYNC
	1
#else
	0
#endif
	;
EXPORT_SYMBOL_GPL(mars_fast_fullsync);

int mars_throttle_start = 0;

int mars_throttle_end = 90;

int mars_emergency_mode = 0;
EXPORT_SYMBOL_GPL(mars_emergency_mode);

int mars_reset_emergency = 1;
EXPORT_SYMBOL_GPL(mars_reset_emergency);

int mars_keep_msg = 10;
EXPORT_SYMBOL_GPL(mars_keep_msg);

#ifdef CONFIG_MARS_DEBUG
#include <linux/reboot.h>

int mars_crash_mode = 0;
EXPORT_SYMBOL_GPL(mars_crash_mode);
int mars_hang_mode = 0;
EXPORT_SYMBOL_GPL(mars_hang_mode);

void _crashme(int mode, bool do_sync)
{
	if (mode == mars_crash_mode) {
		if (do_sync)
			mars_sync();
		emergency_restart();
	}
}

#endif

#define GLOBAL_PATH_LIST			\
  "/mars"					\
  "|/mars/ips/"					\
  "|/mars/todo-global/"				\
  "|/mars/defaults/"				\
  "|/mars/userspace/"

static DECLARE_RWSEM(mars_resource_sem);
static const char *mars_resource_list;
static const char *tmp_resource_list;

#define MARS_SYMLINK_MAX 1023

struct key_value_pair {
        const char *key;
        char *val;
        char *old_val;
	unsigned long last_jiffies;
	struct lamport_time system_stamp;
	struct lamport_time lamport_stamp;
};

static inline
void clear_vals(struct key_value_pair *start)
{
	while (start->key) {
		brick_string_free(start->val);
		start->val = NULL;
		brick_string_free(start->old_val);
		start->old_val = NULL;
		start++;
	}
}

static
void show_vals(struct key_value_pair *start, const char *path, const char *add)
{
	while (start->key) {
		char *dst = path_make("%s/actual-%s/msg-%s%s", path, my_id(), add, start->key);
		// show the old message for some keep_time if no new one is available
		if (!start->val && start->old_val &&
		    (long long)start->last_jiffies  + mars_keep_msg * HZ <= (long long)jiffies) {
			start->val = start->old_val;
			start->old_val = NULL;
		}
		if (start->val) {
			char *src = path_make("%ld.%09ld %ld.%09ld %s",
					      start->system_stamp.tv_sec, start->system_stamp.tv_nsec, 
					      start->lamport_stamp.tv_sec, start->lamport_stamp.tv_nsec, 
					      start->val);
			ordered_symlink(src, dst, NULL);
			brick_string_free(src);
			brick_string_free(start->old_val);
			start->old_val = start->val;
			start->val = NULL;
		} else {
			ordered_symlink("OK", dst, NULL);
			memset(&start->system_stamp, 0, sizeof(start->system_stamp));
			memset(&start->lamport_stamp, 0, sizeof(start->lamport_stamp));
			brick_string_free(start->old_val);
			start->old_val = NULL;
		}
		brick_string_free(dst);
		start++;
	}
}

static inline
void assign_keys(struct key_value_pair *start, const char **keys)
{
	while (*keys) {
		start->key = *keys;
		start++;
		keys++;
	}
}

static inline
struct key_value_pair *find_key(struct key_value_pair *start, const char *key)
{
	while (start->key) {
		if (!strcmp(start->key, key)) {
			return start;
		}
		start++;
	}
	MARS_ERR("cannot find key '%s'\n", key);
	return NULL;
}

static
void _make_msg(int line, struct key_value_pair *pair, const char *fmt, ...)  __attribute__ ((format (printf, 3, 4)));

static
void _make_msg(int line, struct key_value_pair *pair, const char *fmt, ...)
{
	int len;
	va_list args;

	if (unlikely(!pair || !pair->key)) {
		MARS_ERR("bad pointer %p at line %d\n", pair, line);
		return;
	}
	pair->last_jiffies = jiffies;
	if (!pair->val) {
		pair->val = brick_string_alloc(MARS_SYMLINK_MAX + 1);
		len = 0;
		if (!pair->system_stamp.tv_sec) {
			get_lamport(&pair->system_stamp, &pair->lamport_stamp);
		}
	} else {
		len = strnlen(pair->val, MARS_SYMLINK_MAX);
		if (unlikely(len >= MARS_SYMLINK_MAX - 48))
			return;
		pair->val[len++] = ',';
	}

	va_start(args, fmt);
	vsnprintf(pair->val + len, MARS_SYMLINK_MAX - 1 - len, fmt, args);
	va_end(args);
}

#define make_msg(pair, fmt, args...)			\
	_make_msg(__LINE__, pair, fmt, ##args)

static
struct key_value_pair gbl_pairs[] = {
	{ NULL }
};

#define make_gbl_msg(key, fmt, args...)			\
	make_msg(find_key(gbl_pairs, key), fmt, ##args)

static
const char *rot_keys[] = {
	// from _update_version_link()
	"err-versionlink-skip",
	// from _update_info()
	"err-sequence-trash",
	// from _is_switchover_possible()
	"inf-log-foreign-denied",
	"inf-versionlink-not-yet-exist",
	"inf-versionlink-not-equal",
	"inf-replay-not-yet-finished",
	"err-bad-log-name",
	"err-log-not-contiguous",
	"err-versionlink-not-readable",
	"err-replaylink-not-readable",
	"err-splitbrain-detected",
	// from _update_file()
	"inf-fetch",
	// from make_sync()
	"inf-sync",
	// from make_log_step()
	"wrn-log-consecutive",
	// from make_log_finalize()
	"inf-replay-start",
	"wrn-space-low",
	"err-space-low",
	"err-emergency",
	"err-replay-stop",
	// from _check_logging_status()
	"inf-replay-tolerance",
	NULL,
};

#define make_rot_msg(rot, key, fmt, args...)			\
	make_msg(find_key(&(rot)->msgs[0], key), fmt, ##args)


#define IS_EXHAUSTED()             (mars_emergency_mode > 0)
#define IS_EMERGENCY_SECONDARY()   (mars_emergency_mode > 1)
#define IS_EMERGENCY_PRIMARY()     (mars_emergency_mode > 2)
#define IS_JAMMED()                (mars_emergency_mode > 3)

static
void __make_alivelink_str(const char *name, const char *src, bool lazy)
{
	char *dst = path_make("/mars/%s-%s", name, my_id());
	if (!src || !dst) {
		MARS_ERR("cannot make alivelink paths\n");
		goto err;
	}
	if (lazy) {
		char *check = mars_readlink(dst);
		bool ok = (check && !strcmp(check, src));

		brick_string_free(check);
		if (ok) {
			MARS_DBG("symlink '%s' -> '%s' has not changed\n", src, dst);
			goto err;
		}
	}
	MARS_DBG("'%s' -> '%s'\n", src, dst);
	ordered_symlink(src, dst, NULL);
err:
	brick_string_free(dst);
}
#define _make_alivelink_str(name,src)		\
	__make_alivelink_str(name,src,false)

static
void __make_alivelink(const char *name, loff_t val, bool lazy)
{
	char *src = path_make("%lld", val);
	__make_alivelink_str(name, src, lazy);
	brick_string_free(src);
}
#define _make_alivelink(name,val)		\
	__make_alivelink(name,val,false)

static
int compute_emergency_mode(void)
{
	loff_t rest;
	loff_t present;
	loff_t limit = 0;
	int mode = 4;
	int this_mode = 0;

	mars_remaining_space("/mars", &raw_total_space, &rest);

	/* Take current writeback memory usage into account.
	 * Somewhen, it will land on the disk...
	 */
	rest -= atomic64_read(&global_mshadow_used) / 1024;
	if (rest < 0)
		rest = 0;

	raw_remaining_space = rest;

#define CHECK_LIMIT(LIMIT_VAR)					\
	if (LIMIT_VAR > 0)					\
		limit += (loff_t)LIMIT_VAR * 1024 * 1024;	\
	if (rest < limit && !this_mode) {			\
		this_mode = mode;				\
	}							\
	mode--;							\

	CHECK_LIMIT(global_free_space_4);
	CHECK_LIMIT(global_free_space_3);
	CHECK_LIMIT(global_free_space_2);
	CHECK_LIMIT(global_free_space_1);

	/* Decrease the emergeny mode only in single steps.
	 */
	if (mars_reset_emergency && mars_emergency_mode > 0 && mars_emergency_mode > this_mode) {
		mars_emergency_mode--;
	} else {
		mars_emergency_mode = this_mode;
	}

	__make_alivelink("emergency", mars_emergency_mode, true);

	rest -= limit;
	if (rest < 0)
		rest = 0;
	global_remaining_space = rest;
	__make_alivelink("rest-space", rest / (1024 * 1024), true);

	present = raw_total_space - limit;
	global_total_space = present;

	if (mars_throttle_start > 0 &&
	    mars_throttle_end > mars_throttle_start &&
	    present > 0) {
		loff_t percent_used = 100 - (rest * 100 / present);
		if (percent_used < mars_throttle_start) {
			if_throttle_start_size = 0;
		} else if (percent_used >= mars_throttle_end) {
			if_throttle_start_size = 1;
		} else {
			if_throttle_start_size = (mars_throttle_end - percent_used) * 1024 / (mars_throttle_end - mars_throttle_start) + 1;
		}
	}

	if (unlikely(present < global_free_space_0)) {
		return -ENOSPC;
	}
	return 0;
}

static
struct mars_brick *_kill_brick(struct mars_brick* brick)
{
	int status;
	int i;

	MARS_DBG("brick '%s' forceful shutdown\n", brick->brick_path);

	/* any predecessors should timeout ASAP */
	for (i = 0; i < brick->nr_inputs; i++)
		if (brick->inputs[i] && brick->inputs[i]->brick)
			brick->inputs[i]->brick->power.io_timeout = 1;

	/* first switch off (in parallel to other ones) before waiting */
	if (!brick->power.led_off) {
		MARS_DBG("brick '%s' needs switching off\n", brick->brick_path);
		mars_power_button(brick, false, true);
		return brick;
	}
	status = mars_kill_brick((void *)brick);
	if (status < 0) {
		MARS_ERR("could not kill brick, status = %d\n", status);
	} else {
		brick = NULL;
	}
	mars_trigger();
	return brick;
}

///////////////////////////////////////////////////////////////////

static struct task_struct *main_thread = NULL;

typedef int (*main_worker_fn)(void *buf, struct mars_dent *dent);

struct main_class {
	char *cl_name;
	int    cl_len;
	char   cl_type;
	bool   cl_hostcontext;
	bool   cl_serial;
	bool   cl_use_channel;
	int    cl_father;
	main_worker_fn cl_prepare;
	main_worker_fn cl_forward;
	main_worker_fn cl_backward;
};

// the order is important!
enum {
	// root element: this must have index 0
	CL_ROOT,
	// global ID
	CL_UUID,
	// global userspace
	CL_GLOBAL_USERSPACE,
	CL_GLOBAL_USERSPACE_ITEMS,
	// global todos
	CL_GLOBAL_TODO,
	CL_GLOBAL_TODO_DELETE,
	CL_GLOBAL_TODO_DELETED,
	CL_DEFAULTS0,
	CL_DEFAULTS,
	CL_DEFAULTS_ITEMS0,
	CL_DEFAULTS_ITEMS,
	// replacement for DNS in kernelspace
	CL_IPS,
	CL_PEERS,
	CL_GBL_ACTUAL,
	CL_GBL_ACTUAL_ITEMS,
	CL_TREE,
	CL_FEATURES,
	CL_USABLE,
	CL_COMPAT_DELETIONS, /* transient, to re-disappear */
	CL_EMERGENCY,
	CL_REST_SPACE,
	// resource definitions
	CL_RESOURCE,
	CL_RESOURCE_USERSPACE,
	CL_RESOURCE_USERSPACE_ITEMS,
	CL_RES_DEFAULTS0,
	CL_RES_DEFAULTS,
	CL_RES_DEFAULTS_ITEMS0,
	CL_RES_DEFAULTS_ITEMS,
	CL_TODO,
	CL_TODO_ITEMS,
	CL_ACTUAL,
	CL_ACTUAL_ITEMS,
	CL_DATA,
	CL_WORK,
	CL_SIZE,
	CL_ACTSIZE,
	CL_PRIMARY,
	CL_SYSTEMD_CATCHALL,
	CL__FILE,
	CL_CONNECT,
	CL_TRANSFER,
	CL_SYNC,
	CL_VERIF,
	CL_SYNCPOS,
	CL__COPY,
	CL__DIRECT,
	CL_VERSION,
	CL_LOG,
	CL_REPLAYSTATUS,
	CL_DEVICE,
	CL_MAXNR,
	/* these must come last for race avoidance */
	CL_ALIVE,
	CL_TIME,
};

///////////////////////////////////////////////////////////////////////

// needed for logfile rotation

#define INFS_MAX (TL_INPUT_LOG2 - TL_INPUT_LOG1 + 1)

struct mars_rotate {
	struct list_head rot_head;
	struct mars_global *global;
	struct copy_brick *sync_brick;
	struct mars_dent *replay_link;
	struct mars_brick *bio_brick;
	struct mars_dent *aio_dent;
	struct aio_brick *aio_brick;
	struct mars_info aio_info;
	struct trans_logger_brick *trans_brick;
	struct mars_dent *first_log;
	struct mars_dent *last_log;
	struct mars_dent *relevant_log;
	struct mars_brick *relevant_brick;
	struct mars_dent *next_relevant_log;
	struct mars_brick *next_relevant_brick;
	struct mars_dent *prev_log;
	struct mars_dent *next_log;
	struct mars_dent *syncstatus_dent;
	struct lamport_time sync_finish_stamp;
	struct if_brick *if_brick;
	const char *fetch_path;
	const char *fetch_peer;
	const char *avoid_peer;
	const char *preferred_peer;
	const char *parent_path;
	const char *parent_rest;
	const char *fetch_next_origin;
	struct say_channel *log_say;
	struct copy_brick *fetch_brick;
	struct mars_limiter replay_limiter;
	struct mars_limiter sync_limiter;
	struct mars_limiter fetch_limiter;
	int inf_prev_sequence;
	int inf_old_sequence;
	long long flip_start;
	loff_t flip_pos;
	loff_t dev_size;
	loff_t start_pos;
	loff_t end_pos;
	int retry_recovery;
	int max_sequence;
	int fetch_round;
	int fetch_serial;
	int fetch_next_serial;
	int repair_log_seq;
	int split_brain_serial;
	int split_brain_round;
	int fetch_next_is_available;
	int relevant_serial;
	int replay_code;
	int avoid_count;
	int old_open_count;
	bool has_symlinks;
	bool is_attached;
	bool res_shutdown;
	bool has_error;
	bool has_double_logfile;
	bool has_hole_logfile;
	bool allow_update;
	bool rot_activated;
	bool forbid_replay;
	bool replay_mode;
	bool todo_primary;
	bool checked_reboot;
	bool is_primary;
	bool old_is_primary;
	bool created_hole;
	bool is_log_damaged;
	bool has_emergency;
	bool log_is_really_damaged;
	struct mutex inf_mutex;
	bool infs_is_dirty[INFS_MAX];
	struct trans_logger_info infs[INFS_MAX];
	struct trans_logger_info current_inf;
	struct key_value_pair msgs[sizeof(rot_keys) / sizeof(char*)];
};

static struct rw_semaphore rot_sem = __RWSEM_INITIALIZER(rot_sem);
static LIST_HEAD(rot_anchor);

///////////////////////////////////////////////////////////////////////

// TUNING

int mars_mem_percent = 20;
int mars_mem_gb = 16;

#define CONF_TRANS_SHADOW_LIMIT (1024 * 128) // don't fill the hashtable too much

//#define TRANS_FAKE

#define CONF_TRANS_BATCHLEN 64
#define CONF_TRANS_PRIO   MARS_PRIO_HIGH
#define CONF_TRANS_LOG_READS false
//#define CONF_TRANS_LOG_READS true

#define CONF_ALL_BATCHLEN 1
#define CONF_ALL_PRIO   MARS_PRIO_NORMAL

#define IF_SKIP_SYNC true

#define IF_MAX_PLUGGED 10000
#define IF_READAHEAD 0
//#define IF_READAHEAD 1

#define BIO_READAHEAD 0
//#define BIO_READAHEAD 1
#define BIO_SYNC true
#define BIO_UNPLUG true

#define COPY_APPEND_MODE 0
//#define COPY_APPEND_MODE 1 // FIXME: does not work yet
#define COPY_PRIO MARS_PRIO_LOW

static
int _set_trans_params(struct mars_brick *_brick, void *private)
{
	struct trans_logger_brick *trans_brick = (void*)_brick;
	if (_brick->type != (void*)&trans_logger_brick_type) {
		MARS_ERR("bad brick type\n");
		return -EINVAL;
	}
	if (!trans_brick->q_phase[1].q_ordering) {
		trans_brick->q_phase[0].q_batchlen = CONF_TRANS_BATCHLEN;
		trans_brick->q_phase[1].q_batchlen = CONF_ALL_BATCHLEN;
		trans_brick->q_phase[2].q_batchlen = CONF_ALL_BATCHLEN;
		trans_brick->q_phase[3].q_batchlen = CONF_ALL_BATCHLEN;

		trans_brick->q_phase[0].q_io_prio = CONF_TRANS_PRIO;
		trans_brick->q_phase[1].q_io_prio = CONF_ALL_PRIO;
		trans_brick->q_phase[2].q_io_prio = CONF_ALL_PRIO;
		trans_brick->q_phase[3].q_io_prio = CONF_ALL_PRIO;

		trans_brick->q_phase[1].q_ordering = true;
		trans_brick->q_phase[3].q_ordering = true;

		trans_brick->shadow_mem_limit = CONF_TRANS_SHADOW_LIMIT;
		trans_brick->log_reads = CONF_TRANS_LOG_READS;

#ifdef TRANS_FAKE
		trans_brick->debug_shortcut = true;
#endif

	}
	MARS_INF("name = '%s' path = '%s'\n", _brick->brick_name, _brick->brick_path);
	return 1;
}

struct client_cookie {
	bool limit_mode;
	bool create_mode;
};

static
int _set_client_params(struct mars_brick *_brick, void *private)
{
	struct client_brick *client_brick = (void*)_brick;
	struct client_cookie *clc = private;
	client_brick->limit_mode = clc ? clc->limit_mode : false;
	client_brick->killme = true;
	MARS_INF("name = '%s' path = '%s'\n", _brick->brick_name, _brick->brick_path);
	return 1;
}

static
int _set_sio_params(struct mars_brick *_brick, void *private)
{
	struct sio_brick *sio_brick = (void*)_brick;
	if (_brick->type == (void*)&client_brick_type) {
		return _set_client_params(_brick, private);
	}
	if (_brick->type != (void*)&sio_brick_type) {
		MARS_ERR("bad brick type\n");
		return -EINVAL;
	}
	sio_brick->o_direct = false; // important!
	sio_brick->o_fdsync = true;
	sio_brick->killme = true;
	MARS_INF("name = '%s' path = '%s'\n", _brick->brick_name, _brick->brick_path);
	return 1;
}

static
int _set_aio_params(struct mars_brick *_brick, void *private)
{
	struct aio_brick *aio_brick = (void*)_brick;
	struct client_cookie *clc = private;
	if (_brick->type == (void*)&client_brick_type) {
		return _set_client_params(_brick, private);
	}
	if (_brick->type == (void*)&sio_brick_type) {
		return _set_sio_params(_brick, private);
	}
	if (_brick->type != (void*)&aio_brick_type) {
		MARS_ERR("bad brick type\n");
		return -EINVAL;
	}
	aio_brick->o_creat = clc && clc->create_mode;
	aio_brick->o_direct = false; // important!
	aio_brick->o_fdsync = true;
	aio_brick->killme = true;
	MARS_INF("name = '%s' path = '%s'\n", _brick->brick_name, _brick->brick_path);
	return 1;
}

static
int _set_bio_params(struct mars_brick *_brick, void *private)
{
	struct bio_brick *bio_brick;
	if (_brick->type == (void*)&client_brick_type) {
		return _set_client_params(_brick, private);
	}
	if (_brick->type == (void*)&aio_brick_type) {
		return _set_aio_params(_brick, private);
	}
	if (_brick->type == (void*)&sio_brick_type) {
		return _set_sio_params(_brick, private);
	}
	if (_brick->type != (void*)&bio_brick_type) {
		MARS_ERR("bad brick type\n");
		return -EINVAL;
	}
	bio_brick = (void*)_brick;
	bio_brick->ra_pages = BIO_READAHEAD;
	bio_brick->do_sync = BIO_SYNC;
	bio_brick->do_unplug = BIO_UNPLUG;
	bio_brick->killme = true;
	MARS_INF("name = '%s' path = '%s'\n", _brick->brick_name, _brick->brick_path);
	return 1;
}

static
int _set_if_params(struct mars_brick *_brick, void *private)
{
	struct if_brick *if_brick = (void*)_brick;
	struct mars_rotate *rot = private;
	if (_brick->type != (void*)&if_brick_type) {
		MARS_ERR("bad brick type\n");
		return -EINVAL;
	}
	if (!rot) {
		MARS_ERR("too early\n");
		return -EINVAL;
	}
	if (rot->dev_size <= 0) {
		MARS_ERR("dev_size = %lld\n", rot->dev_size);
		return -EINVAL;
	}
	if (if_brick->dev_size > 0 && rot->dev_size < if_brick->dev_size) {
		MARS_ERR("new dev size = %lld < old dev_size = %lld\n", rot->dev_size, if_brick->dev_size);
		return -EINVAL;
	}
	if_brick->dev_size = rot->dev_size;
	if_brick->max_plugged = IF_MAX_PLUGGED;
	if_brick->readahead = IF_READAHEAD;
	if_brick->skip_sync = IF_SKIP_SYNC;
	MARS_INF("name = '%s' path = '%s' size = %lld\n", _brick->brick_name, _brick->brick_path, if_brick->dev_size);
	return 1;
}

struct copy_cookie {
	const char *argv[2];
	const char *copy_path;
	loff_t start_pos;
	loff_t end_pos;
	bool keep_running;
	bool verify_mode;

 	const char *fullpath[2];
	struct mars_output *output[2];
	struct mars_info info[2];
};

static
int _set_copy_params(struct mars_brick *_brick, void *private)
{
	struct copy_brick *copy_brick = (void*)_brick;
	struct copy_cookie *cc = private;
	int status = 1;

	if (_brick->type != (void*)&copy_brick_type) {
		MARS_ERR("bad brick type\n");
		status = -EINVAL;
		goto done;
	}
	copy_brick->append_mode = COPY_APPEND_MODE;
	copy_brick->io_prio = COPY_PRIO;
	copy_brick->verify_mode = cc->verify_mode;
	copy_brick->repair_mode = true;
	copy_brick->killme = true;
	MARS_INF("name = '%s' path = '%s'\n", _brick->brick_name, _brick->brick_path);

	/* Determine the copy area, switch on/off when necessary
	 */
	if (!copy_brick->power.button && copy_brick->power.led_off) {
		int i;

		for (i = 0; i < 2; i++) {
			struct mars_output *aio_output = cc->output[i];
			struct mars_brick *aio_brick;

			if (unlikely(!aio_output)) {
				MARS_WRN("'%s' uninitialized output %d\n",
					 _brick->brick_path, i);
				goto done;
			}
			aio_brick = aio_output->brick;
			if (unlikely(!aio_brick)) {
				MARS_WRN("'%s' uninitialized brick %d\n",
					 _brick->brick_path, i);
				goto done;
			}
			if (!aio_brick->power.led_on) {
				MARS_INF("'%s' brick %d not working\n",
					 _brick->brick_path, i);
				goto done;
			}
			status = aio_output->ops->mars_get_info(
					    aio_output,
					    &cc->info[i]);
			if (status < 0) {
				MARS_WRN("cannot determine current size of '%s'\n", cc->argv[i]);
				goto done;
			}
			MARS_DBG("%d '%s' current_size = %lld\n", i, cc->fullpath[i], cc->info[i].current_size);
		}
		copy_brick->copy_start = cc->info[1].current_size;
		copy_brick->copy_last = copy_brick->copy_start;
		if (cc->start_pos != -1) {
			copy_brick->copy_start = cc->start_pos;
			copy_brick->copy_last = copy_brick->copy_start;
			if (unlikely(cc->start_pos > cc->info[0].current_size)) {
				MARS_ERR("bad start position %lld is larger than actual size %lld on '%s'\n", cc->start_pos, cc->info[0].current_size, cc->copy_path);
				status = -EINVAL;
				goto done;
			}
		}
		MARS_DBG("copy_start = %lld\n", copy_brick->copy_start);
		copy_brick->copy_end = cc->info[0].current_size;
		if (cc->end_pos != -1) {
			if (unlikely(cc->end_pos > copy_brick->copy_end)) {
				MARS_ERR("target size %lld is larger than actual size %lld on source\n", cc->end_pos, copy_brick->copy_end);
				status = -EINVAL;
				goto done;
			}
			copy_brick->copy_end = cc->end_pos;
			if (unlikely(cc->end_pos > cc->info[1].current_size)) {
				MARS_ERR("bad end position %lld is larger than actual size %lld on target\n", cc->end_pos, cc->info[1].current_size);
				status = -EINVAL;
				goto done;
			}
		}
		MARS_DBG("copy_end = %lld\n", copy_brick->copy_end);
		if (copy_brick->copy_start < copy_brick->copy_end) {
			status = 1;
			MARS_DBG("copy switch on\n");
		}
	} else if (copy_brick->power.button && copy_brick->power.led_on &&
		   !cc->keep_running &&
		   copy_brick->copy_last == copy_brick->copy_end && copy_brick->copy_end > 0) {
		status = 0;
		MARS_DBG("copy switch off\n");
	}

done:
	return status;
}

///////////////////////////////////////////////////////////////////////

// internal helpers

#define MARS_DELIM ','

static int _parse_args(struct mars_dent *dent, char *str, int count)
{
	int i;
	int status = -EINVAL;
	if (!str)
		goto done;
	if (!dent->d_args) {
		dent->d_args = brick_strdup(str);
		if (!dent->d_args) {
			status = -ENOMEM;
			goto done;
		}
	}
	for (i = 0; i < count; i++) {
		char *tmp;
		int len;
		if (!*str)
			goto done;
		if (i == count-1) {
			len = strlen(str);
		} else {
			char *tmp = strchr(str, MARS_DELIM);
			if (!tmp)
				goto done;
			len = (tmp - str);
		}
		tmp = brick_string_alloc(len + 1);
		if (!tmp) {
			status = -ENOMEM;
			goto done;
		}
		brick_string_free(dent->d_argv[i]);
		dent->d_argv[i] = tmp;
		strncpy(dent->d_argv[i], str, len);
		dent->d_argv[i][len] = '\0';

		str += len;
		if (i != count-1)
			str++;
	}
	status = 0;
done:
	if (status < 0) {
		MARS_ERR("bad syntax '%s' (should have %d args), status = %d\n", dent->d_args ? dent->d_args : "", count, status);
	}
	return status;
}

static
int _check_switch(struct mars_global *global, const char *path)
{
	int res = 0;
	struct mars_dent *allow_dent;

	/* Upon shutdown, treat all switches as "off"
	 */
	if (!global->global_power.button)
		goto done;

	allow_dent = mars_find_dent(global, path);
	if (!allow_dent || !allow_dent->new_link)
		goto done;
	sscanf(allow_dent->new_link, "%d", &res);
	MARS_DBG("'%s' -> %d\n", path, res);

done:
	return res;
}

static
int _check_allow(struct mars_global *global, const char *parent_path, const char *name)
{
	int res = 0;
	char *path = path_make("%s/todo-%s/%s", parent_path, my_id(), name);

	if (!path)
		goto done;

	res = _check_switch(global, path);

done:
	brick_string_free(path);
	return res;
}

#define skip_part(s) _skip_part(s, ',', ':')
#define skip_sect(s) _skip_part(s, ':', 0)
static inline
int _skip_part(const char *str, const char del1, const char del2)
{
	int len = 0;
	while (str[len] && str[len] != del1 && (!del2 || str[len] != del2))
		len++;
	return len;
}

static inline
int skip_dir(const char *str)
{
	int len = 0;
	int res = 0;
	for (len = 0; str[len]; len++)
		if (str[len] == '/')
			res = len + 1;
	return res;
}

static
int parse_logfile_name(const char *str, int *seq, const char **host)
{
	char *_host;
	int count;
	int len = 0;
	int len_host;

	*seq = 0;
	if (host)
		*host = NULL;

	count = sscanf(str, "log-%d-%n", seq, &len);
	if (unlikely(count != 1)) {
		MARS_ERR("bad logfile name '%s', count=%d, len=%d\n", str, count, len);
		return 0;
	} else if (!host) {
		return -1;
	}

	_host = brick_strdup(str + len);
	if (unlikely(!_host)) {
		MARS_ERR("no MEM\n");
		return 0;
	}

	len_host = skip_part(_host);
	_host[len_host] = '\0';
	*host = _host;
	len += len_host;

	return len;
}

static
int compare_replaylinks(struct mars_rotate *rot, const char *hosta, const char *hostb)
{
	const char *linka = path_make("%s/replay-%s", rot->parent_path, hosta);
	const char *linkb = path_make("%s/replay-%s", rot->parent_path, hostb);
	const char *a = NULL;
	const char *b = NULL;
	int seqa;
	int seqb;
	int posa;
	int posb;
	loff_t offa;
	loff_t offb;
	int count;
	int res = -2;

	if (unlikely(!linka || !linkb)) {
		MARS_ERR("nen MEM");
		goto done;
	}

	a = ordered_readlink(linka);
	if (unlikely(!a || !a[0])) {
		MARS_ERR_TO(rot->log_say, "cannot read replaylink '%s'\n", linka);
		goto done;
	}
	b = ordered_readlink(linkb);
	if (unlikely(!b || !b[0])) {
		MARS_ERR_TO(rot->log_say, "cannot read replaylink '%s'\n", linkb);
		goto done;
	}

	count = sscanf(a, "log-%d-%n", &seqa, &posa);
	if (unlikely(count != 1)) {
		MARS_ERR_TO(rot->log_say, "replay link '%s' -> '%s' is malformed\n", linka, a);
	}
	count = sscanf(b, "log-%d-%n", &seqb, &posb);
	if (unlikely(count != 1)) {
		MARS_ERR_TO(rot->log_say, "replay link '%s' -> '%s' is malformed\n", linkb, b);
	}

	if (seqa < seqb) {
		res = -1;
		goto done;
	} else if (seqa > seqb) {
		res = 1;
		goto done;
	}

	posa += skip_part(a + posa);
	posb += skip_part(b + posb);
	if (unlikely(!a[posa++])) {
		MARS_ERR_TO(rot->log_say, "replay link '%s' -> '%s' is malformed\n", linka, a);
	}
	if (unlikely(!b[posb++])) {
		MARS_ERR_TO(rot->log_say, "replay link '%s' -> '%s' is malformed\n", linkb, b);
	}

	count = sscanf(a + posa, "%lld", &offa);
	if (unlikely(count != 1)) {
		MARS_ERR_TO(rot->log_say, "replay link '%s' -> '%s' is malformed\n", linka, a);
	}
	count = sscanf(b + posb, "%lld", &offb);
	if (unlikely(count != 1)) {
		MARS_ERR_TO(rot->log_say, "replay link '%s' -> '%s' is malformed\n", linkb, b);
	}

	if (offa < offb) {
		res = -1;
	} else if (offa > offb) {
		res = 1;
	} else {
		res = 0;
	}

 done:
	brick_string_free(a);
	brick_string_free(b);
	brick_string_free(linka);
	brick_string_free(linkb);
	return res;
}

///////////////////////////////////////////////////////////////////////

// status display

static
int _update_link_when_necessary(struct mars_rotate *rot, const char *type, const char *old, const char *new)
{
	char *check = NULL;
	int status = -EINVAL;
	bool res = false;

	if (unlikely(!old || !new))
		goto out;
	
	/* Check whether something really has changed (avoid
	 * useless/disturbing timestamp updates)
	 */
	check = ordered_readlink(new);
	if (check && !strcmp(check, old)) {
		MARS_DBG("%s symlink '%s' -> '%s' has not changed\n", type, old, new);
		res = 0;
		goto out;
	}

	status = ordered_symlink(old, new, NULL);
	if (unlikely(status < 0)) {
		MARS_ERR_TO(rot->log_say, "cannot create %s symlink '%s' -> '%s' status = %d\n", type, old, new, status);
	} else {
		res = 1;
		MARS_DBG("made %s symlink '%s' -> '%s' status = %d\n", type, old, new, status);
	}

out:
	brick_string_free(check);
	return res;
}

static
int _update_replay_link(struct mars_rotate *rot, struct trans_logger_info *inf)
{
	char *old = NULL;
	char *new = NULL;
	int res = 0;

	old = path_make("log-%09d-%s,%lld,%lld", inf->inf_sequence, inf->inf_host, inf->inf_min_pos, inf->inf_max_pos - inf->inf_min_pos);
	if (!old) {
		goto out;
	}
	new = path_make("%s/replay-%s", rot->parent_path, my_id());
	if (!new) {
		goto out;
	}

	_crashme(1, true);

	res = _update_link_when_necessary(rot, "replay", old, new);

out:
	brick_string_free(new);
	brick_string_free(old);
	return res;
}

static
int _update_version_link(struct mars_rotate *rot,
			 struct trans_logger_info *inf,
			 bool do_check)
{
	char *data = brick_string_alloc(0);
	char *old = brick_string_alloc(0);
	char *new = NULL;
	unsigned char *digest = brick_string_alloc(0);
	char *prev = NULL;
	char *prev_link = NULL;
	char *prev_digest = NULL;
	int len;
	int i;
	int res = 0;

	if (unlikely(!data || !digest || !old)) {
		MARS_ERR("no MEM\n");
		goto out;
	}

	if (likely(inf->inf_sequence > 1)) {
		if (unlikely((inf->inf_sequence < rot->inf_prev_sequence ||
			      inf->inf_sequence > rot->inf_prev_sequence + 1) &&
			     rot->inf_prev_sequence != 0 &&
			     do_check)) {
			char *skip_path = path_make("%s/skip-check-%s", rot->parent_path, my_id());
			char *skip_link = ordered_readlink(skip_path);
			char *msg = "";
			int skip_nr = -1;
			int nr_char = 0;

			if (likely(skip_link && skip_link[0])) {
				(void)sscanf(skip_link, "%d%n", &skip_nr, &nr_char);
				msg = skip_link + nr_char;
			}
			brick_string_free(skip_path);
			if (likely(skip_nr != inf->inf_sequence)) {
				MARS_ERR_TO(rot->log_say, "SKIP in sequence numbers detected: %d != %d + 1\n", inf->inf_sequence, rot->inf_prev_sequence);
				make_rot_msg(rot, "err-versionlink-skip", "SKIP in sequence numbers detected: %d != %d + 1", inf->inf_sequence, rot->inf_prev_sequence);
				brick_string_free(skip_link);
				goto out;
			}
			MARS_WRN_TO(rot->log_say,
				    "you explicitly requested to SKIP sequence numbers from %d to %d%s\n",
				    rot->inf_prev_sequence, inf->inf_sequence, msg);
			brick_string_free(skip_link);
		}
		prev = path_make("%s/version-%09d-%s", rot->parent_path, inf->inf_sequence - 1, my_id());
		if (unlikely(!prev)) {
			MARS_ERR("no MEM\n");
			goto out;
		}
		prev_link = ordered_readlink(prev);
		rot->inf_prev_sequence = inf->inf_sequence;
	}

	len = sprintf(data, "%d,%s,%lld:%s", inf->inf_sequence, inf->inf_host, inf->inf_log_pos, prev_link ? prev_link : "");
	
	MARS_DBG("data = '%s' len = %d\n", data, len);

	mars_digest(MREF_CHKSUM_MD5_OLD,
		    NULL,
		    digest,
		    data, len);

	len = 0;
	/* Maintain compatibilty with old behaviour */
	for (i = 0; i < OLD_MARS_DIGEST_SIZE; i++) {
		len += sprintf(old + len, "%02x", digest[i]);
	}

	if (likely(prev_link && prev_link[0])) {
		char *tmp;
		prev_digest = brick_strdup(prev_link);
		if (unlikely(!prev_digest)) {
			MARS_ERR("no MEM\n");
			goto out;
		}
		// take the part before ':'
		for (tmp = prev_digest; *tmp; tmp++)
			if (*tmp == ':')
				break;
		*tmp = '\0';
	}

	len += sprintf(old + len, ",log-%09d-%s,%lld:%s", inf->inf_sequence, inf->inf_host, inf->inf_log_pos, prev_digest ? prev_digest : "");

	new = path_make("%s/version-%09d-%s", rot->parent_path, inf->inf_sequence, my_id());
	if (!new) {
		MARS_ERR("no MEM\n");
		goto out;
	}

	_crashme(2, true);

	res = _update_link_when_necessary(rot , "version", old, new);

out:
	brick_string_free(new);
	brick_string_free(prev);
	brick_string_free(data);
	brick_string_free(digest);
	brick_string_free(old);
	brick_string_free(prev_link);
	brick_string_free(prev_digest);
	return res;
}

static
void _update_info(struct trans_logger_info *inf)
{
	struct mars_rotate *rot = inf->inf_private;
	int hash;

	if (unlikely(!rot)) {
		MARS_ERR("rot is NULL\n");
		goto done;
	}

	MARS_DBG("inf = %p '%s' seq = %d min_pos = %lld max_pos = %lld log_pos = %lld is_replaying = %d is_logging = %d\n",
		 inf,
		 SAFE_STR(inf->inf_host),
		 inf->inf_sequence,
		 inf->inf_min_pos,
		 inf->inf_max_pos,
		 inf->inf_log_pos,
		 inf->inf_is_replaying,
		 inf->inf_is_logging);

	hash = inf->inf_index - TL_INPUT_LOG1;
	if (unlikely(hash < 0 || hash >= INFS_MAX)) {
			MARS_ERR_TO(rot->log_say,
				    "bad inf_index=%d hash=%d\n",
				    inf->inf_index, hash);
			goto done;
	}
	if (rot->infs_is_dirty[hash]) {
		/* The logger thread is updating faster than the main thread
		 * can deal with. This may happen.
		 */
		if (rot->infs[hash].inf_sequence != inf->inf_sequence) {
			MARS_DBG("buffer %d: sequence trash %d -> %d\n",
				 hash,
				 rot->infs[hash].inf_sequence,
				 inf->inf_sequence);
		} else {
			MARS_DBG("buffer %d is overwritten (sequence=%d)\n", hash, inf->inf_sequence);
		}
	}

	mutex_lock(&rot->inf_mutex);
	memcpy(&rot->infs[hash], inf, sizeof(struct trans_logger_info));
	rot->infs_is_dirty[hash] = true;
	mutex_unlock(&rot->inf_mutex);

	mars_trigger();
done:;
}

static
void write_info_links(struct mars_rotate *rot)
{
	int count = 0;
	int hash = -1;
	int min = 0;
	int i;

	if (unlikely(!rot->trans_brick))
		return;

	mutex_lock(&rot->inf_mutex);
	/* Only update the lowest log number, even if multiple
	 * logfiles are written in parallel during logrotate.
	 * Otherwise we would get nasty races, since their update
	 * speed may be different.
	 */
	for (i = TL_INPUT_LOG1; i <= TL_INPUT_LOG2; i++) {
		struct trans_logger_input *trans_input;
		int inf_nr;

		trans_input = rot->trans_brick->inputs[i];
		if (!trans_input ||
		    !trans_input->connect)
			continue;
		inf_nr = i - TL_INPUT_LOG1;
		if (!min || rot->infs[inf_nr].inf_sequence < min) {
			min = rot->infs[inf_nr].inf_sequence;
			hash = inf_nr;
		}
	}

	if (hash < 0 || !rot->infs_is_dirty[hash]) {
		mutex_unlock(&rot->inf_mutex);
		MARS_DBG("hash=%d\n", hash);
		return;
	}

	rot->infs_is_dirty[hash] = false;
	memcpy(&rot->current_inf, &rot->infs[hash],
	       sizeof(struct trans_logger_info));
	mutex_unlock(&rot->inf_mutex);

	MARS_DBG("seq=%d min_pos=%lld max_pos=%lld log_pos=%lld is_replaying=%d is_logging=%d\n",
		 rot->current_inf.inf_sequence,
		 rot->current_inf.inf_min_pos,
		 rot->current_inf.inf_max_pos,
		 rot->current_inf.inf_log_pos,
		 rot->current_inf.inf_is_replaying,
		 rot->current_inf.inf_is_logging);

	if (rot->current_inf.inf_is_logging | rot->current_inf.inf_is_replaying) {
		count += _update_replay_link(rot, &rot->current_inf);
		count += _update_version_link(rot, &rot->current_inf, true);
		if (min > rot->inf_old_sequence) {
			mars_sync();
			rot->inf_old_sequence = min;
		}
	}
	if (count) {
		if (rot->current_inf.inf_min_pos == rot->current_inf.inf_max_pos)
			mars_trigger();
		if (rot->todo_primary | rot->is_primary | rot->old_is_primary)
			mars_remote_trigger();
	}
}

static
void _recover_versionlink(struct mars_rotate *rot,
			  const char *host,
			  int sequence, loff_t end_pos)
{
	struct trans_logger_info inf = {
		.inf_private = rot,
		.inf_sequence = sequence,
		.inf_min_pos = 0,
		.inf_max_pos = 0,
		.inf_log_pos = end_pos,
		.inf_is_replaying = false,
	};
	strncpy(inf.inf_host, host, sizeof(inf.inf_host));

	MARS_DBG("sequence = %d end_pos = %lld\n",
		 sequence, end_pos);

	_update_version_link(rot, &inf, false);
}

static
void _make_new_replaylink(struct mars_rotate *rot, char *new_host, int new_sequence, loff_t end_pos)
{
	struct trans_logger_info inf = {
		.inf_private = rot,
		.inf_sequence = new_sequence,
		.inf_min_pos = 0,
		.inf_max_pos = 0,
		.inf_log_pos = end_pos,
		.inf_is_replaying = true,
	};
	strncpy(inf.inf_host, new_host, sizeof(inf.inf_host));

	MARS_DBG("new_host = '%s' new_sequence = %d end_pos = %lld\n", new_host, new_sequence, end_pos);

	_update_replay_link(rot, &inf);
	_update_version_link(rot, &inf, false);

	mars_trigger();
	if (rot->todo_primary | rot->is_primary | rot->old_is_primary)
		mars_remote_trigger();
}

static
int __show_actual(const char *path, const char *name, int val)
{
	char *src;
	char *dst = NULL;
	int status = -EINVAL;

	src = path_make("%d", val);
	dst = path_make("%s/actual-%s/%s", path, my_id(), name);
	status = -ENOMEM;
	if (!dst)
		goto done;

	MARS_DBG("symlink '%s' -> '%s'\n", dst, src);
	status = ordered_symlink(src, dst, NULL);

done:
	brick_string_free(src);
	brick_string_free(dst);
	return status;
}

static inline
int _show_actual(const char *path, const char *name, bool val)
{
	return __show_actual(path, name, val ? 1 : 0);
}

static
void _show_primary(struct mars_rotate *rot, struct mars_dent *parent)
{
	int status;
	if (!rot || !parent) {
		return;
	}
	status = _show_actual(parent->d_path, "is-primary", rot->is_primary);
	if (rot->is_primary != rot->old_is_primary) {
		rot->old_is_primary = rot->is_primary;
		mars_remote_trigger();
	}
}

static
void _show_brick_status(struct mars_brick *test, bool shutdown)
{
	const char *path;
	char *src;
	char *dst;
	int status;
	path = test->brick_path;
	if (!path) {
		MARS_WRN("bad path\n");
		return;
	}
	if (*path != '/') {
		MARS_WRN("bogus path '%s'\n", path);
		return;
	}

	src = (test->power.led_on && !shutdown) ? "1" : "0";
	dst = backskip_replace(path, '/', true, "/actual-%s/", my_id());
	if (!dst) {
		return;
	}

	status = ordered_symlink(src, dst, NULL);
	MARS_DBG("status symlink '%s' -> '%s' status = %d\n", dst, src, status);
	brick_string_free(dst);
}

static
void _show_rate(struct mars_rotate *rot, struct mars_limiter *limiter, const char *basename)
{
	char *name;

	mars_limit(limiter, 0);

	name = path_make("ops-%s", basename);
	__show_actual(rot->parent_path, name, limiter->lim_ops_rate);
	brick_string_free(name);

	name = path_make("amount-%s", basename);
	__show_actual(rot->parent_path, name, limiter->lim_amount_rate);
	brick_string_free(name);
}

///////////////////////////////////////////////////////////////////////

typedef int (*copy_update_fn)(struct mars_brick *copy, bool switch_on, void *private);

static
int __make_copy(
		struct mars_global *global,
		struct mars_dent *belongs,
		const char *switch_path,
		const char *copy_path,
		const char *parent,
		const char *argv[],
		struct key_value_pair *msg_pair,
		loff_t start_pos, // -1 means at EOF of source
		loff_t end_pos,   // -1 means at EOF of target
		bool keep_running,
		bool verify_mode,
		bool limit_mode,
		bool space_using_mode,
		struct copy_brick **__copy,
		copy_update_fn updater,
		void *private)
{
	struct mars_brick *copy;
	struct copy_cookie cc = {};
	struct client_cookie clc[2] = {
		{
			.limit_mode = limit_mode,
		},
		{
			.limit_mode = limit_mode,
			.create_mode = true,
		},
	};
	int i;
	bool switch_copy;
	bool later_off = false;
	int status = -EINVAL;

	if (!switch_path || !global) {
		goto done;
	}

	// don't generate empty aio files if copy does not yet exist
	switch_copy = _check_switch(global, switch_path);
	copy = mars_find_brick(global, &copy_brick_type, copy_path);
	if (!copy && !switch_copy) {
		goto done;
	}

	// create/find predecessor aio bricks
	for (i = 0; i < 2; i++) {
		struct mars_brick *aio;

		/* do not change names underway */
		if (copy && copy->inputs[i] && copy->inputs[i]->connect) {
			aio = copy->inputs[i]->connect->brick;
			if (aio && aio->power.button)
				goto found;
		}

		cc.argv[i] = argv[i];
		if (parent) {
			cc.fullpath[i] = path_make("%s/%s", parent, argv[i]);
			if (!cc.fullpath[i]) {
				MARS_ERR("cannot make path '%s/%s'\n", parent, argv[i]);
				goto done;
			}
		} else {
			cc.fullpath[i] = argv[i];
		}

		aio =
			make_brick_all(global,
				       NULL,
				       _set_bio_params,
				       &clc[i],
				       NULL,
				       (const struct generic_brick_type*)&bio_brick_type,
				       (const struct generic_brick_type*[]){},
				       switch_copy || (copy && !copy->power.led_off) ? 2 : -1,
				       cc.fullpath[i],
				       (const char *[]){},
				       0);
		if (!aio) {
			MARS_DBG("cannot instantiate '%s'\n", cc.fullpath[i]);
			make_msg(msg_pair, "cannot instantiate '%s'", cc.fullpath[i]);
			goto done;
		}
		if (!aio->power.led_on) {
			MARS_DBG("predecessor '%s' not yet on\n", cc.fullpath[i]);
			aio->power.force_off = false;
			later_off = true;
		}

	found:
		cc.output[i] = aio->outputs[0];

		/* When switching off, use a short timeout for aborting.
		 * Important on very slow networks (since a large number
		 * of requests may be pending).
		 */
		aio->power.io_timeout = switch_copy ? 0 : 1;
	}

	switch_copy = (switch_copy &&
		       !later_off &&
		       (!IS_EMERGENCY_PRIMARY() || space_using_mode));
	if (updater) {
		status = updater(copy, switch_copy, private);
		if (unlikely(status < 0)) {
			MARS_DBG("brick '%s' updater status=%d\n",
				 copy->brick_path, status);
		}
	}

	cc.copy_path = copy_path;
	cc.start_pos = start_pos;
	cc.end_pos = end_pos;
	cc.keep_running = keep_running;
	cc.verify_mode = verify_mode;

	copy =
		make_brick_all(global,
			       belongs,
			       _set_copy_params,
			       &cc,
			       cc.fullpath[1],
			       (const struct generic_brick_type*)&copy_brick_type,
			       (const struct generic_brick_type*[]){NULL,NULL,NULL,NULL},
			       switch_copy ? 2 : -1,
			       "%s",
			       (const char *[]){"%s", "%s", "%s", "%s"},
			       4,
			       copy_path,
			       cc.fullpath[0],
			       cc.fullpath[0],
			       cc.fullpath[1],
			       cc.fullpath[1]);
	if (copy) {
		struct copy_brick *_copy = (void*)copy;
		copy->show_status = _show_brick_status;
		make_msg(msg_pair,
			 "from = '%s' to = '%s'"
			 " on = %d start_pos = %lld end_pos = %lld"
			 " actual_pos = %lld actual_stamp = %ld.%09ld"
			 " ops_rate = %d amount_rate = %d"
			 " read_fly = %d write_fly = %d error_code = %d nr_errors = %d",
			 argv[0],
			 argv[1],
			 _copy->power.led_on,
			 _copy->copy_start,
			 _copy->copy_end,
			 _copy->copy_last,
			 _copy->copy_last_stamp.tv_sec, _copy->copy_last_stamp.tv_nsec,
			 _copy->copy_limiter ? _copy->copy_limiter->lim_ops_rate : 0,
			 _copy->copy_limiter ? _copy->copy_limiter->lim_amount_rate : 0,
			 atomic_read(&_copy->copy_read_flight),
			 atomic_read(&_copy->copy_write_flight),
			 _copy->copy_error,
			 _copy->copy_error_count);
	}
	if (__copy)
		*__copy = (void*)copy;

	status = 0;

done:
	MARS_DBG("status = %d\n", status);
	for (i = 0; i < 2; i++) {
		if (cc.fullpath[i] && cc.fullpath[i] != argv[i])
			brick_string_free(cc.fullpath[i]);
	}
	return status;
}

///////////////////////////////////////////////////////////////////////

// remote workers

static DECLARE_RWSEM(peer_lock);
static int peer_count = 0;
static
struct list_head peer_anchor = LIST_HEAD_INIT(peer_anchor);

struct mars_peerinfo {
	struct mars_global *global;
	char *peer;
	char *peer_dir_list;
	struct mars_socket socket;
	struct task_struct *peer_thread;
	struct mutex peer_lock;
	struct list_head peer_head;
	struct list_head remote_dent_list;
	unsigned long last_remote_jiffies;
	int maxdepth;
	int features_version;
	int strategy_version;
	__u32 available_mask;
	bool to_terminate;
	bool has_terminated;
	bool to_remote_trigger;
	bool from_remote_trigger;
	bool do_communicate;
	bool do_additional;
	bool do_entire_once;
	bool doing_additional;
};

static
struct mars_peerinfo *find_peer(const char *peer_name)
{
	struct list_head *tmp;
	struct mars_peerinfo *res = NULL;

	/* TODO: replace exhaustive search by better data structure */
	down_read(&peer_lock);
	for (tmp = peer_anchor.next; tmp != &peer_anchor; tmp = tmp->next) {
		struct mars_peerinfo *peer = container_of(tmp, struct mars_peerinfo, peer_head);
		if (!strcmp(peer->peer, peer_name)) {
			res = peer;
			break;
		}
	}
	up_read(&peer_lock);

	return res;
}

static
void additional_peers(int add)
{
	if (add <= 0)
		return;

	down_read(&peer_lock);
	while (add > 0) {
		/* Approximate equal distribution */
#ifdef HAS_GET_RANDOM_INT
		int nr = peer_count > 1 ? get_random_int() % peer_count : 0;
#else
		struct lamport_time now = get_real_lamport();
		int nr = peer_count > 1 ? (now.tv_sec + now.tv_nsec) % peer_count : 0;
#endif
		struct list_head *tmp;

		for (tmp = peer_anchor.next; tmp != &peer_anchor; tmp = tmp->next) {
			struct mars_peerinfo *peer;

			peer = container_of(tmp, struct mars_peerinfo, peer_head);
			if (peer->do_communicate | peer->do_additional)
				continue;
			if (!nr) {
				peer->do_additional = true;
				break;
			}
			nr--;
		}
		add--;
	}
	up_read(&peer_lock);
}

static
void show_peers(void)
{
	struct list_head *tmp;

	down_read(&peer_lock);
	MARS_DBG("PEER_count = %d\n", peer_count); 
	for (tmp = peer_anchor.next; tmp != &peer_anchor; tmp = tmp->next) {
		struct mars_peerinfo *peer;

		peer = container_of(tmp, struct mars_peerinfo, peer_head);
		MARS_DBG("PEER '%s' alive=%d trigg=%d/%d comm=%d add=%d/%d\n",
			 peer->peer,
			 mars_socket_is_alive(&peer->socket),
			 peer->to_remote_trigger,
			 peer->from_remote_trigger,
			 peer->do_communicate,
			 peer->do_additional,
			 peer->doing_additional);
	}
	up_read(&peer_lock);
}

static
bool _is_usable_dir(const char *name)
{
	if (!strncmp(name, "resource-", 9)
	   || !strncmp(name, "todo-", 5)
	   || !strncmp(name, "actual-", 7)
	   || !strncmp(name, "defaults", 8)
	   ) {
		return true;
	}
	return false;
}

static
bool _is_peer_logfile(const char *name, const char *id)
{
	int len = strlen(name);
	int idlen = id ? strlen(id) : 4 + 9 + 1;

	if (len <= idlen ||
	   strncmp(name, "log-", 4) != 0) {
		MARS_DBG("not a logfile at all: '%s'\n", name);
		return false;
	}
	if (id &&
	   name[len - idlen - 1] == '-' &&
	   strncmp(name + len - idlen, id, idlen) == 0) {
		MARS_DBG("not a peer logfile: '%s'\n", name);
		return false;
	}
	MARS_DBG("found peer logfile: '%s'\n", name);
	return true;
}

static
int _update_file(struct mars_dent *parent, const char *switch_path, const char *copy_path, const char *file, const char *peer, loff_t end_pos)
{
	struct mars_rotate *rot = parent->d_private;
	struct mars_global *global = rot->global;
#ifdef CONFIG_MARS_SEPARATE_PORTS
	const char *tmp = path_make("%s@%s:%d", file, peer, mars_net_default_port + MARS_TRAFFIC_REPLICATION);
#else
	const char *tmp = path_make("%s@%s", file, peer);
#endif
	const char *argv[2] = { tmp, file };
	struct copy_brick *copy = NULL;
	struct key_value_pair *msg_pair = find_key(rot->msgs, "inf-fetch");
	loff_t start_pos;
	bool do_start = true;
	int status = -ENOMEM;

	if (unlikely(!tmp || !global))
		goto done;

	rot->fetch_round = 0;

	if (rot->todo_primary | rot->is_primary) {
		MARS_DBG("disallowing fetch, todo_primary=%d is_primary=%d\n", rot->todo_primary, rot->is_primary);
		make_msg(msg_pair, "disallowing fetch (todo_primary=%d is_primary=%d)", rot->todo_primary, rot->is_primary);
		do_start = false;
	}
	if (do_start && !strcmp(peer, "(none)")) {
		MARS_DBG("disabling fetch from unspecified peer / no primary designated\n");
		make_msg(msg_pair, "disabling fetch from unspecified peer / no primary designated");
		do_start = false;
	}
	if (do_start && !_check_allow(rot->global, rot->parent_path, "attach")) {
		MARS_DBG("disabling fetch due to detach / rmmod\n");
		make_msg(msg_pair, "disabling fetch due to detach / rmmod");
		do_start = false;
	}
#if 0
	/* Disabled for now. Re-enable this code after a new feature has been
	 * implemented: when pause-replay is given, /dev/mars/mydata should
	 * appear in _readonly_ form.
	 * The idea is to _not_ disable the fetch during this!
	 * You may draw a backup from the readonly device without losing your
	 * redundancy, because the transactions logs will contiue to be updated.
	 * Until the new feature is implemented, use
	 * "marsadm pause-replay $res; marsadm detach $res; mount -o ro /dev/lv/$res"
	 * as a workaround.
	 */
	if (do_start && !_check_allow(global, parent->d_path, "attach")) {
		MARS_DBG("disabling fetch due to detach\n");
		make_msg(msg_pair, "disabling fetch due to detach");
		do_start = false;
	}
#endif
	if (do_start && !_check_allow(global, parent->d_path, "connect")) {
		MARS_DBG("disabling fetch due to disconnect\n");
		make_msg(msg_pair, "disabling fetch due to disconnect");
		do_start = false;
	}

	/* Self-correct logfile when necessary
	 */
	start_pos = -1;
	if (do_start && (rot->is_log_damaged | rot->log_is_really_damaged)) {
		start_pos = 0;
		MARS_INF("Trying to repair damaged logfile '%s'\n", file);
	}

	MARS_DBG("src = '%s' dst = '%s' start_pos=%lld do_start=%d\n",
		 tmp, file, start_pos, do_start);

	status = __make_copy(global,
			     NULL,
			     do_start ? switch_path : "",
			     copy_path,
			     NULL,
			     argv,
			     msg_pair,
			     start_pos,
			     -1, 
			     false, false, false, true,
			     &copy,
			     NULL, NULL);
	if (status >= 0 && copy) {
		copy->copy_limiter = &rot->fetch_limiter;
		// FIXME: code is dead
		if (copy->append_mode && copy->power.led_on &&
		    end_pos > copy->copy_end) {
			MARS_DBG("appending to '%s' %lld => %lld\n", copy_path, copy->copy_end, end_pos);
			// FIXME: use corrected length from mars_get_info() / see _set_copy_params()
			copy->copy_end = end_pos;
		}
	}

done:
	brick_string_free(tmp);
	return status;
}

static
int check_logfile(const char *peer, struct mars_dent *remote_dent, struct mars_dent *local_dent, struct mars_dent *parent, loff_t dst_size)
{
	loff_t src_size = remote_dent->new_stat.size;
	struct mars_rotate *rot;
	const char *switch_path = NULL;
	struct copy_brick *fetch_brick;
	int status = 0;

	// correct the remote size when necessary
	if (remote_dent->d_corr_B > 0 && remote_dent->d_corr_B < src_size) {
		MARS_DBG("logfile '%s' correcting src_size from %lld to %lld\n", remote_dent->d_path, src_size, remote_dent->d_corr_B);
		src_size = remote_dent->d_corr_B;
	}

	// plausibility checks
	if (unlikely(dst_size > src_size)) {
		MARS_WRN("my local copy is larger than the remote one, ignoring\n");
		status = -EINVAL;
		goto done;
	}

	// check whether we are participating in that resource
	rot = parent->d_private;
	if (!rot) {
		MARS_WRN("parent has no rot info\n");
		status = -EINVAL;
		goto done;
	}
	if (!rot->fetch_path) {
		MARS_WRN("parent has no fetch_path\n");
		status = -EINVAL;
		goto done;
	}

	// bookkeeping for serialization of logfile updates
	if (remote_dent->d_serial > rot->fetch_serial) {
		rot->fetch_next_is_available++;
		if (!rot->fetch_next_serial || !rot->fetch_next_origin) {
			rot->fetch_next_serial = remote_dent->d_serial;
			rot->fetch_next_origin = brick_strdup(remote_dent->d_rest);
		} else if (rot->fetch_next_serial == remote_dent->d_serial && strcmp(rot->fetch_next_origin, remote_dent->d_rest)) {
			rot->split_brain_round = 0;
			rot->split_brain_serial = remote_dent->d_serial;
			MARS_WRN("SPLIT BRAIN (logfiles from '%s' and '%s' with same serial number %d) detected!\n",
				 rot->fetch_next_origin, remote_dent->d_rest, rot->split_brain_serial);
		}
	}

	// check whether connection is allowed
	switch_path = path_make("%s/todo-%s/connect", parent->d_path, my_id());

	// check whether copy is necessary
	fetch_brick = rot->fetch_brick;
	MARS_DBG("fetch_brick = %p (remote '%s' %d) fetch_serial = %d\n", fetch_brick, remote_dent->d_path, remote_dent->d_serial, rot->fetch_serial);
	if (fetch_brick) {
		if (remote_dent->d_serial == rot->fetch_serial && rot->fetch_peer && !strcmp(peer, rot->fetch_peer)) {
			// treat copy brick instance underway
			status = _update_file(parent, switch_path, rot->fetch_path, remote_dent->d_path, peer, src_size);
			MARS_DBG("re-update '%s' from peer '%s' status = %d\n", remote_dent->d_path, peer, status);
		}
	/* Try to self-repair any damaged logfiles.
	 */
	} else if ((rot->is_log_damaged | rot->log_is_really_damaged) &&
		   rot->replay_mode && !rot->todo_primary &&  rot->allow_update &&
		   rot->repair_log_seq == remote_dent->d_serial) {
		status = _update_file(parent, switch_path, rot->fetch_path, remote_dent->d_path, peer, src_size);
		MARS_DBG("REPAIR '%s' from peer '%s' status = %d\n", remote_dent->d_path, peer, status);
	} else if (!rot->fetch_serial && rot->allow_update &&
		   !rot->is_primary && !rot->old_is_primary &&
		   (!rot->preferred_peer || !strcmp(rot->preferred_peer, peer)) &&
		   (!rot->avoid_peer || strcmp(peer, rot->avoid_peer) || rot->avoid_count-- <= 0) &&
		   (!rot->split_brain_serial || remote_dent->d_serial < rot->split_brain_serial) &&
		   (dst_size < src_size || !local_dent)) {
		// start copy brick instance
		status = _update_file(parent, switch_path, rot->fetch_path, remote_dent->d_path, peer, src_size);
		MARS_DBG("update '%s' from peer '%s' status = %d\n", remote_dent->d_path, peer, status);
		if (likely(status >= 0)) {
			rot->fetch_serial = remote_dent->d_serial;
			rot->fetch_next_is_available = 0;
			brick_string_free(rot->avoid_peer);
			brick_string_free(rot->fetch_peer);
			rot->fetch_peer = brick_strdup(peer);
		}
	} else {
		MARS_DBG("allow_update = %d src_size = %lld dst_size = %lld local_dent = %p\n", rot->allow_update, src_size, dst_size, local_dent);
	}

done:
	brick_string_free(switch_path);
	return status;
}

static
int run_bone(struct mars_peerinfo *peer, struct mars_dent *remote_dent)
{
	int status = 0;
	struct kstat local_stat = {};
	bool stat_ok;
	bool is_deleted;
	bool update_mtime = true;
	bool update_ctime = true;
	bool run_trigger = false;
	bool run_systemd_trigger = false;

	if (!strncmp(remote_dent->d_name, ".tmp", 4)) {
		goto done;
	}
	if (!strncmp(remote_dent->d_name, ".deleted-", 9)) {
		goto done;
	}
	if (!strncmp(remote_dent->d_name, "ignore", 6)) {
		goto done;
	}

	if (remote_dent->new_link && !strncmp(remote_dent->d_path, "/mars/todo-global/delete-", 25)) {
		if (remote_dent->d_serial < peer->global->deleted_my_border) {
			MARS_DBG("ignoring deletion '%s' at border %d\n", remote_dent->d_path, peer->global->deleted_my_border);
			goto done;
		}
	}

	status = mars_stat(remote_dent->d_path, &local_stat, true);
	stat_ok = (status >= 0);

	is_deleted = remote_dent->new_link &&
		!strcmp(remote_dent->new_link, MARS_DELETED_STR);

	if (stat_ok) {
		update_mtime = lamport_time_compare(&remote_dent->new_stat.mtime, &local_stat.mtime) > 0;
		update_ctime = lamport_time_compare(&remote_dent->new_stat.ctime, &local_stat.ctime) > 0;

		MARS_IO("timestamps '%s' remote = %ld.%09ld local = %ld.%09ld\n", remote_dent->d_path, remote_dent->new_stat.mtime.tv_sec, remote_dent->new_stat.mtime.tv_nsec, local_stat.mtime.tv_sec, local_stat.mtime.tv_nsec);

#ifdef MARS_HAS_PREPATCH
		if ((remote_dent->new_stat.mode & S_IRWXU) !=
		   (local_stat.mode & S_IRWXU) &&
		   update_ctime) {
			mode_t newmode = local_stat.mode;
			MARS_DBG("chmod '%s' 0x%xd -> 0x%xd\n", remote_dent->d_path, newmode & S_IRWXU, remote_dent->new_stat.mode & S_IRWXU);
			newmode &= ~S_IRWXU;
			newmode |= (remote_dent->new_stat.mode & S_IRWXU);
			mars_chmod(remote_dent->d_path, newmode);
			run_trigger = true;
		}
#endif
	}

	if (S_ISDIR(remote_dent->new_stat.mode)) {
		if (!_is_usable_dir(remote_dent->d_name)) {
			MARS_DBG("ignoring directory '%s'\n", remote_dent->d_path);
			goto done;
		}
		if (!stat_ok) {
			status = mars_mkdir(remote_dent->d_path);
			MARS_DBG("create directory '%s' status = %d\n", remote_dent->d_path, status);
#ifdef MARS_HAS_PREPATCH
			if (status >= 0) {
				mars_chmod(remote_dent->d_path, remote_dent->new_stat.mode);
			}
#endif
		}
	} else if (S_ISLNK(remote_dent->new_stat.mode) && remote_dent->new_link) {
		/* Important: not not create .deleted values
		 * unless the object already exists.
		 */
		if (is_deleted ?
		    (stat_ok && update_mtime) :
		    (!stat_ok || update_mtime)) {
			status = ordered_symlink(remote_dent->new_link,
						 remote_dent->d_path,
						 &remote_dent->new_stat.mtime);
			MARS_DBG("create symlink '%s' -> '%s' status = %d\n", remote_dent->d_path, remote_dent->new_link, status);
			run_trigger = true;
			if (!status &&
			    (!strncmp(remote_dent->d_name, "primary", 7) ||
			     !strncmp(remote_dent->d_name, "systemd", 7)))
				run_systemd_trigger = true;

		}
	} else if (S_ISREG(remote_dent->new_stat.mode) && _is_peer_logfile(remote_dent->d_name, my_id())) {
		const char *parent_path = backskip_replace(remote_dent->d_path, '/', false, "");
		if (likely(parent_path)) {
			struct mars_dent *parent = mars_find_dent(peer->global, parent_path);
			struct mars_rotate *rot;
			if (unlikely(!parent)) {
				MARS_DBG("ignoring non-existing local resource '%s'\n", parent_path);
			// don't copy old / outdated logfiles
			} else if ((rot = parent->d_private) &&
				   rot->relevant_serial > remote_dent->d_serial) {
				MARS_DBG("ignoring outdated remote logfile '%s' (behind %d)\n", remote_dent->d_path, rot->relevant_serial);
			} else {
				struct mars_dent *local_dent = mars_find_dent(peer->global, remote_dent->d_path);
				status = check_logfile(peer->peer, remote_dent, local_dent, parent, local_stat.size);
			}
			brick_string_free(parent_path);
		}
	} else {
		MARS_DBG("ignoring '%s'\n", remote_dent->d_path);
	}

 done:
	if (status >= 0) {
		status = run_trigger ? 1 : 0;
		if (run_systemd_trigger)
			status |= 2;
	}
	return status;
}

static
int run_bones(struct mars_peerinfo *peer)
{
	LIST_HEAD(tmp_list);
	struct list_head *tmp;
	bool run_trigger = false;
	bool run_systemd_trigger = false;
	int status = 0;

	mutex_lock(&peer->peer_lock);
	list_replace_init(&peer->remote_dent_list, &tmp_list);
	mutex_unlock(&peer->peer_lock);

	MARS_DBG("remote_dent_list list_empty = %d\n", list_empty(&tmp_list));

	if (peer->do_additional && !peer->doing_additional &&
	    !peer->do_communicate && !list_empty(&tmp_list)) {
		peer->doing_additional = true;
		mars_running_additional_peers++;
	}
	for (tmp = tmp_list.next; tmp != &tmp_list; tmp = tmp->next) {
		struct mars_dent *remote_dent = container_of(tmp, struct mars_dent, dent_link);
		if (!remote_dent->d_path || !remote_dent->d_name) {
			MARS_DBG("NULL\n");
			continue;
		}
		MARS_IO("path = '%s'\n", remote_dent->d_path);
		status = run_bone(peer, remote_dent);
		if (status > 0) {
			run_trigger = true;
			if (status & 2)
				run_systemd_trigger = true;
		}
		//MARS_DBG("path = '%s' worker status = %d\n", remote_dent->d_path, status);
	}

	mars_free_dent_all(NULL, &tmp_list);

	if (run_trigger) {
		mars_trigger();
	}
	if (run_systemd_trigger) {
		struct file *f;
		const int flags = O_RDWR | O_CREAT;
		const int prot = 0600;
		mm_segment_t oldfs;

		oldfs = get_fs();
		set_fs(get_ds());
		f = filp_open("/mars/userspace/systemd-trigger", flags, prot);
		set_fs(oldfs);
		if (f && !IS_ERR(f))
			filp_close(f, NULL);
	}
	return status;
}

///////////////////////////////////////////////////////////////////////

// remote working infrastructure

static
void _peer_cleanup(struct mars_peerinfo *peer)
{
	MARS_DBG("cleanup\n");
	if (mars_socket_is_alive(&peer->socket)) {
		MARS_DBG("really shutdown socket\n");
		mars_shutdown_socket(&peer->socket);
	}
	mars_put_socket(&peer->socket);
}

static DECLARE_WAIT_QUEUE_HEAD(remote_event);

static inline
bool peer_thead_should_run(struct mars_peerinfo *peer)
{
	return mars_net_is_alive && !peer->to_terminate && !brick_thread_should_stop();
}

static
void report_peer_connection(struct key_value_pair *peer_pairs, bool do_additional)
{
	const char *peer_role =
		do_additional ? "additional-connection-with-" : "needed-connection-with-";

	show_vals(peer_pairs, "/mars", peer_role);
}

static
int peer_action_dent_list(struct mars_global *tmp_global,
			  struct mars_peerinfo *peer,
			  const char *real_peer,
			  const char *paths,
			  struct key_value_pair *peer_pairs)
{
	int status;

	MARS_DBG("fetching remote dentries from '%s' '%s'\n",
		 peer->peer, paths);

	status = mars_recv_dent_list(&peer->socket, &tmp_global->dent_anchor);
	if (unlikely(status < 0))
		goto free;

	if (likely(!list_empty(&tmp_global->dent_anchor))) {
		LIST_HEAD(old_list);
		struct mars_dent *peer_uuid;
		const char *my_uuid;
		int cmp;

		MARS_DBG("got remote denties from %s\n", peer->peer);

		peer_uuid = mars_find_dent(tmp_global, "/mars/uuid");
		if (unlikely(!peer_uuid || !peer_uuid->new_link)) {
			MARS_ERR("peer %s has no uuid\n", peer->peer);
			make_msg(peer_pairs, "peer '%s' has no UUID",
				 peer->peer);
			status = -EPROTO;
			goto free;
		}
		my_uuid = ordered_readlink("/mars/uuid");
		if (unlikely(!my_uuid)) {
			MARS_ERR("cannot determine my own uuid for peer %s\n", peer->peer);
			make_msg(peer_pairs, "cannot determine my own uuid");
			status = -EPROTO;
			goto free;
		}
		cmp = strcmp(peer_uuid->new_link, my_uuid);
		if (unlikely(cmp)) {
			MARS_ERR("UUID mismatch for peer %s, you are trying to communicate with a foreign cluster!\n", peer->peer);
			make_msg(peer_pairs, "UUID mismatch with '%s', own cluster '%s' is trying to communicate with a foreign cluster '%s'",
				 peer->peer,
				 my_uuid, peer_uuid->new_link);
			brick_string_free(my_uuid);
			status = -EPROTO;
			goto free;
		}
		brick_string_free(my_uuid);

		make_msg(peer_pairs, "CONNECTED %s(%s) fetching '%s'",
			 peer->peer, real_peer,
			 paths);

		mutex_lock(&peer->peer_lock);

		list_replace_init(&peer->remote_dent_list, &old_list);
		list_replace_init(&tmp_global->dent_anchor, &peer->remote_dent_list);
		list_del_init(&tmp_global->dent_quick_anchor);

		mutex_unlock(&peer->peer_lock);

		peer->last_remote_jiffies = jiffies;

		mars_trigger();

		mars_free_dent_all(tmp_global, &old_list);
	}

 free:
	mars_free_dent_all(tmp_global, &tmp_global->dent_anchor);
	return status;
}

/* React on different types of peer responses
 */
static
int peer_actions(struct mars_global *tmp_global,
		 struct mars_peerinfo *peer,
		 const char *real_peer,
		 const char *paths,
		 struct key_value_pair *peer_pairs)
{
	struct mars_cmd inter_cmd = {
	};
	int status;

	/* Compatibility to old protocol: we cannot send/recv cmds */
	if (!peer->socket.s_common_proto_level)
		return peer_action_dent_list(tmp_global,
					     peer, real_peer, paths,
					     peer_pairs);

	/* New protocoal with extensible cases */
	status = mars_recv_cmd(&peer->socket, &inter_cmd);
	if (unlikely(status < 0)) {
		MARS_WRN("communication error on inter_cmd receive, status = %d\n", status);
		goto done;
	}

	switch (inter_cmd.cmd_code) {
	case CMD_GETENTS:
	{
	  status = peer_action_dent_list(tmp_global,
					 peer, real_peer,
					 paths, peer_pairs);
		break;
	}
	default:
		/* do nothing, ignore any unknown inter_cmd */
		break;
	}

 done:
	brick_string_free(inter_cmd.cmd_str1);
	return status;
}

static
int peer_thread(void *data)
{
	struct mars_peerinfo *peer = data;
	const char *real_host;
	const char *real_peer;
	struct sockaddr_storage sockaddr = {};
	struct key_value_pair peer_pairs[] = {
		{ peer->peer },
		{ NULL }
	};
	struct mars_global *tmp_global;
	int pause_time = 0;
	bool do_kill = false;
	bool repeated = false;
	int status;

	if (!peer || !mars_net_is_alive)
		return -1;

	tmp_global = alloc_mars_global();

	real_host = mars_translate_hostname(peer->peer);
	real_peer = path_make("%s:%d",
			      real_host,
			      mars_net_default_port + MARS_TRAFFIC_META);
	brick_string_free(real_host);
	MARS_INF("-------- peer thread starting on peer '%s' (%s)\n", peer->peer, real_peer);

	status = mars_create_sockaddr(&sockaddr, real_peer);
	if (unlikely(status < 0)) {
		MARS_ERR("unusable remote address '%s' (%s)\n", real_peer, peer->peer);
		goto done;
	}

        while (peer_thead_should_run(peer)) {
		struct mars_cmd cmd = {
			.cmd_int1 = peer->maxdepth,
		};

		if (likely(repeated)) {
			report_peer_connection(peer_pairs, !peer->do_communicate);
			report_peer_connection(peer_pairs, peer->do_communicate);
		}
		repeated = true;

		if (!mars_socket_is_alive(&peer->socket)) {
			make_msg(peer_pairs, "connection to '%s' (%s) is dead", peer->peer, real_peer);
			brick_string_free(real_peer);
			real_peer = mars_translate_hostname(peer->peer);
			status = mars_create_sockaddr(&sockaddr, real_peer);
			if (unlikely(status < 0)) {
				MARS_ERR("unusable remote address '%s' (%s)\n", real_peer, peer->peer);
				make_msg(peer_pairs, "unusable remote address '%s' (%s)\n", real_peer, peer->peer);
				brick_msleep(1000);
				continue;
			}
			if (do_kill) {
				do_kill = false;
				_peer_cleanup(peer);
				brick_msleep(1000);
				continue;
			}
			if (!peer_thead_should_run(peer))
				break;

			status = mars_create_socket(&peer->socket,
						    &sockaddr,
						    &mars_tcp_params[MARS_TRAFFIC_META],
						    false);
			if (unlikely(status < 0)) {
				MARS_INF("no connection to mars module on '%s' (%s) status = %d\n", peer->peer, real_peer, status);
				make_msg(peer_pairs, "connection to '%s' (%s) could not be established: status = %d", peer->peer, real_peer, status);
				/* additional threads should give up immediately */
				if (peer->do_additional)
					break;
				brick_msleep(2000);
				continue;
			}
			do_kill = true;
			peer->socket.s_shutdown_on_err = true;
			peer->socket.s_send_abort = mars_peer_abort;
			peer->socket.s_recv_abort = mars_peer_abort;
			MARS_DBG("successfully opened socket to '%s'\n", real_peer);
			clear_vals(peer_pairs);
			peer->to_remote_trigger = true;
			mars_trigger();
			continue;
		} else {
			const char *new_peer;

			/* check whether IP assignment has changed */
			new_peer = mars_translate_hostname(peer->peer);
			MARS_INF("AHA %d '%s' '%s'\n", 
				 mars_socket_is_alive(&peer->socket),
				 new_peer, real_peer);
			if (new_peer && real_peer && strcmp(new_peer, real_peer))
				mars_shutdown_socket(&peer->socket);
			brick_string_free(new_peer);
		}

		if (peer->from_remote_trigger) {
			pause_time = 0;
			peer->from_remote_trigger = false;
			MARS_DBG("got notify from peer.\n");
			mars_trigger();
		}

		status = 0;
		if (peer->to_remote_trigger) {
			pause_time = 0;
			MARS_DBG("sending notify to peer...\n");
			cmd.cmd_code = CMD_NOTIFY;
			status = mars_send_cmd(&peer->socket, &cmd, true);
		}

		if (likely(status >= 0)) {
			peer->to_remote_trigger = false;
			cmd.cmd_code = CMD_GETENTS;
			if ((!peer->do_additional || peer->do_communicate) &&
			    !peer->do_entire_once &&
			    mars_resource_list) {
				char *dir_list;

				down_read(&mars_resource_sem);
				dir_list =  path_make("%s%s",
						      mars_resource_list,
						      peer->peer_dir_list);
				up_read(&mars_resource_sem);
				cmd.cmd_str1 = dir_list;
			} else {
				cmd.cmd_str1 = brick_strdup("/mars");
				peer->do_entire_once = false;
			}
			MARS_DBG("fetching dents from '%s' paths '%s'\n",
				 peer->peer, cmd.cmd_str1);
			status = mars_send_cmd(&peer->socket, &cmd, false);
		}
		if (unlikely(status < 0)) {
			MARS_WRN("communication error on send, status = %d\n", status);
			if (do_kill) {
				do_kill = false;
				_peer_cleanup(peer);
			}
			goto free_and_restart;
		}

		status = peer_actions(tmp_global,
				      peer, real_peer,
				      cmd.cmd_str1, peer_pairs);
		if (unlikely(status < 0)) {
			MARS_WRN("communication error on receive, status = %d\n", status);
			if (do_kill) {
				do_kill = false;
				_peer_cleanup(peer);
			}
			goto free_and_restart;
		}

		brick_string_free(cmd.cmd_str1);
		brick_msleep(100);
		if (!peer->to_terminate && !brick_thread_should_stop()) {
			bool old_additional = peer->do_additional;
			bool old_communicate = peer->do_communicate;

			if (old_additional && !old_communicate) {
				if (mars_running_additional_peers > mars_run_additional_peers)
					break;
				pause_time += 30;
				if (pause_time > 600)
					pause_time = 600;
			}
			if (pause_time < mars_propagate_interval)
				pause_time++;
			wait_event_interruptible_timeout(remote_event,
							 (peer->to_remote_trigger | peer->from_remote_trigger) ||
							 !peer_thead_should_run(peer) ||
							 (old_additional != peer->do_additional) ||
							 (old_communicate != peer->do_communicate) ||
							 (mars_global && mars_global->main_trigger),
							 pause_time * HZ);
		}
		continue;

	free_and_restart:
		brick_string_free(cmd.cmd_str1);
		/* additional threads should give up immediately */
		if (peer->do_additional && !peer->do_communicate)
			break;
		brick_msleep(2000);
	}

	MARS_INF("-------- peer thread terminating\n");

	clear_vals(peer_pairs);
	if (peer->do_communicate)
		make_msg(peer_pairs, "NOT connected %s(%s)", peer->peer, real_peer);
	report_peer_connection(peer_pairs, !peer->do_communicate);
	report_peer_connection(peer_pairs, peer->do_communicate);

	peer->do_additional = false;
	if (peer->doing_additional) {
		peer->doing_additional = false;
		mars_running_additional_peers--;
	}
	if (do_kill) {
		_peer_cleanup(peer);
	}

done:
	clear_vals(peer_pairs);
	brick_string_free(real_peer);
	brick_mem_free(tmp_global);
	peer->has_terminated = true;
	return 0;
}

static
void _make_alive(void)
{
	struct lamport_time now;
	char *tmp;
	char *features;

	/* These need to be updated always */
	get_lamport(NULL, &now);
	tmp = path_make("%ld.%09ld", now.tv_sec, now.tv_nsec);
	if (likely(tmp)) {
		_make_alivelink_str("time", tmp);
		brick_string_free(tmp);
	}
	_make_alivelink("alive", mars_global && mars_global->global_power.button ? 1 : 0);
	/* These may be updated lazily */
	__make_alivelink_str("tree", SYMLINK_TREE_VERSION, true);
	features = path_make(stringify(OPTIONAL_FEATURES_VERSION)
			     ","
			     stringify(OPTIONAL_STRATEGY_VERSION)
			     ",0x%08x",
			     available_digest_mask | available_compression_mask);
	__make_alivelink_str("features", features, true);
	brick_string_free(features);
	features = path_make("%d,%d,0x%08x",
			     usable_features_version,
			     usable_strategy_version,
			     usable_digest_mask | usable_compression_mask);
	__make_alivelink_str("usable", features, true);
	brick_string_free(features);
	__make_alivelink_str("buildtag", BUILDTAG "(" BUILDDATE ")", true);
	__make_alivelink("used-log-digest", used_log_digest, true);
	__make_alivelink("used-net-digest", used_net_digest, true);
	__make_alivelink("used-log-compression", used_log_compression, true);
	__make_alivelink("used-net-compression", used_net_compression, true);
}

void from_remote_trigger(void)
{
	struct list_head *tmp;
	int count = 0;

	_make_alive();

	down_read(&peer_lock);
	for (tmp = peer_anchor.next; tmp != &peer_anchor; tmp = tmp->next) {
		struct mars_peerinfo *peer = container_of(tmp, struct mars_peerinfo, peer_head);
		peer->from_remote_trigger = true;
		count++;
	}
	up_read(&peer_lock);

	MARS_DBG("got trigger for %d peers\n", count);
	wake_up_interruptible_all(&remote_event);
}
EXPORT_SYMBOL_GPL(from_remote_trigger);

static
void __mars_remote_trigger(bool do_all)
{
	struct list_head *tmp;
	int count = 0;

	down_read(&peer_lock);
	for (tmp = peer_anchor.next; tmp != &peer_anchor; tmp = tmp->next) {
		struct mars_peerinfo *peer = container_of(tmp, struct mars_peerinfo, peer_head);
		/* skip some peers when requested */
		if (!do_all && !peer->do_communicate)
			continue;
		peer->to_remote_trigger = true;
		count++;
	}
	up_read(&peer_lock);

	MARS_DBG("triggered %d peers\n", count);
	wake_up_interruptible_all(&remote_event);
}

static
void __mars_full_trigger(int mode)
{
	struct list_head *tmp;
	int count = 0;

	down_read(&peer_lock);
	for (tmp = peer_anchor.next; tmp != &peer_anchor; tmp = tmp->next) {
		struct mars_peerinfo *peer = container_of(tmp, struct mars_peerinfo, peer_head);

		if (mode & 8)
			peer->do_entire_once = true;
		count++;
	}
	up_read(&peer_lock);

	MARS_DBG("full trigger %d peers\n", count);
	wake_up_interruptible_all(&remote_event);
}

static
bool is_shutdown(void)
{
	int used = atomic_read(&global_mshadow_count);

	if (used  > 0) {
		MARS_INF("global shutdown delayed: there are %d buffers in use, occupying %ld bytes\n", used, atomic64_read(&global_mshadow_used));
		return false;
	}
	used = atomic_read(&mars_global_io_flying);
	if (used <= 0)
		return true;

	MARS_INF("global shutdown delayed: there are %d IO requests flying\n", used);
	return false;
}

///////////////////////////////////////////////////////////////////////

// helpers for worker functions

static
void activate_peer(struct mars_rotate *rot, const char *peer_name)
{
	struct mars_peerinfo *peer;

	if (unlikely(!peer_name))
		return;

	peer = find_peer(peer_name);
	if (peer) {
		peer->do_communicate = true;
		peer->do_additional = false;
		if (peer->doing_additional) {
			peer->doing_additional = false;
			mars_running_additional_peers--;
		}
	}
}

static int _kill_peer(struct mars_global *global, struct mars_peerinfo *peer)
{
	LIST_HEAD(tmp_list);

	if (!peer) {
		return 0;
	}

	down_write(&peer_lock);
	if (!list_empty(&peer->peer_head))
		peer_count--;
	list_del_init(&peer->peer_head);
	up_write(&peer_lock);

	MARS_INF("stopping peer thread...\n");
	if (peer->peer_thread) {
		brick_thread_stop(peer->peer_thread);
		peer->peer_thread = NULL;
		peer->do_communicate = false;
		peer->do_additional = false;
	}

	mutex_lock(&peer->peer_lock);
	list_replace_init(&peer->remote_dent_list, &tmp_list);
	mutex_unlock(&peer->peer_lock);

	mars_free_dent_all(NULL, &tmp_list);
	if (peer->doing_additional) {
		peer->doing_additional = false;
		mars_running_additional_peers--;
	}
	brick_string_free(peer->peer);
	brick_string_free(peer->peer_dir_list);
	return 0;
}

static
void peer_destruct(void *_peer)
{
	struct mars_peerinfo *peer = _peer;
	if (likely(peer))
		_kill_peer(peer->global, peer);
}

static
char * make_peer_dir_list(char *mypeer)
{
	char *res;

	res = path_make(
			"|/mars/defaults-%s"
			"|/mars/actual-%s",
			mypeer,
			mypeer
			);
	return res;
}

static
int _make_peer(struct mars_global *global, struct mars_dent *dent)
{
	static int serial = 0;
	struct mars_peerinfo *peer;
	char *mypeer;
	char *parent_path;
	char *feature_path;
	char *feature_str;
	int status = 0;

	if (!global || !dent || !dent->new_link || !dent->d_parent || !(parent_path = dent->d_parent->d_path)) {
		MARS_DBG("cannot work\n");
		return 0;
	}
	mypeer = dent->d_rest;
	if (!mypeer) {
		status = _parse_args(dent, dent->new_link, 1);
		if (status < 0)
			goto done;
		mypeer = dent->d_argv[0];
	}

	MARS_DBG("peer '%s'\n", mypeer);
	if (!dent->d_private) {
		dent->d_private = brick_zmem_alloc(sizeof(struct mars_peerinfo));
		if (!dent->d_private) {
			MARS_ERR("no memory for peer structure\n");
			status = -ENOMEM;
			goto done;
		}
		dent->d_private_destruct = peer_destruct;
		peer = dent->d_private;
		peer->global = global;
		peer->peer = brick_strdup(mypeer);
		peer->maxdepth = 2;

		peer->peer_dir_list = make_peer_dir_list(mypeer);

		peer->features_version = 0;
		peer->strategy_version = 0;
		peer->available_mask = 0;

		mutex_init(&peer->peer_lock);
		INIT_LIST_HEAD(&peer->peer_head);
		INIT_LIST_HEAD(&peer->remote_dent_list);

		/* always trigger on peer startup */
		peer->from_remote_trigger = true;
		peer->to_remote_trigger = true;

		down_write(&peer_lock);
		list_add_tail(&peer->peer_head, &peer_anchor);
		peer_count++;
		up_write(&peer_lock);
	}

	peer = dent->d_private;

	/* Determine remote features and digest mask */
	feature_path = path_make("/mars/features-%s", mypeer);
	feature_str = mars_readlink(feature_path);
	if (feature_str) {
		sscanf(feature_str, "%d,%d,0x%x",
		       &peer->features_version,
		       &peer->strategy_version,
		       &peer->available_mask);
	}
	/* else/anyway: treat missing features as 0 = worst case */
	if (peer->features_version < 3) {
		peer->strategy_version = 0;
		peer->available_mask = 0;
	}

	brick_string_free(feature_path);
	brick_string_free(feature_str);

	/* at least one digest must remain usable */
	peer->available_mask |= MREF_CHKSUM_MD5_OLD;
	_tmp_digest_mask &= peer->available_mask;
	_tmp_compression_mask &= peer->available_mask;
	if (peer->features_version < _tmp_features_version)
		_tmp_features_version = peer->features_version;
	if (peer->strategy_version < _tmp_strategy_version)
		_tmp_strategy_version = peer->strategy_version;

	// create or stop communication thread when necessary
	if (peer->do_communicate | peer->do_additional) {
		/* Peers may terminate unexpectedly on their own */
		if (unlikely(peer->has_terminated && peer->peer_thread)) {
			brick_thread_stop(peer->peer_thread);
			peer->peer_thread = NULL;
		}
		if (!peer->peer_thread && mars_net_is_alive) {
			peer->to_terminate = false;
			peer->has_terminated = false;
			peer->peer_thread = brick_thread_create(peer_thread, peer, "mars_peer%d", serial++);
			if (unlikely(!peer->peer_thread)) {
				MARS_ERR("cannot start peer thread\n");
				return -1;
			}
			MARS_DBG("started peer thread\n");
		}
	} else if (peer->peer_thread) {
		peer->to_terminate = true;
		if (peer->has_terminated) {
			brick_thread_stop(peer->peer_thread);
			peer->peer_thread = NULL;
		}
	}

	/* This must be called by the main thread in order to
	 * avoid nasty races.
	 * The peer thread does nothing but fetching the dent list.
	 */
	status = run_bones(peer);

done:
	return status;
}

static int kill_scan(void *buf, struct mars_dent *dent)
{
	struct mars_global *global = buf;
	struct mars_peerinfo *peer = dent->d_private;
	int res;

	if (!global || global->global_power.button || !peer) {
		return 0;
	}
	dent->d_private = NULL;
	res = _kill_peer(global, peer);
	brick_mem_free(peer);
	return res;
}

static int make_scan(void *buf, struct mars_dent *dent)
{
	MARS_DBG("path = '%s' peer = '%s'\n", dent->d_path, dent->d_rest);
	// don't connect to myself
	if (!strcmp(dent->d_rest, my_id())) {
		return 0;
	}
	return _make_peer(buf, dent);
}


static
int kill_any(void *buf, struct mars_dent *dent)
{
	struct mars_global *global = buf;
	struct list_head *tmp;

	if (global->global_power.button || !is_shutdown()) {
		return 0;
	}

	for (tmp = dent->brick_list.next; tmp != &dent->brick_list; tmp = tmp->next) {
		struct mars_brick *brick = container_of(tmp, struct mars_brick, dent_brick_link);
		if (brick->nr_outputs > 0 && brick->outputs[0] && brick->outputs[0]->nr_connected) {
			MARS_DBG("cannot kill dent '%s' because brick '%s' is wired\n", dent->d_path, brick->brick_path);
			return 0;
		}
	}

	MARS_DBG("killing dent = '%s'\n", dent->d_path);
	mars_kill_dent(global, dent);
	return 1;
}

///////////////////////////////////////////////////////////////////////

// handlers / helpers for logfile rotation

static
void _create_new_logfile(const char *path)
{
	struct file *f;
	const int flags = O_RDWR | O_CREAT | O_EXCL;
	const int prot = 0600;
	mm_segment_t oldfs;

	oldfs = get_fs();
	set_fs(get_ds());
	f = filp_open(path, flags, prot);
	set_fs(oldfs);
	if (IS_ERR(f)) {
		int err = PTR_ERR(f);
		if (err == -EEXIST) {
			MARS_INF("logfile '%s' already exists\n", path);
		} else {
			MARS_ERR("could not create logfile '%s' status = %d\n", path, err);
		}
	} else {
		MARS_DBG("created empty logfile '%s'\n", path);
		mars_sync();
		_crashme(10, false);
		filp_close(f, NULL);
		mars_trigger();
	}
}

static
const char *__get_link_path(const char *_linkpath, const char **linkpath)
{
	const char *res = ordered_readlink(_linkpath);

	if (linkpath)
		*linkpath = _linkpath;
	else
		brick_string_free(_linkpath);
	return res;
}

static
const char *get_replaylink(const char *parent_path, const char *host, const char **linkpath)
{
	const char * _linkpath = path_make("%s/replay-%s", parent_path, host);

	return __get_link_path(_linkpath, linkpath);
}

static
const char *get_versionlink(const char *parent_path, int seq, const char *host, const char **linkpath)
{
	const char * _linkpath = path_make("%s/version-%09d-%s", parent_path, seq, host);

	return __get_link_path(_linkpath, linkpath);
}

static inline
int _get_tolerance(struct mars_rotate *rot)
{
	if (rot->is_log_damaged)
		return REPLAY_TOLERANCE;

	/* Do not insist on completeness of logfiles when pause-fetch
	 * is given, important for primary --force when the old primary
	 * is unreachable (or even dead forever).
	 */
	if (rot->todo_primary &&
	    !_check_allow(rot->global, rot->parent_path, "connect"))
		return REPLAY_TOLERANCE;

	return 0;
}

static
bool is_switchover_possible(struct mars_rotate *rot, const char *old_log_path, const char *new_log_path, int replay_tolerance, bool skip_new)
{
	const char *old_log_name = old_log_path + skip_dir(old_log_path);
	const char *new_log_name = new_log_path + skip_dir(new_log_path);
	const char *old_host = NULL;
	const char *new_host = NULL;
	const char *own_versionlink_path = NULL;
	const char *old_versionlink_path = NULL;
	const char *new_versionlink_path = NULL;
	const char *own_versionlink = NULL;
	const char *old_versionlink = NULL;
	const char *new_versionlink = NULL;
	const char *own_replaylink_path = NULL;
	const char *own_replaylink = NULL;
	loff_t own_r_val;
	loff_t own_v_val;
	int old_log_seq;
	int new_log_seq;
	int own_r_offset;
	int own_v_offset;
	int own_r_len;
	int own_v_len;
	int len1;
	int len2;
	int offs2;

	bool res = false;

	MARS_DBG("old_log = '%s' new_log = '%s' toler = %d skip_new = %d\n",
		 old_log_path, new_log_path, replay_tolerance, skip_new);

	// check precondition: is split brain already for sure?
	if (unlikely(rot->has_double_logfile)) {
		MARS_WRN_TO(rot->log_say, "SPLIT BRAIN detected: multiple logfiles with sequence number %d exist\n", rot->next_relevant_log->d_serial);
		make_rot_msg(rot, "err-splitbrain-detected", "SPLIT BRAIN detected: multiple logfiles with sequence number %d exist\n", rot->next_relevant_log->d_serial);
		goto done;
	}

	// parse the names
	if (unlikely(!parse_logfile_name(old_log_name, &old_log_seq, &old_host))) {
		make_rot_msg(rot, "err-bad-log-name", "logfile name '%s' cannot be parsed", old_log_name);
		goto done;
	}
	if (unlikely(!parse_logfile_name(new_log_name, &new_log_seq, &new_host))) {
		make_rot_msg(rot, "err-bad-log-name", "logfile name '%s' cannot be parsed", new_log_name);
		goto done;
	}

	// check: are the sequence numbers contiguous?
	if (unlikely(new_log_seq != old_log_seq + 1)) {
		MARS_ERR_TO(rot->log_say, "logfile sequence numbers are not contiguous (%d != %d + 1), old_log_path='%s' new_log_path='%s'\n", new_log_seq, old_log_seq, old_log_path, new_log_path);
		make_rot_msg(rot, "err-log-not-contiguous", "logfile sequence numbers are not contiguous (%d != %d + 1) old_log_path='%s' new_log_path='%s'", new_log_seq, old_log_seq, old_log_path, new_log_path);
		goto done;
	}

	// fetch all the versionlinks and test for their existence.
	own_versionlink = get_versionlink(rot->parent_path, old_log_seq, my_id(), &own_versionlink_path);
	if (unlikely(!own_versionlink || !own_versionlink[0])) {
		MARS_ERR_TO(rot->log_say, "cannot read my own versionlink '%s'\n", SAFE_STR(own_versionlink_path));
		make_rot_msg(rot, "err-versionlink-not-readable", "cannot read my own versionlink '%s'", SAFE_STR(own_versionlink_path));
		goto done;
	}
	old_versionlink = get_versionlink(rot->parent_path, old_log_seq, old_host, &old_versionlink_path);
	if (unlikely(!old_versionlink || !old_versionlink[0])) {
		MARS_ERR_TO(rot->log_say, "cannot read old versionlink '%s'\n", SAFE_STR(old_versionlink_path));
		make_rot_msg(rot, "err-versionlink-not-readable", "cannot read old versionlink '%s'", SAFE_STR(old_versionlink_path));
		goto done;
	}
	new_versionlink = get_versionlink(rot->parent_path, new_log_seq,
					  new_host, &new_versionlink_path);
	if (rot->todo_primary &&
	    !strcmp(old_host, my_id()) &&
	    strcmp(new_host, my_id())) {
		MARS_INF_TO(rot->log_say,
			    "As a designated primary, I am refusing switchover from my own logfile '%s' to foreign logfile '%s' and versionlink '%s'.\n",
			    SAFE_STR(old_log_path),
			    SAFE_STR(new_log_path),
			    SAFE_STR(new_versionlink_path));
		make_rot_msg(rot, "inf-log-foreign-denied",
			     "denied switchover from own logfile '%s' to foreign '%s'",
			     SAFE_STR(old_log_path),
			     SAFE_STR(new_log_path));
		goto done;
	}
	if (!skip_new && strcmp(new_host, my_id())) {
		if (unlikely(!new_versionlink || !new_versionlink[0])) {
			MARS_INF_TO(rot->log_say, "new versionlink '%s' does not yet exist, we must wait for it.\n", SAFE_STR(new_versionlink_path));
			make_rot_msg(rot, "inf-versionlink-not-yet-exist", "we must wait for new versionlink '%s'", SAFE_STR(new_versionlink_path));
			goto done;
		}
	}

	// check: are the versionlinks correct?
	if (unlikely(strcmp(own_versionlink, old_versionlink))) {
		MARS_INF_TO(rot->log_say, "old logfile is not yet completeley transferred, own_versionlink '%s' -> '%s' != old_versionlink '%s' -> '%s'\n", own_versionlink_path, own_versionlink, old_versionlink_path, old_versionlink);
		make_rot_msg(rot, "inf-versionlink-not-equal", "old logfile is not yet completeley transferred (own_versionlink '%s' -> '%s' != old_versionlink '%s' -> '%s')", own_versionlink_path, own_versionlink, old_versionlink_path, old_versionlink);
		goto done;
	}

	// check: did I fully replay my old logfile data?
	own_replaylink = get_replaylink(rot->parent_path, my_id(), &own_replaylink_path);
	if (unlikely(!own_replaylink || !own_replaylink[0])) {
		MARS_ERR_TO(rot->log_say, "cannot read my own replaylink '%s'\n", SAFE_STR(own_replaylink_path));
		goto done;
	}
	own_r_len    = skip_part(own_replaylink);
	own_v_offset = skip_part(own_versionlink);
	if (unlikely(!own_versionlink[own_v_offset++])) {
		MARS_ERR_TO(rot->log_say, "own version link '%s' -> '%s' is malformed\n", own_versionlink_path, own_versionlink);
		make_rot_msg(rot, "err-replaylink-not-readable", "own version link '%s' -> '%s' is malformed", own_versionlink_path, own_versionlink);
		goto done;
	}
	own_v_len    = skip_part(own_versionlink + own_v_offset);
	if (unlikely(own_r_len != own_v_len ||
		     strncmp(own_replaylink, own_versionlink + own_v_offset, own_r_len))) {
		MARS_ERR_TO(rot->log_say, "internal problem: logfile name mismatch between '%s' and '%s'\n", own_replaylink, own_versionlink);
		make_rot_msg(rot, "err-bad-log-name", "internal problem: logfile name mismatch between '%s' and '%s'", own_replaylink, own_versionlink);
		goto done;
	}
	if (unlikely(!own_replaylink[own_r_len])) {
		MARS_ERR_TO(rot->log_say, "own replay link '%s' -> '%s' is malformed\n", own_replaylink_path, own_replaylink);
		make_rot_msg(rot, "err-replaylink-not-readable", "own replay link '%s' -> '%s' is malformed", own_replaylink_path, own_replaylink);
		goto done;
	}
	own_r_offset = own_r_len + 1;
	if (unlikely(!own_versionlink[own_v_len])) {
		MARS_ERR_TO(rot->log_say, "own version link '%s' -> '%s' is malformed\n", own_versionlink_path, own_versionlink);
		make_rot_msg(rot, "err-versionlink-not-readable", "own version link '%s' -> '%s' is malformed", own_versionlink_path, own_versionlink);
		goto done;
	}
	own_v_offset += own_r_len + 1;
	own_r_len    = skip_part(own_replaylink  + own_r_offset);
	own_v_len    = skip_part(own_versionlink + own_v_offset);
	own_r_val = own_v_val = 0;
	if (sscanf(own_replaylink + own_r_offset, "%lld", &own_r_val) != 1) {
		MARS_ERR_TO(rot->log_say, "own replay link '%s' -> '%s' is malformed\n", own_replaylink_path, own_replaylink);
		make_rot_msg(rot, "err-replaylink-not-readable", "own replay link '%s' -> '%s' is malformed", own_replaylink_path, own_replaylink);
		goto done;
	}
	if (sscanf(own_versionlink + own_v_offset, "%lld", &own_v_val) != 1) {
		MARS_ERR_TO(rot->log_say, "own version link '%s' -> '%s' is malformed\n", own_versionlink_path, own_versionlink);
		make_rot_msg(rot, "err-versionlink-not-readable", "own version link '%s' -> '%s' is malformed", own_versionlink_path, own_versionlink);
		goto done;
	}
	if (unlikely(own_r_len > own_v_len || own_r_len + replay_tolerance < own_v_len)) {
		MARS_INF_TO(rot->log_say, "log replay is not yet finished: '%s' and '%s' are reporting different positions.\n", own_replaylink, own_versionlink);
		make_rot_msg(rot, "inf-replay-not-yet-finished", "log replay is not yet finished: '%s' and '%s' are reporting different positions", own_replaylink, own_versionlink);
		goto done;
	}

	// last check: is the new versionlink based on the old one?
	if (new_versionlink && new_versionlink[0]) {
		len1  = skip_sect(own_versionlink);
		offs2 = skip_sect(new_versionlink);
		if (unlikely(!new_versionlink[offs2++])) {
			MARS_ERR_TO(rot->log_say, "new version link '%s' -> '%s' is malformed\n", new_versionlink_path, new_versionlink);
			make_rot_msg(rot, "err-versionlink-not-readable", "new version link '%s' -> '%s' is malformed", new_versionlink_path, new_versionlink);
			goto done;
		}
		len2  = skip_sect(new_versionlink + offs2);
		if (unlikely(len1 != len2 ||
			     strncmp(own_versionlink, new_versionlink + offs2, len1))) {
			MARS_WRN_TO(rot->log_say, "VERSION MISMATCH old '%s' -> '%s' new '%s' -> '%s' ==(%d,%d) ===> check for SPLIT BRAIN!\n", own_versionlink_path, own_versionlink, new_versionlink_path, new_versionlink, len1, len2);
			make_rot_msg(rot, "err-splitbrain-detected", "VERSION MISMATCH old '%s' -> '%s' new '%s' -> '%s' ==(%d,%d) ===> check for SPLIT BRAIN", own_versionlink_path, own_versionlink, new_versionlink_path, new_versionlink, len1, len2);
			goto done;
		}
	}

	// report success
	res = true;
	MARS_DBG("VERSION OK '%s' -> '%s'\n", own_versionlink_path, own_versionlink);
	mars_trigger();
	mars_remote_trigger();

 done:
	brick_string_free(old_host);
	brick_string_free(new_host);
	brick_string_free(own_versionlink_path);
	brick_string_free(old_versionlink_path);
	brick_string_free(new_versionlink_path);
	brick_string_free(own_versionlink);
	brick_string_free(old_versionlink);
	brick_string_free(new_versionlink);
	brick_string_free(own_replaylink_path);
	brick_string_free(own_replaylink);
	return res;
}

static
void rot_destruct(void *_rot)
{
	struct mars_rotate *rot = _rot;
	if (likely(rot)) {
		down_write(&rot_sem);
		list_del_init(&rot->rot_head);
		up_write(&rot_sem);
		write_info_links(rot);
		del_channel(rot->log_say);
		rot->log_say = NULL;
		brick_string_free(rot->fetch_path);
		brick_string_free(rot->fetch_peer);
		brick_string_free(rot->avoid_peer);
		brick_string_free(rot->preferred_peer);
		brick_string_free(rot->parent_path);
		brick_string_free(rot->parent_rest);
		brick_string_free(rot->fetch_next_origin);
		rot->fetch_path = NULL;
		rot->fetch_peer = NULL;
		rot->preferred_peer = NULL;
		rot->parent_path = NULL;
		rot->parent_rest = NULL;
		rot->fetch_next_origin = NULL;
		clear_vals(rot->msgs);
	}
}

/* This must be called once at every round of logfile checking.
 */
static
int make_log_init(void *buf, struct mars_dent *dent)
{
	struct mars_global *global = buf;
	struct mars_dent *parent = dent->d_parent;
	struct mars_brick *bio_brick;
	struct mars_brick *aio_brick;
	struct mars_brick *trans_brick;
	struct mars_rotate *rot = parent->d_private;
	struct mars_dent *replay_link;
	struct mars_dent *aio_dent;
	struct mars_output *output;
	const char *parent_path;
	const char *replay_path = NULL;
	const char *aio_path = NULL;
	loff_t logrot_limit;
	bool switch_on;
	int status = 0;

	if (!global->global_power.button) {
		goto done;
	}
	status = -EINVAL;
	CHECK_PTR(parent, done);
	parent_path = parent->d_path;
	CHECK_PTR(parent_path, done);

	if (!rot) {
		const char *fetch_path;
		rot = brick_zmem_alloc(sizeof(struct mars_rotate));
		if (unlikely(!rot)) {
			MARS_ERR("cannot allocate rot structure\n");
			status = -ENOMEM;
			goto done;
		}
		mutex_init(&rot->inf_mutex);
		fetch_path = path_make("%s/logfile-update", parent_path);
		if (unlikely(!fetch_path)) {
			MARS_ERR("cannot create fetch_path\n");
			brick_mem_free(rot);
			status = -ENOMEM;
			goto done;
		}
		rot->fetch_path = fetch_path;
		rot->global = global;
		parent->d_private = rot;
		parent->d_private_destruct = rot_destruct;
		assign_keys(rot->msgs, rot_keys);

		down_write(&rot_sem);
		list_add_tail(&rot->rot_head, &rot_anchor);
		up_write(&rot_sem);
	}

	rot->replay_link = NULL;
	rot->aio_dent = NULL;
	rot->aio_brick = NULL;
	rot->first_log = NULL;
	rot->last_log = NULL;
	rot->relevant_log = NULL;
	rot->relevant_serial = 0;
	rot->relevant_brick = NULL;
	rot->next_relevant_log = NULL;
	rot->prev_log = NULL;
	rot->next_log = NULL;
	brick_string_free(rot->fetch_next_origin);
	rot->fetch_next_origin = NULL;
	rot->max_sequence = 0;
	// reset the split brain detector only when conflicts have gone for a number of rounds
	if (rot->split_brain_serial && rot->split_brain_round++ > 3)
		rot->split_brain_serial = 0;
	rot->fetch_next_serial = 0;
	rot->has_error = false;
	rot->has_symlinks = true;
	brick_string_free(rot->preferred_peer);
	rot->preferred_peer = NULL;

	activate_peer(rot, dent->d_rest);

	if (dent->new_link)
		sscanf(dent->new_link, "%lld", &rot->dev_size);
	if (!rot->parent_path) {
		rot->parent_path = brick_strdup(parent_path);
		rot->parent_rest = brick_strdup(parent->d_rest);
	}

	if (unlikely(!rot->log_say)) {
		char *name = path_make("%s/logstatus-%s", parent_path, my_id());
		if (likely(name)) {
			rot->log_say = make_channel(name, true);
			brick_string_free(name);
		}
	}
	
	write_info_links(rot);

	/* Fetch the replay status symlink.
	 * It must exist, and its value will control everything.
	 */
	replay_path = path_make("%s/replay-%s", parent_path, my_id());
	if (unlikely(!replay_path)) {
		MARS_ERR("cannot make path\n");
		status = -ENOMEM;
		goto done;
	}

	replay_link = (void*)mars_find_dent(global, replay_path);
	rot->repair_log_seq = -1;
	if (unlikely(!replay_link || !replay_link->new_link)) {
		MARS_DBG("replay status symlink '%s' does not exist (%p)\n", replay_path, replay_link);
		rot->allow_update = false;
		status = -ENOENT;
		goto done;
	}

	status = _parse_args(replay_link, replay_link->new_link, 3);
	if (unlikely(status < 0)) {
		goto done;
	}
	parse_logfile_name(replay_link->d_argv[0],
			   &rot->repair_log_seq, NULL);

	rot->replay_link = replay_link;

	/* Fetch AIO dentry of the logfile.
	 */
	if (rot->trans_brick) {
		struct trans_logger_input *trans_input = rot->trans_brick->inputs[rot->trans_brick->old_input_nr];
		if (trans_input && trans_input->is_operating) {
			aio_path = path_make("%s/log-%09d-%s", parent_path, trans_input->inf.inf_sequence, trans_input->inf.inf_host);
			MARS_DBG("using logfile '%s' from trans_input %d (new=%d)\n", SAFE_STR(aio_path), rot->trans_brick->old_input_nr, rot->trans_brick->log_input_nr);
		}
	}
	if (!aio_path) {
		aio_path = path_make("%s/%s", parent_path, replay_link->d_argv[0]);
		MARS_DBG("using logfile '%s' from replay symlink\n", SAFE_STR(aio_path));
	}
	if (unlikely(!aio_path)) {
		MARS_ERR("cannot make path\n");
		status = -ENOMEM;
		goto done;
	}

	aio_dent = (void*)mars_find_dent(global, aio_path);
	if (unlikely(!aio_dent)) {
		MARS_DBG("logfile '%s' does not exist\n", aio_path);
		status = -ENOENT;
		if (rot->todo_primary && !rot->is_primary && !rot->old_is_primary) {
			int offset = strlen(aio_path) - strlen(my_id());
			if (offset > 0 && aio_path[offset-1] == '-' && !strcmp(aio_path + offset, my_id())) {
				// try to create an empty logfile
				_create_new_logfile(aio_path);
			}
		}
		goto done;
	}
	rot->aio_dent = aio_dent;

	// check whether attach is allowed
	switch_on = _check_allow(global, parent->d_path, "attach");
	if (switch_on && rot->res_shutdown) {
		MARS_ERR("cannot start transaction logger: resource shutdown mode is currently active\n");
		switch_on = false;
	}

	/* Fetch / make the AIO brick instance
	 */
	aio_brick =
		make_brick_all(global,
			       aio_dent,
			       _set_aio_params,
			       NULL,
			       aio_path,
			       (const struct generic_brick_type*)&aio_brick_type,
			       (const struct generic_brick_type*[]){},
			       rot->trans_brick || switch_on ? 2 : -1, // disallow detach when trans_logger is present
			       "%s",
			       (const char *[]){},
			       0,
			       aio_path);
	rot->aio_brick = (void*)aio_brick;
	status = 0;
	if (unlikely(!aio_brick || !aio_brick->power.led_on)) {
		goto done; // this may happen in case of detach
	}
	bio_brick = rot->bio_brick;
	if (unlikely(!bio_brick || !bio_brick->power.led_on)) {
		goto done; // this may happen in case of detach
	}

	/* Fetch the actual logfile size
	 */
	output = aio_brick->outputs[0];
	status = output->ops->mars_get_info(output, &rot->aio_info);
	if (status < 0) {
		MARS_ERR("cannot get info on '%s'\n", aio_path);
		goto done;
	}
	MARS_DBG("logfile '%s' size = %lld\n", aio_path, rot->aio_info.current_size);

	logrot_limit = raw_total_space / (1024ll * 1024 / 32);
	if (logrot_limit <= 0)
		logrot_limit = 1;
	if (logrot_limit > global_logrot_auto)
		logrot_limit = global_logrot_auto;
	if (rot->is_primary &&
	    logrot_limit > 0 &&
	    unlikely(rot->aio_info.current_size >= logrot_limit * 1024 * 1024 * 1024)) {
		char *new_path = path_make("%s/log-%09d-%s", parent_path, aio_dent->d_serial + 1, my_id());
		if (likely(new_path && !mars_find_dent(global, new_path))) {
			MARS_INF("old logfile size = %lld, creating new logfile '%s'\n", rot->aio_info.current_size, new_path);
			_create_new_logfile(new_path);
		}
		brick_string_free(new_path);
	}

	/* Fetch / make the transaction logger.
	 * We deliberately "forget" to connect the log input here.
	 * Will be carried out later in make_log_step().
	 * The final switch-on will be started in make_log_finalize().
	 */
	trans_brick =
		make_brick_all(global,
			       replay_link,
			       _set_trans_params,
			       NULL,
			       aio_path,
			       (const struct generic_brick_type*)&trans_logger_brick_type,
			       (const struct generic_brick_type*[]){NULL},
			       1, // create when necessary, but leave in current state otherwise
			       "%s/replay-%s", 
			       (const char *[]){"%s/data-%s"},
			       1,
			       parent_path,
			       my_id(),
			       parent_path,
			       my_id());
	if (!rot->trans_brick && trans_brick)
		clear_vals(rot->msgs);
	rot->trans_brick = (void*)trans_brick;
	status = -ENOENT;
	if (!trans_brick) {
		goto done;
	}
	rot->trans_brick->kill_ptr = (void**)&rot->trans_brick;
	rot->trans_brick->replay_limiter = &rot->replay_limiter;
	/* For safety, default is to try an (unnecessary) replay in case
	 * something goes wrong later.
	 */
	rot->replay_mode = true;

	status = 0;

done:
	brick_string_free(aio_path);
	brick_string_free(replay_path);
	return status;
}

static
bool _next_is_acceptable(struct mars_rotate *rot, struct mars_dent *old_dent, struct mars_dent *new_dent)
{
	/* Primaries are never allowed to consider logfiles not belonging to them.
	 * Secondaries need this for replay, unfortunately.
	 */
	if ((rot->is_primary | rot->old_is_primary) ||
	    (rot->trans_brick && rot->trans_brick->power.led_on && !rot->trans_brick->replay_mode)) {
		if (new_dent->new_stat.size) {
			MARS_WRN("logrotate impossible, '%s' size = %lld\n", new_dent->d_rest, new_dent->new_stat.size);
			return false;
		}
		if (strcmp(new_dent->d_rest, my_id())) {
			MARS_WRN("logrotate impossible, '%s'\n", new_dent->d_rest);
			return false;
		}
	} else {
		/* Only secondaries should check for contiguity,
		 * primaries sometimes need holes for emergency mode.
		 */
		if (new_dent->d_serial != old_dent->d_serial + 1)
			return false;
	}
	return true;
}

/* Note: this is strictly called in d_serial order.
 * This is important!
 */
static
int make_log_step(void *buf, struct mars_dent *dent)
{
	struct mars_global *global = buf;
	struct mars_dent *parent = dent->d_parent;
	struct mars_rotate *rot;
	struct trans_logger_brick *trans_brick;
	struct mars_dent *prev_log;
	int replay_log_nr = 0;
	int status = -EINVAL;

	CHECK_PTR(parent, err);
	rot = parent->d_private;
	if (!rot)
		goto err;
	CHECK_PTR(rot, err);

	status = 0;
	trans_brick = rot->trans_brick;
	if (!global->global_power.button || !dent->d_parent || !trans_brick || rot->has_error) {
		MARS_DBG("nothing to do rot_error = %d\n", rot->has_error);
		goto done;
	}

	/* Check for consecutiveness of logfiles
	 */
	prev_log = rot->next_log;
	if (prev_log && prev_log->d_serial + 1 != dent->d_serial &&
	    (!rot->replay_link || !rot->replay_link->d_argv[0] ||
	     sscanf(rot->replay_link->d_argv[0], "log-%d", &replay_log_nr) != 1 ||
	     dent->d_serial > replay_log_nr)) {
		MARS_WRN_TO(rot->log_say, "transaction logs are not consecutive at '%s' (%d ~> %d)\n", dent->d_path, prev_log->d_serial, dent->d_serial);
		make_rot_msg(rot, "wrn-log-consecutive", "transaction logs are not consecutive at '%s' (%d ~> %d)\n", dent->d_path, prev_log->d_serial, dent->d_serial);
	}

	if (dent->d_serial > rot->max_sequence) {
		rot->max_sequence = dent->d_serial;
	}

	if (!rot->first_log)
		rot->first_log = dent;

	/* Skip any logfiles after the relevant one.
	 * This should happen only when replaying multiple logfiles
	 * in sequence, or when starting a new logfile for writing.
	 */
	status = 0;
	if (rot->relevant_log) {
		if (!rot->next_relevant_log) {
			if (unlikely(dent->d_serial == rot->relevant_log->d_serial)) {
				// always prefer the one created by myself
				if (!strcmp(rot->relevant_log->d_rest, my_id())) {
					MARS_WRN("PREFER LOGFILE '%s' in front of '%s'\n",
						 rot->relevant_log->d_path, dent->d_path);
				} else if (!strcmp(dent->d_rest, my_id())) {
					MARS_WRN("PREFER LOGFILE '%s' in front of '%s'\n",
						 dent->d_path, rot->relevant_log->d_path);
					rot->relevant_log = dent;
				} else {
					rot->has_double_logfile = true;
					MARS_ERR("DOUBLE LOGFILES '%s' '%s'\n",
						 dent->d_path, rot->relevant_log->d_path);
				}
			} else if (_next_is_acceptable(rot, rot->relevant_log, dent)) {
				rot->next_relevant_log = dent;
			} else if (rot->last_log && dent->d_serial > rot->last_log->d_serial + 5) {
				rot->has_hole_logfile = true;
			}
		} else { // check for double logfiles => split brain
			if (unlikely(dent->d_serial == rot->next_relevant_log->d_serial)) {
				// always prefer the one created by myself
				if (!strcmp(rot->next_relevant_log->d_rest, my_id())) {
					MARS_WRN("PREFER LOGFILE '%s' in front of '%s'\n", rot->next_relevant_log->d_path, dent->d_path);
				} else if (!strcmp(dent->d_rest, my_id())) {
					MARS_WRN("PREFER LOGFILE '%s' in front of '%s'\n", dent->d_path, rot->next_relevant_log->d_path);
					rot->next_relevant_log = dent;
				} else {
					rot->has_double_logfile = true;
					MARS_ERR("DOUBLE LOGFILES '%s' '%s'\n", dent->d_path, rot->next_relevant_log->d_path);
				}
			} else if (dent->d_serial > rot->next_relevant_log->d_serial + 5) {
				rot->has_hole_logfile = true;
			}

		}
		MARS_DBG("next_relevant_log = %p\n", rot->next_relevant_log);
		goto ok;
	}

	/* Preconditions
	 */
	if (!rot->replay_link || !rot->aio_dent || !rot->aio_brick) {
		MARS_DBG("nothing to do on '%s'\n", dent->d_path);
		goto ok;
	}
	rot->last_log = dent;

	/* Remember the relevant log.
	 */
	if (!rot->relevant_log && rot->aio_dent->d_serial == dent->d_serial) {
		rot->relevant_serial = dent->d_serial;
		rot->relevant_log = dent;
		rot->has_double_logfile = false;
		rot->has_hole_logfile = false;
	}

ok:
	/* All ok: switch over the indicators.
	 */
	MARS_DBG("next_log = '%s'\n", dent->d_path);
	rot->prev_log = rot->next_log;
	rot->next_log = dent;

done:
	if (status < 0) {
		MARS_DBG("rot_error status = %d\n", status);
		rot->has_error = true;
	}
err:
	return status;
}


/* Internal helper. Return codes:
 * ret < 0 : error
 * ret == 0 : not relevant
 * ret == 1 : relevant, no transaction replay, switch to the next
 * ret == 2 : relevant for transaction replay
 * ret == 3 : relevant for appending
 */
static
int _check_logging_status(struct mars_rotate *rot, int *log_nr, long long *oldpos_start, long long *oldpos_end, long long *newpos)
{
	struct mars_dent *dent = rot->relevant_log;
	struct mars_dent *parent;
	struct mars_global *global = NULL;
	const char *vers_link = NULL;
	int status = 0;

	if (!dent)
		goto done;
	
	status = -EINVAL;
	parent = dent->d_parent;
	CHECK_PTR(parent, done);
	global = rot->global;
	CHECK_PTR_NULL(global, done);
	CHECK_PTR(rot->replay_link, done);
	CHECK_PTR(rot->aio_brick, done);
	CHECK_PTR(rot->aio_dent, done);

	MARS_DBG("    dent = '%s'\n", dent->d_path);
	MARS_DBG("aio_dent = '%s'\n", rot->aio_dent->d_path);
	if (unlikely(strcmp(dent->d_path, rot->aio_dent->d_path))) {
		goto done;
	}

	if (sscanf(rot->replay_link->d_argv[0], "log-%d", log_nr) != 1) {
		MARS_ERR_TO(rot->log_say, "replay link has malformed logfile number '%s'\n", rot->replay_link->d_argv[0]);
		goto done;
	}
	if (sscanf(rot->replay_link->d_argv[1], "%lld", oldpos_start) != 1) {
		MARS_ERR_TO(rot->log_say, "replay link has bad start position argument '%s'\n", rot->replay_link->d_argv[1]);
		goto done;
	}
	if (sscanf(rot->replay_link->d_argv[2], "%lld", oldpos_end) != 1) {
		MARS_ERR_TO(rot->log_say, "replay link has bad end position argument '%s'\n", rot->replay_link->d_argv[2]);
		goto done;
	}
	*oldpos_end += *oldpos_start;
	if (unlikely(*oldpos_end < *oldpos_start)) {
		MARS_ERR_TO(rot->log_say, "replay link end_pos %lld < start_pos %lld\n", *oldpos_end, *oldpos_start);
		// safety: use the smaller value, it does not hurt
		*oldpos_start = *oldpos_end;
		if (unlikely(*oldpos_start < 0))
			*oldpos_start = 0;
	}

	vers_link = get_versionlink(rot->parent_path, *log_nr, my_id(), NULL);
	if (vers_link && vers_link[0]) {
		long long vers_pos = 0;
		int offset = 0;
		int i;

		for (i = 0; i < 2; i++) {
			offset += skip_part(vers_link + offset);
			if (unlikely(!vers_link[offset++])) {
				MARS_ERR_TO(rot->log_say, "version link '%s' is malformed\n", vers_link);
				goto check_pos;
			}
		}

		sscanf(vers_link + offset, "%lld", &vers_pos);
		if (vers_pos < *oldpos_start) {
			MARS_WRN("versionlink has smaller startpos %lld < %lld\n",
				 vers_pos, *oldpos_start);
			/* for safety, take the minimum of both */
			*oldpos_start = vers_pos;
		} else if (vers_pos > *oldpos_start) {
			MARS_WRN("versionlink has greater startpos %lld > %lld\n",
				 vers_pos, *oldpos_start);
		}

	}
 check_pos:
	*newpos = rot->aio_info.current_size;

	if (unlikely(rot->aio_info.current_size < *oldpos_start)) {
		status = -EBADF;
		/* Allow primary --force even when logfiles are truncated / damaged.
		 */
		if (rot->todo_primary && !rot->is_primary &&
		    !rot->fetch_brick &&
		    !_check_allow(global, parent->d_path, "connect") &&
		    _check_allow(rot->global, rot->parent_path, "attach")) {
			MARS_WRN("FORCING transaction log '%s' %lld < %lld as finished\n",
				 rot->aio_dent->d_path,
				 rot->aio_info.current_size, *oldpos_start);
			status = 1;
		}
		goto done;
	}

	status = 0;
	if (rot->aio_info.current_size > *oldpos_start) {
		if ((rot->aio_info.current_size - *oldpos_start < _get_tolerance(rot) ||
		     (rot->log_is_really_damaged &&
		      rot->todo_primary &&
		      rot->relevant_log &&
		      strcmp(rot->relevant_log->d_rest, my_id()))) &&
		    (rot->todo_primary ||
		        (rot->relevant_log &&
		         rot->next_relevant_log &&
		         is_switchover_possible(rot, rot->relevant_log->d_path, rot->next_relevant_log->d_path, _get_tolerance(rot), false)))) {
			MARS_INF_TO(rot->log_say, "TOLERANCE: transaction log '%s' is treated as fully applied\n", rot->aio_dent->d_path);
			make_rot_msg(rot, "inf-replay-tolerance", "TOLERANCE: transaction log '%s' is treated as fully applied", rot->aio_dent->d_path);
			status = 1;
		} else {
			MARS_INF_TO(rot->log_say, "transaction log replay is necessary on '%s' from %lld to %lld (dirty region ends at %lld)\n", rot->aio_dent->d_path, *oldpos_start, rot->aio_info.current_size, *oldpos_end);
			status = 2;
		}
	} else if (rot->next_relevant_log) {
		MARS_INF_TO(rot->log_say, "transaction log '%s' is already applied, and the next one is available for switching\n", rot->aio_dent->d_path);
		status = 1;
	} else if (rot->todo_primary) {
		if (rot->aio_info.current_size > 0 || strcmp(dent->d_rest, my_id()) != 0) {
			MARS_INF_TO(rot->log_say, "transaction log '%s' is already applied (would be usable for appending at position %lld, but a fresh logfile will be used for safety reasons)\n", rot->aio_dent->d_path, *oldpos_end);
			status = 1;
		} else {
			MARS_INF_TO(rot->log_say, "empty transaction log '%s' is usable for me as a primary node\n", rot->aio_dent->d_path);
			status = 3;
		}
	} else {
		MARS_DBG("transaction log '%s' is the last one, currently fully applied\n", rot->aio_dent->d_path);
		status = 0;
	}

done:
	brick_string_free(vers_link);
	return status;
}


static
int _make_logging_status(struct mars_rotate *rot)
{
	struct mars_dent *dent = rot->relevant_log;
	struct mars_dent *parent;
	struct mars_dent *next_relevant_log;
	struct mars_global *global = NULL;
	struct trans_logger_brick *trans_brick;
	int log_nr = 0;
	loff_t start_pos = 0;
	loff_t dirty_pos = 0;
	loff_t end_pos = 0;
	int status = 0;

	if (!dent)
		goto done;

	status = -EINVAL;
	parent = dent->d_parent;
	CHECK_PTR(parent, done);
	global = rot->global;
	CHECK_PTR_NULL(global, done);

	status = 0;
	trans_brick = rot->trans_brick;
	if (!global->global_power.button || !trans_brick || rot->has_error) {
		MARS_DBG("nothing to do rot_error = %d\n", rot->has_error);
		goto done;
	}

	/* Find current logging status.
	 */
	status = _check_logging_status(rot, &log_nr, &start_pos, &dirty_pos, &end_pos);
	MARS_DBG("case = %d (todo_primary=%d is_primary=%d old_is_primary=%d)\n", status,  rot->todo_primary, rot->is_primary, rot->old_is_primary);
	if (status < 0) {
		goto done;
	}
	if (unlikely(start_pos < 0 || dirty_pos < start_pos || end_pos < dirty_pos)) {
		MARS_ERR_TO(rot->log_say, "replay symlink has implausible values: start_pos = %lld dirty_pos = %lld end_pos = %lld\n", start_pos, dirty_pos, end_pos);
	}
	/* Relevant or not?
	 */
	switch (status) {
	case 0: // not relevant
		goto ok;
	case 1: /* Relevant, and transaction replay already finished.
		 * Allow switching over to a new logfile.
		 */
		next_relevant_log = rot->next_relevant_log;
		if (!trans_brick->power.button && !trans_brick->power.led_on && trans_brick->power.led_off) {
			if (next_relevant_log && !rot->log_is_really_damaged) {
				int replay_tolerance = _get_tolerance(rot);
				bool skip_new = !!rot->todo_primary;
				bool possible;

				MARS_DBG("check switchover from '%s' to '%s' (size = %lld, skip_new = %d, replay_tolerance = %d)\n",
					 dent->d_path,
					 next_relevant_log->d_path,
					 next_relevant_log->new_stat.size,
					 skip_new,
					 replay_tolerance);

				possible =
					is_switchover_possible(rot,
							       dent->d_path,
							       rot->next_relevant_log->d_path,
							       replay_tolerance,
							       skip_new);

				if (possible) {
					MARS_INF_TO(rot->log_say, "start switchover from transaction log '%s' to '%s'\n", dent->d_path, rot->next_relevant_log->d_path);
					_make_new_replaylink(rot, rot->next_relevant_log->d_rest, rot->next_relevant_log->d_serial, rot->next_relevant_log->new_stat.size);
				} else {
					bool want_bypass =
						(rot->todo_primary &&
						 !_check_allow(global,
							       parent->d_path,
							       "connect"));
					if (want_bypass) {
						MARS_INF_TO(rot->log_say,
							    "forcefully bypassing transaction log '%s'\n",
							    SAFE_STR(next_relevant_log->d_path));
						next_relevant_log = NULL;
					}
				}
			}
			if (rot->todo_primary &&
			    (!next_relevant_log || rot->log_is_really_damaged)) {
				if (dent->d_serial > log_nr)
					log_nr = dent->d_serial;
				/* The primary versionlink needs to be ahead of the synced part of
				 * the logfile. When the primary crashes, it may point to a position
				 * which was never written to disk, or even to a prior one.
				 * Ensure that after reboot the primary will exceptionally re-consider
				 * versionlink updating.
				 */
				if (rot->aio_dent && rot->aio_dent->d_rest &&
				    !strcmp(rot->aio_dent->d_rest, my_id())) {
					MARS_INF_TO(rot->log_say,
						    "recover own versionlink %d end_pos=%lld\n",
						    log_nr, end_pos);
					_recover_versionlink(rot, my_id(), log_nr, end_pos);
				}
				MARS_INF_TO(rot->log_say, "preparing new transaction log, number moves from %d to %d\n", dent->d_serial, log_nr + 1);
				_make_new_replaylink(rot, my_id(), log_nr + 1, 0);
			} else {
				MARS_DBG("nothing to do on last transaction log '%s'\n", dent->d_path);
			}
		}
		status = -EAGAIN;
		goto done;
	case 2: // relevant for transaction replay
		MARS_INF_TO(rot->log_say, "replaying transaction log '%s' from position %lld to %lld\n", dent->d_path, start_pos, end_pos);
		rot->replay_mode = true;
		rot->start_pos = start_pos;
		rot->end_pos = end_pos;
		break;
	case 3: // relevant for appending
		MARS_INF_TO(rot->log_say, "appending to transaction log '%s'\n", dent->d_path);
		rot->replay_mode = false;
		rot->start_pos = 0;
		rot->end_pos = 0;
		break;
	default:
		MARS_ERR_TO(rot->log_say, "bad internal status %d\n", status);
		status = -EINVAL;
		goto done;
	}

ok:
	/* All ok: switch over the indicators.
	 */
	rot->prev_log = rot->next_log;
	rot->next_log = dent;

done:
	if (status < 0) {
		MARS_DBG("rot_error status = %d\n", status);
		rot->has_error = true;
	}
	return status;
}

static
void _init_trans_input(struct trans_logger_input *trans_input,
		       struct mars_dent *log_dent,
		       int input_nr,
		       struct mars_rotate *rot)
{
	if (unlikely(trans_input->connect || trans_input->is_operating)) {
		MARS_ERR("this should not happen\n");
		return;
	}

	memset(&trans_input->inf, 0, sizeof(trans_input->inf));

	strncpy(trans_input->inf.inf_host, log_dent->d_rest, sizeof(trans_input->inf.inf_host));
	trans_input->inf.inf_index = input_nr;
	trans_input->inf.inf_sequence = log_dent->d_serial;
	trans_input->inf.inf_private = rot;
	trans_input->inf.inf_callback = _update_info;
	MARS_DBG("initialized '%s' %d\n", trans_input->inf.inf_host, trans_input->inf.inf_sequence);
}

static
int _get_free_input(struct trans_logger_brick *trans_brick)
{
	int nr = (((trans_brick->log_input_nr - TL_INPUT_LOG1) + 1) % 2) + TL_INPUT_LOG1;
	struct trans_logger_input *candidate;

	candidate = trans_brick->inputs[nr];
	if (unlikely(!candidate)) {
		MARS_ERR("input nr = %d is corrupted!\n", nr);
		return -EEXIST;
	}
	if (unlikely(candidate->is_operating || candidate->connect)) {
		MARS_DBG("nr = %d unusable! is_operating = %d connect = %p\n", nr, candidate->is_operating, candidate->connect);
		return -EAGAIN;
	}
	MARS_DBG("got nr = %d\n", nr);
	return nr;
}

static
void _rotate_trans(struct mars_rotate *rot)
{
	struct trans_logger_brick *trans_brick = rot->trans_brick;
	int old_nr = trans_brick->old_input_nr;
	int log_nr = trans_brick->log_input_nr;
	int next_nr;

	MARS_DBG("log_input_nr = %d old_input_nr = %d next_relevant_log = %p\n", log_nr, old_nr, rot->next_relevant_log);

	// try to cleanup old log
	if (log_nr != old_nr) {
		struct trans_logger_input *trans_input = trans_brick->inputs[old_nr];
		struct trans_logger_input *new_input = trans_brick->inputs[log_nr];
		if (!trans_input->connect) {
			MARS_DBG("ignoring unused old input %d\n", old_nr);
		} else if (!new_input->is_operating) {
			MARS_DBG("ignoring uninitialized new input %d\n", log_nr);
		} else if (trans_input->is_operating &&
			   trans_input->inf.inf_min_pos == trans_input->inf.inf_max_pos &&
			   list_empty(&trans_input->pos_list) &&
			   atomic_read(&trans_input->log_ref_count) <= 0) {
			int status;

			write_info_links(rot);
			MARS_INF("cleanup old transaction log (%d -> %d)\n", old_nr, log_nr);
			status = mars_disconnect((void*)trans_input);
			if (unlikely(status < 0)) {
				MARS_ERR("disconnect failed\n");
			} else {
				/* Once again: now the other input should be active */
				write_info_links(rot);
				mars_trigger();
				mars_remote_trigger();
			}
		} else {
			MARS_DBG("old transaction replay not yet finished: is_operating = %d pos %lld != %lld\n",
				 trans_input->is_operating,
				 trans_input->inf.inf_min_pos,
				 trans_input->inf.inf_max_pos);
		}
	} else
	// try to setup new log
	if (log_nr == trans_brick->new_input_nr &&
	    rot->next_relevant_log &&
	    _check_allow(rot->global, rot->parent_path, "attach") &&
	    (rot->next_relevant_log->d_serial == trans_brick->inputs[log_nr]->inf.inf_sequence + 1 ||
	     trans_brick->cease_logging) &&
	    (next_nr = _get_free_input(trans_brick)) >= 0) {
		struct trans_logger_input *trans_input;
		int status;
		
		MARS_DBG("start switchover %d -> %d\n", old_nr, next_nr);
		
		rot->next_relevant_brick =
			make_brick_all(rot->global,
				       rot->next_relevant_log,
				       _set_aio_params,
				       NULL,
				       rot->next_relevant_log->d_path,
				       (const struct generic_brick_type*)&aio_brick_type,
				       (const struct generic_brick_type*[]){},
				       2, // create + activate
				       rot->next_relevant_log->d_path,
				       (const char *[]){},
				       0);
		if (unlikely(!rot->next_relevant_brick)) {
			MARS_ERR_TO(rot->log_say, "could not open next transaction log '%s'\n", rot->next_relevant_log->d_path);
			goto done;
		}
		trans_input = trans_brick->inputs[next_nr];
		if (unlikely(!trans_input)) {
			MARS_ERR_TO(rot->log_say, "internal log input does not exist\n");
			goto done;
		}

		_init_trans_input(trans_input,
				  rot->next_relevant_log,
				  next_nr,
				  rot);

		status = mars_connect((void *)trans_input, rot->next_relevant_brick->outputs[0]);
		if (unlikely(status < 0)) {
			MARS_ERR_TO(rot->log_say, "internal connect failed\n");
			goto done;
		}
		trans_brick->new_input_nr = next_nr;
		MARS_INF_TO(rot->log_say, "started logrotate switchover from '%s' to '%s'\n", rot->relevant_log->d_path, rot->next_relevant_log->d_path);
		rot->replay_code = TL_REPLAY_RUNNING;
	}
done: ;
}

static
void _change_trans(struct mars_rotate *rot)
{
	struct trans_logger_brick *trans_brick = rot->trans_brick;
	
	MARS_DBG("replay_mode = %d start_pos = %lld end_pos = %lld\n", trans_brick->replay_mode, rot->start_pos, rot->end_pos);

	if (trans_brick->replay_mode) {
		trans_brick->replay_start_pos = rot->start_pos;
		trans_brick->replay_end_pos = rot->end_pos;
	} else {
		_rotate_trans(rot);
	}
}

static
int _stop_trans(struct mars_rotate *rot);

static
int _start_trans(struct mars_rotate *rot)
{
	struct trans_logger_brick *trans_brick;
	struct trans_logger_input *trans_input;
	int nr;
	int status;

	/* Internal safety checks
	 */
	status = -EINVAL;
	if (unlikely(!rot)) {
		MARS_ERR("rot is NULL\n");
		goto done;
	}
	if (unlikely(!rot->aio_brick || !rot->relevant_log)) {
		MARS_ERR("aio %p or relevant log %p is missing, this should not happen\n", rot->aio_brick, rot->relevant_log);
		goto done;
	}
	trans_brick = rot->trans_brick;
	if (unlikely(!trans_brick)) {
		MARS_ERR("logger instance does not exist\n");
		goto done;
	}

	/* Update status when already working
	 */
	if (trans_brick->power.button || !trans_brick->power.led_off) {
		_change_trans(rot);
		status = 0;
		goto done;
	}

	/* Safeguard */
	status = _stop_trans(rot);
	if (unlikely(status < 0)) {
		MARS_DBG("stop status=%d\n", status);
		goto done;
	}

	/* Further safety checks.
	 */
	if (unlikely(rot->relevant_brick)) {
		MARS_ERR("log aio brick already present, this should not happen\n");
		goto done;
	}
	if (unlikely(trans_brick->inputs[TL_INPUT_LOG1]->is_operating || trans_brick->inputs[TL_INPUT_LOG2]->is_operating)) {
		MARS_ERR("some input is operating, this should not happen\n");
		goto done;
	}

	/* Allocate new input slot
	 */
	nr = _get_free_input(trans_brick);
	if (unlikely(nr < TL_INPUT_LOG1 || nr > TL_INPUT_LOG2)) {
		MARS_ERR("bad new_input_nr = %d\n", nr);
		goto done;
	}
	trans_brick->new_input_nr = nr;
	trans_brick->old_input_nr = nr;
	trans_brick->log_input_nr = nr;
	trans_input = trans_brick->inputs[nr];
	if (unlikely(!trans_input)) {
		MARS_ERR("log input %d does not exist\n", nr);
		goto done;
	}

	/* Open new transaction log
	 */
	rot->relevant_brick =
		make_brick_all(rot->global,
			       rot->relevant_log,
			       _set_aio_params,
			       NULL,
			       rot->relevant_log->d_path,
			       (const struct generic_brick_type*)&aio_brick_type,
			       (const struct generic_brick_type*[]){},
			       2, // start always
			       rot->relevant_log->d_path,
			       (const char *[]){},
			       0);
	if (unlikely(!rot->relevant_brick)) {
		MARS_ERR("log aio brick '%s' not open\n", rot->relevant_log->d_path);
		goto done;
	}

	/* Supply all relevant parameters
	 */
	trans_brick->replay_mode = rot->replay_mode;
	trans_brick->replay_tolerance = REPLAY_TOLERANCE;
	_init_trans_input(trans_input, rot->relevant_log, nr, rot);
	rot->replay_code = TL_REPLAY_RUNNING;

	/* Connect to new transaction log
	 */
	status = mars_connect((void *)trans_input, rot->relevant_brick->outputs[0]);
	if (unlikely(status < 0)) {
		MARS_ERR("initial connect failed\n");
		goto done;
	}

	_change_trans(rot);

	/* Switch on....
	 */
	status = mars_power_button((void*)trans_brick, true, false);
	MARS_DBG("status = %d\n", status);

done:
	return status;
}

static
int _stop_trans(struct mars_rotate *rot)
{
	struct trans_logger_brick *trans_brick = rot->trans_brick;
	const char *parent_path = rot->parent_path;
	int status = 0;

	if (!trans_brick || !parent_path) {
		goto done;
	}

	/* Switch off temporarily....
	 */
	status = mars_power_button((void*)trans_brick, false, false);
	MARS_DBG("status = %d\n", status);
	if (status < 0) {
		goto done;
	}

	/* Disconnect old connection(s)
	 */
	if (trans_brick->power.led_off) {
		int i;

		write_info_links(rot);
		for (i = TL_INPUT_LOG1; i <= TL_INPUT_LOG2; i++) {
			struct trans_logger_input *trans_input;
			trans_input = trans_brick->inputs[i];
			if (trans_input && !trans_input->is_operating) {
				(void)mars_disconnect((void*)trans_input);
			}
		}
	}
	write_info_links(rot);

done:
	return status;
}

static
int make_log_finalize(struct mars_global *global, struct mars_dent *dent)
{
	struct mars_dent *parent = dent->d_parent;
	struct mars_rotate *rot;
	struct trans_logger_brick *trans_brick;
	struct copy_brick *fetch_brick;
	bool is_stopped;
	int status = -EINVAL;

	CHECK_PTR(parent, err);
	rot = parent->d_private;
	if (!rot)
		goto err;
	CHECK_PTR(rot, err);
	rot->has_symlinks = true;
	trans_brick = rot->trans_brick;
	status = 0;
	if (!trans_brick) {
		MARS_DBG("nothing to do\n");
		goto done;
	}

	/* Handle jamming (a very exceptional state)
	 */
	if (IS_JAMMED()) {
#ifndef CONFIG_MARS_DEBUG
		brick_say_logging = 0;
#endif
		rot->has_emergency = true;
		/* Report remote errors to clients when they
		 * try to sync during emergency mode.
		 */
		if (rot->bio_brick && rot->bio_brick->mode_ptr)
			*rot->bio_brick->mode_ptr = -EMEDIUMTYPE;
		MARS_ERR_TO(rot->log_say, "DISK SPACE IS EXTREMELY LOW on %s\n", rot->parent_path);
		make_rot_msg(rot, "err-space-low", "DISK SPACE IS EXTREMELY LOW");
	} else if (IS_EXHAUSTED() && rot->has_emergency) {
		MARS_ERR_TO(rot->log_say, "EMEGENCY MODE HYSTERESIS on %s: you need to free more space for recovery.\n", rot->parent_path);
		make_rot_msg(rot, "err-space-low", "EMEGENCY MODE HYSTERESIS: you need to free more space for recovery.");
	} else {
		int limit = _check_allow(global, parent->d_path, "emergency-limit");
		rot->has_emergency = (limit > 0 && global_remaining_space * 100 / global_total_space < limit);
		MARS_DBG("has_emergency=%d limit=%d remaining_space=%lld total_space=%lld\n",
			 rot->has_emergency, limit, global_remaining_space, global_total_space);
		if (!rot->has_emergency && rot->bio_brick && rot->bio_brick->mode_ptr)
			*rot->bio_brick->mode_ptr = 0;
	}
	_show_actual(parent->d_path, "has-emergency", rot->has_emergency);
	if (rot->has_emergency) {
		if (rot->todo_primary || rot->is_primary) {
			trans_brick->cease_logging = true;
			rot->inf_prev_sequence = 0; // disable checking
		}
	} else {
		if (!trans_logger_resume) {
			MARS_INF_TO(rot->log_say, "emergency mode on %s could be turned off now, but /proc/sys/mars/logger_resume inhibits it.\n", rot->parent_path);
		} else {
			trans_brick->cease_logging = false;
			MARS_INF_TO(rot->log_say, "emergency mode on %s will be turned off again\n", rot->parent_path);
		}
	}
	is_stopped = trans_brick->cease_logging | trans_brick->stopped_logging;
	_show_actual(parent->d_path, "is-emergency", is_stopped);
	if (is_stopped) {
		MARS_ERR_TO(rot->log_say, "EMERGENCY MODE on %s: stopped transaction logging, and created a hole in the logfile sequence nubers.\n", rot->parent_path);
		make_rot_msg(rot, "err-emergency", "EMERGENCY MODE on %s: stopped transaction logging, and created a hole in the logfile sequence nubers.\n", rot->parent_path);
		/* Create a hole in the sequence of logfile numbers.
		 * The secondaries will later stumble over it.
		 */
		if (!rot->created_hole) {
			int new_sequence = rot->max_sequence + 10;
			char *new_vers = path_make("%s/version-%09d-%s", rot->parent_path, new_sequence, my_id());
			char *new_vval = path_make("00000000000000000000000000000000,log-%09d-%s,0:", new_sequence, my_id());
			char *new_path = path_make("%s/log-%09d-%s", rot->parent_path, new_sequence + 1, my_id());
			if (likely(new_vers && new_vval && new_path &&
				   !mars_find_dent(global, new_path))) {
				MARS_INF_TO(rot->log_say, "EMERGENCY: creating new logfile '%s'\n", new_path);
				ordered_symlink(new_vval, new_vers, NULL);
				_create_new_logfile(new_path);
				rot->created_hole = true;
			}
			brick_string_free(new_vers);
			brick_string_free(new_vval);
			brick_string_free(new_path);
		}
	} else {
		rot->created_hole = false;
	}

	if (IS_EMERGENCY_SECONDARY()) {
		if (!rot->todo_primary && rot->first_log && rot->first_log != rot->relevant_log) {
			MARS_WRN_TO(rot->log_say, "EMERGENCY: ruthlessly freeing old logfile '%s', don't cry on any ramifications.\n", rot->first_log->d_path);
			make_rot_msg(rot, "wrn-space-low", "EMERGENCY: ruthlessly freeing old logfile '%s'", rot->first_log->d_path);
			mars_unlink(rot->first_log->d_path);
			rot->first_log->d_killme = true;
			// give it a chance to cease deleting next time
			compute_emergency_mode();
		} else if (IS_EMERGENCY_PRIMARY()) {
			MARS_WRN_TO(rot->log_say, "EMERGENCY: the space on /mars/ is VERY low.\n");
			make_rot_msg(rot, "wrn-space-low", "EMERGENCY: the space on /mars/ is VERY low.");
		} else {
			MARS_WRN_TO(rot->log_say, "EMERGENCY: the space on /mars/ is low.\n");
			make_rot_msg(rot, "wrn-space-low", "EMERGENCY: the space on /mars/ is low.");
		}
	} else if (IS_EXHAUSTED()) {
		MARS_WRN_TO(rot->log_say, "EMERGENCY: the space on /mars/ is becoming low.\n");
		make_rot_msg(rot, "wrn-space-low", "EMERGENCY: the space on /mars/ is becoming low.");
	}

	rot->log_is_really_damaged = false;
	if (trans_brick->replay_mode) {
		write_info_links(rot);
		if (trans_brick->replay_code == TL_REPLAY_FINISHED) {
			MARS_INF_TO(rot->log_say, "logfile replay ended successfully at position %lld\n", trans_brick->replay_current_pos);
			if (rot->replay_code >= TL_REPLAY_RUNNING)
				rot->replay_code = trans_brick->replay_code;
		} else if (trans_brick->replay_code < TL_REPLAY_RUNNING ||
			   (rot->todo_primary &&
			    (trans_brick->replay_code == TL_REPLAY_INCOMPLETE ||
			     trans_brick->replay_end_pos - trans_brick->replay_current_pos < trans_brick->replay_tolerance))) {
			MARS_ERR_TO(rot->log_say, "logfile replay stopped with error = %d at position %lld\n", trans_brick->replay_code, trans_brick->replay_current_pos);
			make_rot_msg(rot, "err-replay-stop", "logfile replay stopped with error = %d at position %lld", trans_brick->replay_code, trans_brick->replay_current_pos);
			rot->replay_code = trans_brick->replay_code;
			rot->log_is_really_damaged = true;
			/* Exception: set actual position for recovery */
			_recover_versionlink(rot,
					     rot->current_inf.inf_host,
					     rot->current_inf.inf_sequence,
					     trans_brick->replay_current_pos);
			/* Exceptionally try switchover, following a damaged
			 * primary (only when possible)
			 */
			if (rot->relevant_log &&
			    rot->next_relevant_log &&
			    is_switchover_possible(rot,
						   rot->relevant_log->d_path,
						   rot->next_relevant_log->d_path,
						   _get_tolerance(rot), false)) {
				rot->log_is_really_damaged = false;
				trans_brick->replay_code = -EAGAIN;
				rot->replay_code = TL_REPLAY_RUNNING;
				MARS_INF_TO(rot->log_say,
					    "exceptional switchover from '%s' to '%s'\n",
					    rot->relevant_log->d_path,
					    rot->next_relevant_log->d_path);
				_make_new_replaylink(rot,
						     rot->next_relevant_log->d_rest,
						     rot->next_relevant_log->d_serial,
						     0);
			/* Designated primary must exceptionally accept a damaged
			 * logfile without successor for recovery under all circumstances.
			 */
			} else if (rot->todo_primary &&
				   rot->relevant_log &&
				   !rot->next_relevant_log &&
				   (!rot->fetch_brick ||
				    !_check_allow(global, parent->d_path, "connect"))) {
				/* Give fetch a chance for getting a better logfile.
				 */
				if (rot->retry_recovery++ <= 10)
					goto skip_retry_recovery;
				rot->log_is_really_damaged = false;
				rot->replay_code = TL_REPLAY_FINISHED;
				MARS_INF_TO(rot->log_say,
					    "exceptional recovery at '%s'\n",
					    rot->relevant_log->d_path);
				_make_new_replaylink(rot,
						     my_id(),
						     rot->relevant_log->d_serial + 1,
						     0);
			}
		} else if (rot->replay_code >= TL_REPLAY_RUNNING) {
			rot->replay_code = trans_brick->replay_code;

		}
	} else {
		rot->replay_code = TL_REPLAY_RUNNING;
	}
	rot->retry_recovery = 0;

 skip_retry_recovery:
	__show_actual(parent->d_path, "replay-code", rot->replay_code);

	/* Stopping is also possible in case of errors
	 */
	if (trans_brick->power.button && trans_brick->power.led_on && !trans_brick->power.led_off) {
		bool do_stop = true;
		if (trans_brick->replay_mode) {
			rot->is_log_damaged =
				(trans_brick->replay_code == -EAGAIN ||
				 trans_brick->replay_code == TL_REPLAY_INCOMPLETE) &&
				trans_brick->replay_end_pos - trans_brick->replay_current_pos < trans_brick->replay_tolerance;
			do_stop = trans_brick->replay_code != TL_REPLAY_RUNNING ||
				!global->global_power.button ||
				!_check_allow(global, parent->d_path, "allow-replay") ||
				!_check_allow(global, parent->d_path, "attach") ;

		} else {
			do_stop =
				!rot->if_brick &&
				!rot->is_primary &&
				(!rot->todo_primary ||
				 !_check_allow(global, parent->d_path, "attach"));
		}

		MARS_DBG("replay_mode = %d replay_code = %d is_primary = %d do_stop = %d\n", trans_brick->replay_mode, trans_brick->replay_code, rot->is_primary, (int)do_stop);

		if (do_stop) {
			status = _stop_trans(rot);
		} else {
			_change_trans(rot);
		}
		goto done;
	}

	/* Starting is only possible when no error occurred.
	 */
	if (!rot->relevant_log || rot->has_error) {
		MARS_DBG("nothing to do\n");
		goto done;
	}

	/* Start when necessary
	 */
	if (!trans_brick->power.button && !trans_brick->power.led_on && trans_brick->power.led_off) {
		bool do_start;

		status = _make_logging_status(rot);
		if (status <= 0) {
			goto done;
		}

		rot->is_log_damaged = false;

		do_start = (!rot->replay_mode ||
			    (rot->start_pos != rot->end_pos &&
			     _check_allow(global, parent->d_path, "allow-replay")));

		if (do_start && rot->forbid_replay) {
			MARS_INF("cannot start replay because sync wants to start\n");
			make_rot_msg(rot, "inf-replay-start", "cannot start replay because sync wants to star");
			do_start = false;
		}

		if (do_start && rot->sync_brick && !rot->sync_brick->power.led_off) {
			MARS_INF("cannot start replay because sync is running\n");
			make_rot_msg(rot, "inf-replay-start", "cannot start replay because sync is running");
			do_start = false;
		}

		MARS_DBG("rot->replay_mode = %d rot->start_pos = %lld rot->end_pos = %lld | do_start = %d\n", rot->replay_mode, rot->start_pos, rot->end_pos, do_start);

		if (do_start) {
			status = _start_trans(rot);
		}
	}

done:
	// check whether some copy has finished
	fetch_brick = (struct copy_brick*)mars_find_brick(global, &copy_brick_type, rot->fetch_path);
	MARS_DBG("fetch_path = '%s' fetch_brick = %p\n", rot->fetch_path, fetch_brick);
	if (fetch_brick &&
	    (fetch_brick->power.led_off ||
	     fetch_brick->power.force_off ||
	     fetch_brick->copy_error ||
	     !global->global_power.button ||
	     !_check_allow(global, parent->d_path, "connect") ||
	     !_check_allow(global, parent->d_path, "attach") ||
	     (fetch_brick->copy_last == fetch_brick->copy_end &&
	      (rot->fetch_next_is_available > 0 ||
	       rot->fetch_round++ > 3)))) {
		int i;

		for (i = 0; i < 4; i++) {
			if (fetch_brick->inputs[i] && fetch_brick->inputs[i]->brick)
				fetch_brick->inputs[i]->brick->power.io_timeout = 1;
		}
		if (fetch_brick->copy_error && !rot->avoid_peer && rot->fetch_peer) {
			rot->avoid_peer = brick_strdup(rot->fetch_peer);
			rot->avoid_count = 3;
		}
		fetch_brick = (void *)_kill_brick((void *)fetch_brick);
		if (!fetch_brick)
			mars_trigger();
	}
	rot->fetch_next_is_available = 0;
	rot->fetch_brick = fetch_brick;
	if (fetch_brick) {
		fetch_brick->kill_ptr = (void**)&rot->fetch_brick;
	} else {
		rot->fetch_serial = 0;
	}

	// remove trans_logger (when possible) upon detach
	if (rot->trans_brick && rot->trans_brick->power.led_off && !rot->trans_brick->outputs[0]->nr_connected) {
		bool do_attach = _check_allow(global, parent->d_path, "attach");
		MARS_DBG("do_attach = %d\n", do_attach);
		if (!do_attach) {
			rot->trans_brick->killme = true;
			rot->trans_brick = NULL;
		}
	}

	_show_actual(rot->parent_path, "is-replaying", rot->trans_brick && rot->trans_brick->replay_mode && !rot->trans_brick->power.led_off);
	_show_rate(rot, &rot->replay_limiter, "replay_rate");
	_show_actual(rot->parent_path, "is-copying", rot->fetch_brick && !rot->fetch_brick->power.led_off);
	_show_rate(rot, &rot->fetch_limiter, "file_rate");
	_show_actual(rot->parent_path, "is-syncing", rot->sync_brick && !rot->sync_brick->power.led_off);
	_show_rate(rot, &rot->sync_limiter, "sync_rate");
err:
	return status;
}

///////////////////////////////////////////////////////////////////////

// specific handlers

static
int make_primary(void *buf, struct mars_dent *dent)
{
	struct mars_global *global = buf;
	struct mars_dent *parent;
	struct mars_rotate *rot;
	int status = -EINVAL;

	parent = dent->d_parent;
	CHECK_PTR(parent, done);
	rot = parent->d_private;
	if (!rot)
		goto done;
	CHECK_PTR(rot, done);

	rot->has_symlinks = true;
	status = 0;

	/* Do not activate primary role shortly after modprobe.
	 * This gives the metadata update a chance to get the
	 * newest version of the primary link from some other
	 * cluster node.
	 */
	if (unlikely(!rot->checked_reboot)) {
		struct lamport_time when;

		get_lamport(NULL, &when);
		when.tv_sec += mars_scan_interval * 2;
		if (lamport_time_compare(&when, &modprobe_stamp) <= 0)
			goto done;
	}

	rot->todo_primary =
		global->global_power.button &&
		_check_allow(rot->global, rot->parent_path, "attach") &&
		dent->new_link &&
		!strcmp(dent->new_link, my_id());

	MARS_DBG("todo_primary = %d is_primary = %d\n", rot->todo_primary, rot->is_primary);

	rot->checked_reboot = true;

done:
	return status;
}

static
void activate_rot(struct mars_rotate *rot)
{
	const char *tmp;

	if (rot->rot_activated)
		return;
	rot->rot_activated = true;
	tmp = path_make("%s|%s/", tmp_resource_list, rot->parent_path);
	brick_string_free(tmp_resource_list);
	tmp_resource_list = tmp;
}

static
int make_bio(void *buf, struct mars_dent *dent)
{
	struct mars_global *global = buf;
	struct mars_rotate *rot;
	struct mars_brick *brick;
	bool switch_on;
	int status = 0;

	if (!global || !dent->d_parent) {
		goto done;
	}
	rot = dent->d_parent->d_private;
	if (!rot)
		goto done;

	/* for detach, both the logger and the bio must be gone */
	if (rot->trans_brick)
		rot->is_attached = true;
	else if (rot->sync_brick)
		rot->is_attached = true;
	else if (!rot->bio_brick)
		rot->is_attached = false;
	_show_actual(rot->parent_path, "is-attached", rot->is_attached);

	rot->has_symlinks = true;
	activate_peer(rot, dent->d_rest);
	if (strcmp(dent->d_rest, my_id()))
		goto done;

	activate_rot(rot);

	switch_on = _check_allow(global, rot->parent_path, "attach");
	if (switch_on && rot->res_shutdown) {
		MARS_ERR("cannot access disk: resource shutdown mode is currently active\n");
		switch_on = false;
	}

	brick =
		make_brick_all(global,
			       dent,
			       _set_bio_params,
			       NULL,
			       dent->d_path,
			       (const struct generic_brick_type*)&bio_brick_type,
			       (const struct generic_brick_type*[]){},
			       rot->trans_brick || switch_on ? 2 : -1,
			       dent->d_path,
			       (const char *[]){},
			       0);
	rot->bio_brick = brick;
	if (unlikely(!brick)) {
		status = -ENXIO;
		goto done;
	}
	brick->outputs[0]->output_name = dent->d_path;

	/* Report the actual size of the device.
	 * It may be larger than the global size.
	 */
	if (brick && brick->power.led_on) {
		struct mars_info info = {};
		struct mars_output *output;
		char *src = NULL;
		char *dst = NULL;

		output = brick->outputs[0];
		status = output->ops->mars_get_info(output, &info);
		if (status < 0) {
			MARS_ERR("cannot get info on '%s'\n", dent->d_path);
			goto done;
		}
		src = path_make("%lld", info.current_size);
		dst = path_make("%s/actsize-%s", dent->d_parent->d_path, my_id());
		if (src && dst) {
			(void)ordered_symlink(src, dst, NULL);
		}
		brick_string_free(src);
		brick_string_free(dst);
	}

 done:
	return status;
}

static
int make_work(void *buf, struct mars_dent *dent)
{
	struct mars_global *global = buf;
	struct mars_rotate *rot;

	if (!global || !dent->d_parent) {
		goto done;
	}
	rot = dent->d_parent->d_private;
	if (!rot)
		goto done;
	rot->has_symlinks = true;

	activate_rot(rot);

 done:
	return 0;
}

static int make_replay(void *buf, struct mars_dent *dent)
{
	struct mars_global *global = buf;
	struct mars_dent *parent = dent->d_parent;
	int status = 0;

	if (!parent || !dent->new_link) {
		MARS_DBG("nothing to do\n");
		goto done;
	}

	status = make_log_finalize(global, dent);
	if (status < 0) {
		MARS_DBG("logger not initialized\n");
		goto done;
	}

done:
	return status;
}

static
void _show_dev(struct mars_rotate *rot)
{
	struct if_brick *if_brick = rot->if_brick;
	int open_count = 0;

	if (if_brick) {
		_show_rate(rot, &if_brick->io_limiter, "if_rate");
		__show_actual(rot->parent_path, "if-flying",
			      atomic_read(&if_brick->flying_count));
		__show_actual(rot->parent_path, "if-state",
			      if_brick->error_code);
		open_count = atomic_read(&if_brick->open_count);
	}
	__show_actual(rot->parent_path, "open-count", open_count);

	if (open_count != rot->old_open_count) {
		rot->old_open_count = open_count;
		mars_remote_trigger();
	}
}

static
int make_dev(void *buf, struct mars_dent *dent)
{
	struct mars_global *global = buf;
	struct mars_dent *parent = dent->d_parent;
	struct mars_rotate *rot = NULL;
	struct mars_brick *dev_brick;
	bool switch_on;
	int status = 0;

	if (!parent || !dent->new_link) {
		MARS_ERR("nothing to do\n");
		return -EINVAL;
	}
	rot = parent->d_private;
	if (!rot || !rot->parent_path) {
		MARS_DBG("nothing to do\n");
		goto err;
	}
	rot->has_symlinks = true;
	if (!rot->trans_brick) {
		MARS_DBG("transaction logger does not exist\n");
		goto done;
	}
	if (rot->dev_size <= 0) {
		MARS_WRN("trying to create device '%s' with zero size\n", dent->d_path);
		goto done;
	}

	status = _parse_args(dent, dent->new_link, 1);
	if (status < 0) {
		MARS_DBG("fail\n");
		goto done;
	}

	switch_on =
		(rot->if_brick && atomic_read(&rot->if_brick->open_count) > 0) ||
		(rot->todo_primary &&
		 rot->trans_brick &&
		 !rot->trans_brick->replay_mode &&
		 (rot->trans_brick->power.led_on ||
		  (!rot->trans_brick->power.button && !rot->trans_brick->power.led_off)) &&
		 _check_allow(global, rot->parent_path, "attach"));
	if (!global->global_power.button) {
		switch_on = false;
	}
	if (switch_on && rot->res_shutdown) {
		MARS_ERR("cannot create device: resource shutdown mode is currently active\n");
		switch_on = false;
	}

	dev_brick =
		make_brick_all(global,
			       dent,
			       _set_if_params,
			       rot,
			       dent->d_argv[0],
			       (const struct generic_brick_type*)&if_brick_type,
			       (const struct generic_brick_type*[]){(const struct generic_brick_type*)&trans_logger_brick_type},
			       switch_on ? 2 : -1,
			       "%s/device-%s", 
			       (const char *[]){"%s/replay-%s"},
			       1,
			       parent->d_path,
			       my_id(),
			       parent->d_path,
			       my_id());
	rot->if_brick = (void*)dev_brick;
	if (!dev_brick) {
		MARS_DBG("device not shown\n");
		goto done;
	}
	if (!switch_on) {
		MARS_DBG("setting killme on if_brick\n");
		dev_brick->killme = true;
	}
	dev_brick->kill_ptr = (void**)&rot->if_brick;
	dev_brick->show_status = _show_brick_status;

done:
	_show_dev(rot);
	rot->is_primary =
		rot->if_brick && !rot->if_brick->power.led_off;	
	_show_primary(rot, parent);
err:
	return status;
}

static
int kill_dev(void *buf, struct mars_dent *dent)
{
	struct mars_dent *parent = dent->d_parent;
	int status = kill_any(buf, dent);
	if (status > 0 && parent) {
		struct mars_rotate *rot = parent->d_private;
		if (rot) {
			rot->if_brick = NULL;
		}
	}
	return status;
}

static int _make_direct(void *buf, struct mars_dent *dent)
{
	struct mars_global *global = buf;
	struct mars_brick *brick;
	char *src_path = NULL;
	int status;
	bool switch_on;
	bool do_dealloc = false;

	if (!dent->d_parent || !dent->new_link) {
		return 0;
	}
	status = _parse_args(dent, dent->new_link, 2);
	if (status < 0) {
		MARS_DBG("parse status = %d\n", status);
		goto done;
	}
	src_path = dent->d_argv[0];
	if (src_path[0] != '/') {
		src_path = path_make("%s/%s", dent->d_parent->d_path, dent->d_argv[0]);
		if (!src_path) {
			MARS_DBG("fail\n");
			status = -ENOMEM;
			goto done;
		}
		do_dealloc = true;
	}

	switch_on = _check_allow(global, dent->d_parent->d_path, "attach");

	brick = 
		make_brick_all(global,
			       dent,
			       _set_bio_params,
			       NULL,
			       src_path,
			       (const struct generic_brick_type*)&bio_brick_type,
			       (const struct generic_brick_type*[]){},
			       switch_on ? 2 : -1,
			       "%s",
			       (const char *[]){},
			       0,
			       src_path);
	status = -1;
	if (!brick) {
		MARS_DBG("fail\n");
		goto done;
	}

	brick = 
		make_brick_all(global,
			       dent,
			       _set_if_params,
			       NULL,
			       dent->d_argv[1],
			       (const struct generic_brick_type*)&if_brick_type,
			       (const struct generic_brick_type*[]){NULL},
			       switch_on ? 2 : -1,
			       "%s/directdevice-%s",
			       (const char *[]){ "%s" },
			       1,
			       dent->d_parent->d_path,
			       dent->d_argv[1],
			       src_path);
	status = -1;
	if (!brick) {
		MARS_DBG("fail\n");
		goto done;
	}

	status = 0;
done:
	MARS_DBG("status = %d\n", status);
	if (do_dealloc && src_path)
		brick_string_free(src_path);
	return status;
}

static int _make_copy(void *buf, struct mars_dent *dent)
{
	struct mars_global *global = buf;
	const char *switch_path = NULL;
	const char *copy_path = NULL;
	int status;

	if (!dent->d_parent || !dent->new_link) {
		return 0;
	}
	status = _parse_args(dent, dent->new_link, 2);
	if (status < 0) {
		goto done;
	}
	copy_path = backskip_replace(dent->d_path, '/', true, "/copy-");
	if (unlikely(!copy_path)) {
		status = -ENOMEM;
		goto done;
	}
	// check whether connection is allowed
	switch_path = path_make("%s/todo-%s/connect", dent->d_parent->d_path, my_id());

	status = __make_copy(global,
			     dent,
			     switch_path,
			     copy_path,
			     dent->d_parent->d_path,
			     (const char**)dent->d_argv,
			     NULL,
			     -1,
			     -1,
			     false, false, true, true,
			     NULL,
			     NULL, NULL);

done:
	MARS_DBG("status = %d\n", status);
	if (copy_path)
		brick_string_free(copy_path);
	if (switch_path)
		brick_string_free(switch_path);
	return status;
}

static
int _update_syncstatus(struct mars_rotate *rot, struct copy_brick *copy, char *peer)
{
	const char *src = NULL;
	const char *dst = NULL;
	const char *syncpos_path = NULL;
	const char *peer_replay_path = NULL;
	const char *peer_replay_link = NULL;
	const char *peer_time_path = NULL;
	int status = -EINVAL;

	/* create syncpos symlink when necessary */
	if (copy->copy_last == copy->copy_end && !rot->sync_finish_stamp.tv_sec) {
		get_lamport(NULL, &rot->sync_finish_stamp);
		MARS_DBG("sync finished at timestamp %lu\n",
			 rot->sync_finish_stamp.tv_sec);
		/* Give the remote replay position a chance to become
		 * recent enough.
		 */
		mars_remote_trigger();
		status = -EAGAIN;
		goto done;
	}
	if (rot->sync_finish_stamp.tv_sec) {
		struct kstat peer_time_stat = {};

		peer_time_path = path_make("/mars/alive-%s", peer);
		status = mars_stat(peer_time_path, &peer_time_stat, true);
		if (unlikely(status < 0)) {
			MARS_ERR("cannot stat '%s'\n", peer_time_path);
			goto done;
		}

		/* The syncpos tells us the replay position at the primary
		 * which was effective at the moment when the local sync was done.
		 * It is used to guarantee consistency:
		 * before our underlying disk is _really_ consistent, not only
		 * the sync must have finished, but additionally the local
		 * replay must have grown (at least) until the same position
		 * at which the primary was at that moment.
		 * Therefore, we have to remember the replay position of
		 * the primary at that moment.
		 * And because of the network delays we must ensure
		 * to get a recent enough remote version.
		 */
		syncpos_path = path_make("%s/syncpos-%s", rot->parent_path, my_id());
		peer_replay_path = path_make("%s/replay-%s", rot->parent_path, peer);
		peer_replay_link = ordered_readlink(peer_replay_path);
		if (unlikely(!peer_replay_link || !peer_replay_link[0])) {
			MARS_ERR("cannot read peer replay link '%s'\n", peer_replay_path);
			goto done;
		}

		_crashme(3, true);

		status = _update_link_when_necessary(rot, "syncpos", peer_replay_link, syncpos_path);
		/* Sync is only marked as finished when the syncpos
		 * production was successful and timestamps are recent enough.
		 */
		if (unlikely(status < 0))
			goto done;
		if (lamport_time_compare(&peer_time_stat.mtime, &rot->sync_finish_stamp) < 0) {
			MARS_INF("peer replay link '%s' is not recent enough (%lu < %lu)\n",
				 peer_replay_path,
				 peer_time_stat.mtime.tv_sec,
				 rot->sync_finish_stamp.tv_sec);
			mars_remote_trigger();
			status = -EAGAIN;
			goto done;
		}
	}

	src = path_make("%lld", copy->copy_last);
	dst = path_make("%s/syncstatus-%s", rot->parent_path, my_id());

	_crashme(4, true);

	status = _update_link_when_necessary(rot, "syncstatus", src, dst);

	brick_string_free(src);
	brick_string_free(dst);
	src = path_make("%lld,%lld", copy->verify_ok_count, copy->verify_error_count);
	dst = path_make("%s/verifystatus-%s", rot->parent_path, my_id());

	_crashme(5, true);

	(void)_update_link_when_necessary(rot, "verifystatus", src, dst);

	memset(&rot->sync_finish_stamp, 0, sizeof(rot->sync_finish_stamp));
done:
	brick_string_free(src);
	brick_string_free(dst);
	brick_string_free(peer_replay_link);
	brick_string_free(peer_replay_path);
	brick_string_free(syncpos_path);
	brick_string_free(peer_time_path);
	return status;
}

struct syncstatus_cookie {
	struct mars_global *global;
	struct mars_rotate *rot;
	char *peer;
};

static
int update_syncstatus(struct mars_brick *_copy, bool switch_on, void *private)
{
	struct copy_brick *copy = (void *)_copy;
	struct syncstatus_cookie *cc = private;
	int status = 0;

	/* Update syncstatus symlink
	 */
	if (copy &&
	    ((copy->power.button && copy->power.led_on) ||
	     !copy->copy_start ||
	     (copy->copy_last == copy->copy_end && copy->copy_end > 0))) {
		status = _update_syncstatus(cc->rot, copy, cc->peer);
	}
	return status;
}

static int make_sync(void *buf, struct mars_dent *dent)
{
	struct mars_global *global = buf;
	struct mars_rotate *rot;
	loff_t start_pos = 0;
	loff_t end_pos = 0;
	struct mars_dent *size_dent;
	struct mars_dent *primary_dent;
	struct mars_dent *syncfrom_dent;
	char *peer;
	struct copy_brick *copy = NULL;
	char *tmp = NULL;
	const char *switch_path = NULL;
	const char *copy_path = NULL;
	const char *src = NULL;
	const char *dst = NULL;
	bool do_start;
	int status;

	if (!dent->d_parent ||
	    !dent->d_parent->d_private ||
	    !dent->new_link) {
		return 0;
	}

	/* Determine peer
	 */
	tmp = path_make("%s/primary", dent->d_parent->d_path);
	primary_dent = (void*)mars_find_dent(global, tmp);
	if (!primary_dent || !primary_dent->new_link) {
		MARS_ERR("cannot determine primary, symlink '%s'\n", tmp);
		status = 0;
		goto done;
	}
	peer = primary_dent->new_link;

	do_start = _check_allow(global, dent->d_parent->d_path, "attach");

	/* Analyze replay position
	 */
	status = sscanf(dent->new_link, "%lld", &start_pos);
	if (status != 1) {
		MARS_ERR("bad syncstatus symlink syntax '%s' (%s)\n", dent->new_link, dent->d_path);
		status = -EINVAL;
		goto done;
	}

	rot = dent->d_parent->d_private;
	status = -ENOENT;
	CHECK_PTR(rot, done);

	rot->has_symlinks = true;
	rot->allow_update = true;
	rot->syncstatus_dent = dent;

	/* Sync necessary?
	 */
	brick_string_free(tmp);
	tmp = path_make("%s/size", dent->d_parent->d_path);
	status = -ENOMEM;
	if (unlikely(!tmp))
		goto done;
	size_dent = (void*)mars_find_dent(global, tmp);
	if (!size_dent || !size_dent->new_link) {
		MARS_ERR("cannot determine size '%s'\n", tmp);
		status = -ENOENT;
		goto done;
	}
	status = sscanf(size_dent->new_link, "%lld", &end_pos);
	if (status != 1) {
		MARS_ERR("bad size symlink syntax '%s' (%s)\n", size_dent->new_link, tmp);
		status = -EINVAL;
		goto done;
	}

	/* Is sync necessary at all?
	 */
	if (start_pos >= end_pos) {
		MARS_DBG("no data sync necessary, size = %lld\n", start_pos);
		do_start = false;
	}

	/* Handle final waiting step when finished
	 */
	if (rot->sync_finish_stamp.tv_sec && do_start)
		goto shortcut;
	if (!do_start)
		memset(&rot->sync_finish_stamp, 0, sizeof(rot->sync_finish_stamp));

	/* Don't sync when logfiles are discontiguous
	 */
	if (do_start && (rot->has_double_logfile | rot->has_hole_logfile)) {
		MARS_WRN("no sync possible due to discontiguous logfiles (%d|%d)\n",
			 rot->has_double_logfile, rot->has_hole_logfile);
		if (do_start)
			start_pos = 0;
		do_start = false;
	}

	/* stop sync when primary is unknown
	 */
	if (!strcmp(peer, "(none)")) {
		MARS_INF("cannot start sync, no primary is designated\n");
		if (do_start)
			start_pos = 0;
		do_start = false;
	}

	/* Check syncfrom link (when existing)
	 */
	brick_string_free(tmp);
	tmp = path_make("%s/syncfrom-%s", dent->d_parent->d_path, my_id());
	syncfrom_dent = (void*)mars_find_dent(global, tmp);
	if (do_start && syncfrom_dent && syncfrom_dent->new_link &&
	    strcmp(syncfrom_dent->new_link, peer)) {
		MARS_WRN("cannot start sync, primary has changed: '%s' != '%s'\n",
			 syncfrom_dent->new_link, peer);
		if (do_start)
			start_pos = 0;
		do_start = false;
	}

	/* Obey global sync limit
	 */
	if (do_start) {
		_global_sync_nr++;
		if (_global_sync_nr > global_sync_limit && global_sync_limit > 0)
			do_start = false;
	}

	/* Disallow contemporary sync & logfile_replay
	 */
	if (do_start &&
	    rot->trans_brick &&
	    !rot->trans_brick->power.led_off) {
		MARS_INF("cannot start sync because logger is working\n");
		do_start = false;
	}

	/* Disallow overwrite of newer data
	 */
	if (do_start)
		write_info_links(rot);
	rot->forbid_replay = (do_start && compare_replaylinks(rot, peer, my_id()) < 0);
	if (rot->forbid_replay) {
		MARS_INF("cannot start sync because my data is newer than the remote one at '%s'!\n", peer);
		do_start = false;
	}

	/* Flip between replay and sync
	 */
	if (do_start && rot->replay_mode && rot->end_pos > rot->start_pos &&
	    mars_sync_flip_interval >= 8) {
		if (!rot->flip_start) {
			rot->flip_start = jiffies;
			rot->flip_pos = rot->start_pos;
		} else if ((long long)jiffies - rot->flip_start > mars_sync_flip_interval * HZ &&
			   rot->sync_brick &&
			   rot->sync_brick->copy_last > rot->flip_pos) {
			do_start = false;
			rot->flip_start = jiffies + mars_sync_flip_interval * HZ;
			mars_trigger();
		}
	} else {
		rot->flip_start = 0;
	}

 shortcut:
	/* Start copy
	 */
#ifdef CONFIG_MARS_SEPARATE_PORTS
	src = path_make("data-%s@%s:%d", peer, peer, mars_net_default_port + MARS_TRAFFIC_SYNC);
#else
	src = path_make("data-%s@%s", peer, peer);
#endif
	dst = path_make("data-%s", my_id());
	copy_path = backskip_replace(dent->d_path, '/', true, "/copy-");

	// check whether connection is allowed
	switch_path = path_make("%s/todo-%s/sync", dent->d_parent->d_path, my_id());

	MARS_DBG("initial sync '%s' => '%s' ('%s' '%s') do_start = %d\n",
		 src, dst,
		 copy_path, switch_path,
		 do_start);

	status = -ENOMEM;
	if (unlikely(!src || !dst || !copy_path || !switch_path))
		goto done;

	/* Informational
	 */
	MARS_DBG("start_pos = %lld end_pos = %lld sync_finish_stamp=%lu do_start=%d\n",
		 start_pos, end_pos, rot->sync_finish_stamp.tv_sec, do_start);

	/* Now do it....
	 */
	{
		const char *argv[2] = { src, dst };
		struct syncstatus_cookie cc = {
			.global = global,
			.rot = rot,
			.peer = peer,
		};

		status = __make_copy(global, dent,
				     do_start ? switch_path : "",
				     copy_path, dent->d_parent->d_path, argv, find_key(rot->msgs, "inf-sync"),
				     start_pos, end_pos,
				     true,
				     mars_fast_fullsync > 0,
				     true, false,
				     &copy,
				     update_syncstatus, &cc);
		if (copy) {
			copy->kill_ptr = (void**)&rot->sync_brick;
			copy->copy_limiter = &rot->sync_limiter;
		}
		rot->sync_brick = copy;
	}

done:
	MARS_DBG("status = %d\n", status);
	brick_string_free(tmp);
	brick_string_free(src);
	brick_string_free(dst);
	brick_string_free(copy_path);
	brick_string_free(switch_path);
	return status;
}

static
bool remember_peer(struct mars_rotate *rot, struct mars_peerinfo *peer)
{
	if (!peer || !rot || rot->preferred_peer)
		return false;

	if ((long long)peer->last_remote_jiffies + mars_scan_interval * HZ * 2 < (long long)jiffies)
		return false;

	rot->preferred_peer = brick_strdup(peer->peer);
	return true;
}

static
int make_connect(void *buf, struct mars_dent *dent)
{
	struct mars_rotate *rot;
	struct mars_peerinfo *peer;
	char *names;
	char *this_name;
	char *tmp;

	if (unlikely(!dent->d_parent || !dent->new_link)) {
		goto done;
	}
	rot = dent->d_parent->d_private;
	if (unlikely(!rot)) {
		goto done;
	}

	names = brick_strdup(dent->new_link);
	for (tmp = this_name = names; *tmp; tmp++) {
		if (*tmp == MARS_DELIM) {
			*tmp = '\0';
			peer = find_peer(this_name);
			if (remember_peer(rot, peer))
				goto found;
			this_name = tmp + 1;
		}
	}
	peer = find_peer(this_name);
	remember_peer(rot, peer);

found:
	brick_string_free(names);
done:
	return 0;
}

static int prepare_delete(void *buf, struct mars_dent *dent)
{
	struct kstat stat;
	struct kstat *to_delete = NULL;
	struct mars_global *global = buf;
	struct mars_dent *target;
	struct mars_dent *response;
	const char *response_path = NULL;
	struct mars_brick *brick;
	int max_serial = 0;
	int status;

	if (!global || !dent || !dent->new_link || !dent->d_path) {
		goto err;
	}

	brick = mars_find_brick(global, NULL, dent->new_link);
	if (brick &&
	    unlikely((brick->nr_outputs > 0 && brick->outputs[0] && brick->outputs[0]->nr_connected) ||
		     (brick->type == (void*)&if_brick_type && !brick->power.led_off))) {
		MARS_WRN("target '%s' cannot be deleted, its brick '%s' in use\n", dent->new_link, SAFE_STR(brick->brick_name));
		goto done;
	}

	status = 0;
	target = mars_find_dent(global, dent->new_link);
	if (target) {
		if (lamport_time_compare(&target->new_stat.mtime, &dent->new_stat.mtime) > 0) {
			MARS_WRN("target '%s' has newer timestamp than deletion link, ignoring\n", dent->new_link);
			status = -EAGAIN;
			goto ok;
		}
		if (target->d_child_count) {
			MARS_WRN("target '%s' has %d children, cannot kill\n", dent->new_link, target->d_child_count);
			goto done;
		}
		target->d_killme = true;
		MARS_DBG("target '%s' marked for removal\n", dent->new_link);
		to_delete = &target->new_stat;
	} else if (mars_stat(dent->new_link, &stat, true) >= 0) {
		if (lamport_time_compare(&stat.mtime, &dent->new_stat.mtime) > 0) {
			MARS_WRN("target '%s' has newer timestamp than deletion link, ignoring\n", dent->new_link);
			status = -EAGAIN;
			goto ok;
		}
		to_delete = &stat;
	} else {
		status = -EAGAIN;
		MARS_DBG("target '%s' does no longer exist\n", dent->new_link);
	}
	if (to_delete) {
		if (S_ISDIR(to_delete->mode)) {
			status = mars_rmdir(dent->new_link);
			MARS_DBG("rmdir '%s', status = %d\n", dent->new_link, status);
		} else {
			status = ordered_unlink(dent->new_link,
						&dent->new_stat.mtime,
						dent->d_serial,
						0);
			MARS_DBG("unlink '%s', status = %d\n", dent->new_link, status);
		}
	}

 ok:	
	if (status < 0) {
		MARS_DBG("deletion '%s' to target '%s' is accomplished\n",
			 dent->d_path, dent->new_link);
		if (dent->d_serial <= global->deleted_border) {
			MARS_DBG("removing deletion symlink '%s'\n", dent->d_path);
			dent->d_killme = true;
			mars_unlink(dent->d_path);
		}
	}

 done:
	// tell the world that we have seen this deletion... (even when not yet accomplished)
	response_path = path_make("/mars/todo-global/deleted-%s", my_id());
	response = mars_find_dent(global, response_path);
	if (response && response->new_link) {
		sscanf(response->new_link, "%d", &max_serial);
	}
	if (dent->d_serial > max_serial) {
		char response_val[16];
		max_serial = dent->d_serial;
		global->deleted_my_border = max_serial;
		snprintf(response_val, sizeof(response_val), "%09d", max_serial);
		ordered_symlink(response_val, response_path, NULL);
	}

 err:
	brick_string_free(response_path);
	return 0;
}

static int check_deleted(void *buf, struct mars_dent *dent)
{
	struct mars_global *global = buf;
	int serial = 0;
	int status;

	if (!global || !dent || !dent->new_link) {
		goto done;
	}

	status = sscanf(dent->new_link, "%d", &serial);
	if (status != 1 || serial <= 0) {
		MARS_WRN("cannot parse symlink '%s' -> '%s'\n", dent->d_path, dent->new_link);
		goto done;
	}

	if (!strcmp(dent->d_rest, my_id())) {
		global->deleted_my_border = serial;
		if (global->deleted_my_border != global->old_deleted_my_border) {
			global->old_deleted_my_border = global->deleted_my_border;
			mars_remote_trigger();
		}
	}

	/* Compute the minimum of the deletion progress among
	 * the resource members.
	 */
	if (serial < global->deleted_min || !global->deleted_min)
		global->deleted_min = serial;

	
 done:
	return 0;
}

/* transient, to re-disappear */
static
int get_compat_deletions(void *buf, struct mars_dent *dent)
{
	if (dent && dent->new_link)
		sscanf(dent->new_link, "%d", &compat_deletions);
	return 0;
}

static
int make_res(void *buf, struct mars_dent *dent)
{
	struct mars_rotate *rot = dent->d_private;

	if (!rot) {
		MARS_DBG("nothing to do\n");
		goto done;
	}

	rot->has_symlinks = false;

 done:
	return 0;
}

static
int kill_res(void *buf, struct mars_dent *dent)
{
	struct mars_rotate *rot = dent->d_private;

	if (unlikely(!rot || !rot->parent_path)) {
		MARS_DBG("nothing to do\n");
		goto done;
	}

	show_vals(rot->msgs, rot->parent_path, "");

	if (unlikely(!rot->global)) {
		MARS_DBG("nothing to do\n");
		goto done;
	}
	if (rot->has_symlinks) {
		MARS_DBG("symlinks were present, nothing to kill.\n");
		goto done;
	}

	// this code is only executed in case of forced deletion of symlinks
	if (rot->if_brick || rot->sync_brick || rot->fetch_brick || rot->trans_brick) {
		rot->res_shutdown = true;
		MARS_WRN("resource '%s' has no symlinks, shutting down.\n", rot->parent_path);
	}
	if (rot->if_brick) {
		if (atomic_read(&rot->if_brick->open_count) > 0) {
			MARS_ERR("cannot destroy resource '%s': device is is use!\n", rot->parent_path);
			goto done;
		}
		rot->if_brick->killme = true;
		if (!rot->if_brick->power.led_off) {
			int status = mars_power_button((void*)rot->if_brick, false, false);
			MARS_INF("switching off resource '%s', device status = %d\n", rot->parent_path, status);
		} else {
			mars_kill_brick((void*)rot->if_brick);
			rot->if_brick = NULL;
		}
	}
	if (rot->sync_brick) {
		rot->sync_brick->killme = true;
		if (!rot->sync_brick->power.led_off) {
			int status = mars_power_button((void*)rot->sync_brick, false, false);
			MARS_INF("switching off resource '%s', sync status = %d\n", rot->parent_path, status);
		}
	}
	if (rot->fetch_brick) {
		rot->fetch_brick->killme = true;
		if (!rot->fetch_brick->power.led_off) {
			int status = mars_power_button((void*)rot->fetch_brick, false, false);
			MARS_INF("switching off resource '%s', fetch status = %d\n", rot->parent_path, status);
		}
	}
	if (rot->trans_brick) {
		struct trans_logger_output *output = rot->trans_brick->outputs[0];
		if (!output || output->nr_connected) {
			MARS_ERR("cannot destroy resource '%s': trans_logger is is use!\n", rot->parent_path);
			goto done;
		}
		rot->trans_brick->killme = true;
		if (!rot->trans_brick->power.led_off) {
			int status = mars_power_button((void*)rot->trans_brick, false, false);
			MARS_INF("switching off resource '%s', logger status = %d\n", rot->parent_path, status);
		}
	}
	if (!rot->if_brick && !rot->sync_brick && !rot->fetch_brick && !rot->trans_brick) {
		rot->res_shutdown = false;
	}

 done:
	return 0;
}

static
int make_defaults(void *buf, struct mars_dent *dent)
{
	if (!dent->new_link)
		goto done;

	MARS_DBG("name = '%s' value = '%s'\n", dent->d_name, dent->new_link);

	if (!strcmp(dent->d_name, "sync-limit")) {
		sscanf(dent->new_link, "%d", &global_sync_limit);
	} else if (!strcmp(dent->d_name, "disabled-log-digests")) {
		sscanf(dent->new_link, "0x%x", &disabled_log_digests);
	} else if (!strcmp(dent->d_name, "disabled-net-digests")) {
		__u32 tmp = 0;

		sscanf(dent->new_link, "0x%x", &tmp);
		/* at least one digest must remain usable */
		tmp &= ~MREF_CHKSUM_MD5_OLD;
		disabled_net_digests = tmp;
	} else if (!strcmp(dent->d_name, "enabled-log-compressions")) {
		sscanf(dent->new_link, "0x%x", &enabled_log_compressions);
	} else if (!strcmp(dent->d_name, "enabled-net-compressions")) {
		sscanf(dent->new_link, "0x%x", &enabled_net_compressions);
	} else {
		MARS_DBG("unimplemented default '%s'\n", dent->d_name);
	}
 done:
	return 0;
}

///////////////////////////////////////////////////////////////////////

/* Please keep the order the same as in the enum.
 */
static const struct main_class main_classes[] = {
	/* Placeholder for root node /mars/
	 */
	[CL_ROOT] = {
	},

	/* UUID, indentifying the whole cluster.
	 */
	[CL_UUID] = {
		.cl_name = "uuid",
		.cl_len = 4,
		.cl_type = 'l',
		.cl_father = CL_ROOT,
	},

	/* Subdirectory for global userspace items...
	 */
	[CL_GLOBAL_USERSPACE] = {
		.cl_name = "userspace",
		.cl_len = 9,
		.cl_type = 'd',
		.cl_hostcontext = false,
		.cl_father = CL_ROOT,
	},
	[CL_GLOBAL_USERSPACE_ITEMS] = {
		.cl_name = "",
		.cl_len = 0, // catch any
		.cl_type = 'L',
		.cl_father = CL_GLOBAL_USERSPACE,
	},

	/* Subdirectory for defaults...
	 */
	[CL_DEFAULTS0] = {
		.cl_name = "defaults",
		.cl_len = 8,
		.cl_type = 'd',
		.cl_hostcontext = false,
		.cl_father = CL_ROOT,
	},
	[CL_DEFAULTS] = {
		.cl_name = "defaults-",
		.cl_len = 9,
		.cl_type = 'd',
		.cl_hostcontext = true,
		.cl_father = CL_ROOT,
	},
	/* ... and its contents
	 */
	[CL_DEFAULTS_ITEMS0] = {
		.cl_name = "",
		.cl_len = 0, // catch any
		.cl_type = 'l',
		.cl_father = CL_DEFAULTS0,
		.cl_forward = make_defaults,
	},
	[CL_DEFAULTS_ITEMS] = {
		.cl_name = "",
		.cl_len = 0, // catch any
		.cl_type = 'l',
		.cl_father = CL_DEFAULTS,
		.cl_forward = make_defaults,
	},

	/* Subdirectory for global controlling items...
	 */
	[CL_GLOBAL_TODO] = {
		.cl_name = "todo-global",
		.cl_len = 11,
		.cl_type = 'd',
		.cl_hostcontext = false,
		.cl_father = CL_ROOT,
	},
	/* ... and its contents
	 */
	[CL_GLOBAL_TODO_DELETE] = {
		.cl_name = "delete-",
		.cl_len = 7,
		.cl_type = 'l',
		.cl_serial = true,
		.cl_hostcontext = false, // ignore context, although present
		.cl_father = CL_GLOBAL_TODO,
		.cl_prepare = prepare_delete,
	},
	[CL_GLOBAL_TODO_DELETED] = {
		.cl_name = "deleted-",
		.cl_len = 8,
		.cl_type = 'l',
		.cl_father = CL_GLOBAL_TODO,
		.cl_prepare = check_deleted,
	},

	/* Directory containing the addresses of all peers
	 */
	[CL_IPS] = {
		.cl_name = "ips",
		.cl_len = 3,
		.cl_type = 'd',
		.cl_father = CL_ROOT,
	},
	/* Anyone participating in a MARS cluster must
	 * be named here (symlink pointing to the IP address).
	 * We have no DNS in kernel space.
	 */
	[CL_PEERS] = {
		.cl_name = "ip-",
		.cl_len = 3,
		.cl_type = 'l',
		.cl_father = CL_IPS,
#ifdef RUN_PEERS
		.cl_forward = make_scan,
#endif
		.cl_backward = kill_scan,
	},
	/* Subdirectory for actual state
	 */
	[CL_GBL_ACTUAL] = {
		.cl_name = "actual-",
		.cl_len = 7,
		.cl_type = 'd',
		.cl_hostcontext = false,
		.cl_father = CL_ROOT,
	},
	/* ... and its contents
	 */
	[CL_GBL_ACTUAL_ITEMS] = {
		.cl_name = "",
		.cl_len = 0, // catch any
		.cl_type = 'l',
		.cl_father = CL_GBL_ACTUAL,
	},
	/* Show version indication for symlink tree.
	 */
	[CL_TREE] = {
		.cl_name = "tree-",
		.cl_len = 5,
		.cl_type = 'l',
		.cl_father = CL_ROOT,
	},
	[CL_FEATURES] = {
		.cl_name = "features-",
		.cl_len = 9,
		.cl_type = 'l',
		.cl_father = CL_ROOT,
	},
	[CL_USABLE] = {
		.cl_name = "usable-",
		.cl_len = 7,
		.cl_type = 'l',
		.cl_father = CL_ROOT,
	},
	/* transient, to re-disappear */
	[CL_COMPAT_DELETIONS] = {
		.cl_name = "compat-deletions",
		.cl_len = 16,
		.cl_type = 'l',
		.cl_hostcontext = false,
		.cl_father = CL_ROOT,
		.cl_forward = get_compat_deletions,
	},
	/* Indicate whether filesystem is full
	 */
	[CL_EMERGENCY] = {
		.cl_name = "emergency-",
		.cl_len = 10,
		.cl_type = 'l',
		.cl_father = CL_ROOT,
	},
	/* dto as percentage
	 */
	[CL_REST_SPACE] = {
		.cl_name = "rest-space-",
		.cl_len = 11,
		.cl_type = 'l',
		.cl_father = CL_ROOT,
	},

	/* Directory containing all items of a resource
	 */
	[CL_RESOURCE] = {
		.cl_name = "resource-",
		.cl_len = 9,
		.cl_type = 'd',
		.cl_use_channel = true,
		.cl_father = CL_ROOT,
		.cl_forward = make_res,
		.cl_backward = kill_res,
	},

	/* Subdirectory for resource-specific userspace items...
	 */
	[CL_RESOURCE_USERSPACE] = {
		.cl_name = "userspace",
		.cl_len = 9,
		.cl_type = 'd',
		.cl_hostcontext = false,
		.cl_father = CL_RESOURCE,
	},
	[CL_RESOURCE_USERSPACE_ITEMS] = {
		.cl_name = "",
		.cl_len = 0, // catch any
		.cl_type = 'L',
		.cl_father = CL_RESOURCE_USERSPACE,
	},

	/* Subdirectory for defaults...
	 */
	[CL_RES_DEFAULTS0] = {
		.cl_name = "defaults",
		.cl_len = 8,
		.cl_type = 'd',
		.cl_hostcontext = false,
		.cl_father = CL_RESOURCE,
	},
	[CL_RES_DEFAULTS] = {
		.cl_name = "defaults-",
		.cl_len = 9,
		.cl_type = 'd',
		.cl_hostcontext = false,
		.cl_father = CL_RESOURCE,
	},
	/* ... and its contents
	 */
	[CL_RES_DEFAULTS_ITEMS0] = {
		.cl_name = "",
		.cl_len = 0, // catch any
		.cl_type = 'l',
		.cl_father = CL_RES_DEFAULTS0,
	},
	[CL_RES_DEFAULTS_ITEMS] = {
		.cl_name = "",
		.cl_len = 0, // catch any
		.cl_type = 'l',
		.cl_father = CL_RES_DEFAULTS,
	},

	/* Subdirectory for controlling items...
	 */
	[CL_TODO] = {
		.cl_name = "todo-",
		.cl_len = 5,
		.cl_type = 'd',
		.cl_hostcontext = false,
		.cl_father = CL_RESOURCE,
	},
	/* ... and its contents
	 */
	[CL_TODO_ITEMS] = {
		.cl_name = "",
		.cl_len = 0, // catch any
		.cl_type = 'l',
		.cl_father = CL_TODO,
	},

	/* Subdirectory for actual state
	 */
	[CL_ACTUAL] = {
		.cl_name = "actual-",
		.cl_len = 7,
		.cl_type = 'd',
		.cl_hostcontext = false,
		.cl_father = CL_RESOURCE,
	},
	/* ... and its contents
	 */
	[CL_ACTUAL_ITEMS] = {
		.cl_name = "",
		.cl_len = 0, // catch any
		.cl_type = 'l',
		.cl_father = CL_ACTUAL,
	},


	/* File or symlink to the real device / real (sparse) file
	 * when hostcontext is missing, the corresponding peer will
	 * not participate in that resource.
	 */
	[CL_DATA] = {
		.cl_name = "data-",
		.cl_len = 5,
		.cl_type = 'F',
		.cl_hostcontext = false, // not really
		.cl_father = CL_RESOURCE,
#ifdef RUN_DATA
		.cl_forward = make_bio,
#endif
		.cl_backward = kill_any,
	},
	/* Internal: allows extra rot activation */
	[CL_WORK] = {
		.cl_name = "work-",
		.cl_len = 5,
		.cl_type = 'l',
		.cl_hostcontext = true,
		.cl_father = CL_RESOURCE,
#ifdef RUN_DATA
		.cl_forward = make_work,
#endif
		.cl_backward = kill_any,
	},
	/* Symlink indicating the (common) size of the resource
	 */
	[CL_SIZE] = {
		.cl_name = "size",
		.cl_len = 4,
		.cl_type = 'l',
		.cl_hostcontext = false,
		.cl_father = CL_RESOURCE,
#ifdef RUN_LOGINIT
		.cl_forward = make_log_init,
#endif
		.cl_backward = kill_any,
	},
	/* Dito for each individual size
	 */
	[CL_ACTSIZE] = {
		.cl_name = "actsize-",
		.cl_len = 8,
		.cl_type = 'l',
		.cl_hostcontext = true,
		.cl_father = CL_RESOURCE,
	},
	/* Symlinks for systemd hinting
	 */
	[CL_SYSTEMD_CATCHALL] = {
		.cl_name = "systemd-",
		.cl_len = 8,
		.cl_type = 'l',
		.cl_father = CL_RESOURCE,
	},
	/* Symlink pointing to the name of the primary node
	 */
	[CL_PRIMARY] = {
		.cl_name = "primary",
		.cl_len = 7,
		.cl_type = 'l',
		.cl_hostcontext = false,
		.cl_father = CL_RESOURCE,
#ifdef RUN_PRIMARY
		.cl_forward = make_primary,
#endif
		.cl_backward = NULL,
	},
	/* Only for testing: open local file
	 */
	[CL__FILE] = {
		.cl_name = "_file-",
		.cl_len = 6,
		.cl_type = 'F',
		.cl_serial = true,
		.cl_hostcontext = true,
		.cl_father = CL_RESOURCE,
		.cl_forward = make_bio,
		.cl_backward = kill_any,
	},
	/* Symlink for connection preferences
	 */
	[CL_CONNECT] = {
		.cl_name = "connect-",
		.cl_len = 8,
		.cl_type = 'l',
		.cl_hostcontext = true,
		.cl_father = CL_RESOURCE,
		.cl_forward = make_connect,
	},
	/* informational symlink indicating the current
	 * status / start / pos / end of logfile transfers.
	 */
	[CL_TRANSFER] = {
		.cl_name = "transferstatus-",
		.cl_len = 15,
		.cl_type = 'l',
		.cl_hostcontext = true,
		.cl_father = CL_RESOURCE,
	},
	/* symlink indicating the current status / end
	 * of initial data sync.
	 */
	[CL_SYNC] = {
		.cl_name = "syncstatus-",
		.cl_len = 11,
		.cl_type = 'l',
		.cl_hostcontext = true,
		.cl_father = CL_RESOURCE,
#ifdef RUN_SYNCSTATUS
		.cl_forward = make_sync,
#endif
		.cl_backward = kill_any,
	},
	/* informational symlink for verify status
	 * of initial data sync.
	 */
	[CL_VERIF] = {
		.cl_name = "verifystatus-",
		.cl_len = 13,
		.cl_type = 'l',
		.cl_hostcontext = true,
		.cl_father = CL_RESOURCE,
	},
	/* informational symlink: after sync has finished,
	 * keep a copy of the replay symlink from the primary.
	 * when comparing the own replay symlink against this,
	 * we can determine whether we are consistent.
	 */
	[CL_SYNCPOS] = {
		.cl_name = "syncpos-",
		.cl_len = 8,
		.cl_type = 'l',
		.cl_hostcontext = true,
		.cl_father = CL_RESOURCE,
	},
	/* Only for testing: make a copy instance
	 */
	[CL__COPY] = {
		.cl_name = "_copy-",
		.cl_len = 6,
		.cl_type = 'l',
		.cl_serial = true,
		.cl_hostcontext = true,
		.cl_father = CL_RESOURCE,
		.cl_forward = _make_copy,
		.cl_backward = kill_any,
	},
	/* Only for testing: access local data
	 */
	[CL__DIRECT] = {
		.cl_name = "_direct-",
		.cl_len = 8,
		.cl_type = 'l',
		.cl_serial = true,
		.cl_hostcontext = true,
		.cl_father = CL_RESOURCE,
		.cl_forward = _make_direct,
		.cl_backward = kill_any,
	},

	/* Passive symlink indicating the split-brain crypto hash
	 */
	[CL_VERSION] = {
		.cl_name = "version-",
		.cl_len = 8,
		.cl_type = 'l',
		.cl_serial = true,
		.cl_hostcontext = false,
		.cl_father = CL_RESOURCE,
	},
	/* Logfiles for transaction logger
	 */
	[CL_LOG] = {
		.cl_name = "log-",
		.cl_len = 4,
		.cl_type = 'F',
		.cl_serial = true,
		.cl_hostcontext = false,
		.cl_father = CL_RESOURCE,
#ifdef RUN_LOGFILES
		.cl_forward = make_log_step,
#endif
		.cl_backward = kill_any,
	},
	/* Symlink indicating the last state of
	 * transaction log replay.
	 */
	[CL_REPLAYSTATUS] = {
		.cl_name = "replay-",
		.cl_len = 7,
		.cl_type = 'l',
		.cl_hostcontext = true,
		.cl_father = CL_RESOURCE,
#ifdef RUN_REPLAY
		.cl_forward = make_replay,
#endif
		.cl_backward = kill_any,
	},

	/* Name of the device appearing at the primary
	 */
	[CL_DEVICE] = {
		.cl_name = "device-",
		.cl_len = 7,
		.cl_type = 'l',
		.cl_hostcontext = true,
		.cl_father = CL_RESOURCE,
#ifdef RUN_DEVICE
		.cl_forward = make_dev,
#endif
		.cl_backward = kill_dev,
	},

	/* Quirk: when dead resources are recreated during a network partition,
	 * this is used to void version number clashes in the
	 * partitioned cluster.
	 */
	[CL_MAXNR] = {
		.cl_name = "maxnr",
		.cl_len = 5,
		.cl_type = 'l',
		.cl_father = CL_RESOURCE,
	},
	/* Indicate aliveness of all cluster paritcipants
	 * by the timestamp of this link.
	 * These must come last for race avoidance.
	 */
	[CL_ALIVE] = {
		.cl_name = "alive-",
		.cl_len = 6,
		.cl_type = 'l',
		.cl_father = CL_ROOT,
	},
	[CL_TIME] = {
		.cl_name = "time-",
		.cl_len = 5,
		.cl_type = 'l',
		.cl_father = CL_ROOT,
	},
	{}
};

/* Helper routine to pre-determine the relevance of a name from the filesystem.
 * Caution: this is called as a callback from iterate_dir() and friends.
 * Don't deadlock by producing any filesystem output within this!
 */
int main_checker(struct mars_dent *parent, const char *_name, int namlen, unsigned int d_type, int *prefix, int *serial, bool *use_channel)
{
	int class;
	int status = -2;
#ifdef MARS_DEBUGGING
	const char *name = brick_strndup(_name, namlen);
	if (!name)
		return -ENOMEM;
#else
	const char *name = _name;
#endif

	for (class = CL_ROOT + 1; ; class++) {
		const struct main_class *test = &main_classes[class];
		int len = test->cl_len;
		if (!test->cl_name) { // end of table
			break;
		}

#ifdef MARS_DEBUGGING
		/* This can only happen when the table stucture is misformed.
		 * Exceptionally produce an error output.
		 * The whole system will not work anyway in such a stupid case.
		 */
		if (len != strlen(test->cl_name)) {
			MARS_ERR("internal table '%s' mismatch: %d != %d\n", test->cl_name, len, (int)strlen(test->cl_name));
			len = strlen(test->cl_name);
		}
#endif

		if (test->cl_father &&
		   (!parent || parent->d_class != test->cl_father)) {
			continue;
		}

		if (len > 0 &&
		   (namlen < len || memcmp(name, test->cl_name, len))) {
			continue;
		}

		// check special contexts
		if (test->cl_serial) {
			int plus = 0;
			int count;
			count = sscanf(name+len, "%d%n", serial, &plus);
			if (count < 1) {
				continue;
			}
			len += plus;
			if (name[len] == '-')
				len++;
		}
		if (prefix)
			*prefix = len;
		if (test->cl_hostcontext) {
			if (memcmp(name+len, my_id(), namlen-len)) {
				continue;
			}
		}

		// all ok
		status = class;
		*use_channel = test->cl_use_channel;
	}

#ifdef MARS_DEBUGGING
	brick_string_free(name);
#endif
	return status;
}

/* Do some syntactic checks, then delegate work to the real worker functions
 * from the main_classes[] table.
 */
static int main_worker(struct mars_global *global, struct mars_dent *dent, bool prepare, bool direction)
{
	main_worker_fn worker;
	int class = dent->d_class;
	bool is_deleted;

	if (class < 0 || class >= sizeof(main_classes)/sizeof(struct main_class)) {
		MARS_ERR_ONCE(dent, "bad internal class %d of '%s'\n", class, dent->d_path);
		return -EINVAL;
	}

	is_deleted = dent->new_link &&
		!strcmp(dent->new_link, MARS_DELETED_STR);

	switch (main_classes[class].cl_type) {
	case 'd':
		if (!S_ISDIR(dent->new_stat.mode) && !is_deleted) {
			MARS_ERR_ONCE(dent, "'%s' should be a directory, but is something else\n", dent->d_path);
			return -EINVAL;
		}
		break;
	case 'f':
		if (!S_ISREG(dent->new_stat.mode) && !is_deleted) {
			MARS_ERR_ONCE(dent, "'%s' should be a regular file, but is something else\n", dent->d_path);
			return -EINVAL;
		}
		break;
	case 'F':
		if (!S_ISREG(dent->new_stat.mode) && !S_ISLNK(dent->new_stat.mode)) {
			MARS_ERR_ONCE(dent, "'%s' should be a regular file or a symlink, but is something else\n", dent->d_path);
			return -EINVAL;
		}
		break;
	case 'l':
		if (!S_ISLNK(dent->new_stat.mode)) {
			MARS_ERR_ONCE(dent, "'%s' should be a symlink, but is something else\n", dent->d_path);
			return -EINVAL;
		}
		break;
	case 'L':
		if (!S_ISLNK(dent->new_stat.mode)) {
			/* ignore silently */
			return -EINVAL;
		}
		break;
	default:
		MARS_ERR_ONCE(dent, "'%s' class %d has unimplemented type %d\n",
			      dent->d_path, class, main_classes[class].cl_type);
		return -EINVAL;
	}
	if (likely(class > CL_ROOT)) {
		int father = main_classes[class].cl_father;
		if (father == CL_ROOT) {
			if (unlikely(dent->d_parent)) {
				MARS_ERR_ONCE(dent, "'%s' class %d is not at the root of the hierarchy\n", dent->d_path, class);
				return -EINVAL;
			}
		} else if (unlikely(!dent->d_parent || dent->d_parent->d_class != father)) {
			MARS_ERR_ONCE(dent, "last component '%s' from '%s' is at the wrong position in the hierarchy (class = %d, parent_class = %d, parent = '%s')\n", dent->d_name, dent->d_path, father, dent->d_parent ? dent->d_parent->d_class : -9999, dent->d_parent ? dent->d_parent->d_path : "");
			return -EINVAL;
		}
	}
	if (prepare) {
		worker = main_classes[class].cl_prepare;
	} else if (direction) {
		worker = main_classes[class].cl_backward;
	} else {
		worker = main_classes[class].cl_forward;
	}
	if (worker) {
		int status;
		if (!direction)
			MARS_DBG("--- start working %s on '%s' rest='%s'\n", direction ? "backward" : "forward", dent->d_path, dent->d_rest);
		status = worker(global, (void*)dent);
		MARS_DBG("--- done, worked %s on '%s', status = %d\n", direction ? "backward" : "forward", dent->d_path, status);
		return status;
	}
	return 0;
}

#define SAY_TEST_STR CONFIG_MARS_LOGDIR "/5.total.log"

static int _main_thread(void *data)
{
	long long last_rollover = jiffies;
	char *id = my_id();
	int status = 0;

	mars_global = alloc_mars_global();

	if (!id || strlen(id) < 2) {
		MARS_ERR("invalid hostname\n");
		status = -EFAULT;
		goto done;
	}	

	MARS_INF("-------- starting as host '%s' ----------\n", id);

        while (mars_global->global_power.button ||
	       !list_empty(&mars_global->brick_anchor)) {
		static const struct mars_brick_type *type_list[] = {
			(void *)&copy_brick_type,
			(void *)&client_brick_type,
			(void *)&aio_brick_type,
			(void *)&sio_brick_type,
			(void *)&bio_brick_type,
			NULL
		};
		struct kstat dummy;
		int say_status;
		struct list_head *tmp;
		int trigger_mode;
		int status;
		loff_t memlimit;

		say_status = mars_stat(SAY_TEST_STR, &dummy, true);
		if (!say_status)
			init_say();

		MARS_DBG("-------- NEW ROUND %d ---------\n", atomic_read(&server_handler_count));

		/* Static memlimit */
		if (mars_mem_percent < 0)
			mars_mem_percent = 0;
		if (mars_mem_percent > 70)
			mars_mem_percent = 70;
		if (mars_mem_gb < 1)
			mars_mem_gb = 1;
		memlimit = (long long)brick_global_memavail * mars_mem_percent / 100;
		if (memlimit > (long long)mars_mem_gb * 1024 * 1024)
			memlimit = (long long)mars_mem_gb * 1024 * 1024;

		/* Dynamic memlimit when /mars is becoming full */
		if (memlimit > global_remaining_space / 4)
			memlimit = global_remaining_space / 4;
		if (memlimit < 4)
			memlimit = 4;

		brick_global_memlimit = memlimit;

		_global_sync_nr = 0;

		brick_msleep(100);

		if (brick_thread_should_stop()) {
			mars_global->global_power.button = false;
			mars_net_is_alive = false;
		}

		_make_alive();

		compute_emergency_mode();

		MARS_DBG("-------- start worker ---------\n");

		down_write(&mars_resource_sem);
		brick_string_free(mars_resource_list);
		mars_resource_list = tmp_resource_list;
		up_write(&mars_resource_sem);
		tmp_resource_list = brick_strdup(GLOBAL_PATH_LIST);

		mars_global->deleted_min = 0;
		status = mars_dent_work(mars_global,
					"/mars",
					sizeof(struct mars_dent),
					main_checker, main_worker,
					mars_global,
					3, true);
		mars_global->deleted_border = mars_global->deleted_min;
		MARS_DBG("-------- worker deleted_min = %d status = %d\n",
			 mars_global->deleted_min, status);

		usable_features_version = _tmp_features_version;
		usable_strategy_version = _tmp_strategy_version;
		usable_digest_mask = _tmp_digest_mask;
		usable_compression_mask = (_tmp_compression_mask & available_compression_mask);
		_tmp_features_version = OPTIONAL_FEATURES_VERSION;
		_tmp_strategy_version = OPTIONAL_STRATEGY_VERSION;
		_tmp_digest_mask = available_digest_mask;
		_tmp_compression_mask = available_compression_mask;

		down_read(&rot_sem);
		for (tmp = rot_anchor.next; tmp != &rot_anchor; tmp = tmp->next) {
			struct mars_rotate *rot = container_of(tmp, struct mars_rotate, rot_head);

			rot->rot_activated = false;
		}
		up_read(&rot_sem);

		if (!mars_global->global_power.button) {
			status = mars_kill_brick_when_possible(mars_global,
							       type_list,
							       true);
		} else {
			status = mars_kill_brick_when_possible(mars_global,
							       type_list + 1,
							       true);
		}
		MARS_DBG("kill any  bricks (when possible) = %d\n", status);

		if ((long long)jiffies + mars_rollover_interval * HZ >= last_rollover) {
			last_rollover = jiffies;
			rollover_all();
		}

		global_sync_nr = _global_sync_nr;
		show_vals(gbl_pairs, "/mars", "");
		show_statistics(mars_global, "main");
		show_peers();

		MARS_DBG("ban_count = %d ban_renew_count = %d\n", mars_global_ban.ban_count, mars_global_ban.ban_renew_count);

		brick_msleep(500);

		wait_event_interruptible_timeout(mars_global->main_event,
						 mars_global->main_trigger,
						 mars_scan_interval * HZ);

		mars_global->main_trigger = false;
		additional_peers(mars_run_additional_peers - mars_running_additional_peers);
		trigger_mode = mars_global->trigger_mode;
		mars_global->trigger_mode = 0;
		if (trigger_mode) {
			__mars_full_trigger(trigger_mode);
		}
	}

done:
	MARS_INF("-------- cleaning up ----------\n");
	mars_remote_trigger();
	brick_msleep(1000);

	mars_free_dent_all(mars_global, &mars_global->dent_anchor);
	mars_kill_brick_all(mars_global, &mars_global->brick_anchor, false);

	show_vals(gbl_pairs, "/mars", "");
	show_statistics(mars_global, "main");

	brick_string_free(mars_resource_list);
	brick_string_free(tmp_resource_list);
	brick_mem_free(mars_global);
	mars_global = NULL;

	MARS_INF("-------- done status = %d ----------\n", status);
	//cleanup_mm();
	return status;
}

static
char *_mars_info(void)
{
	int max = PAGE_SIZE - 64;
	char *txt = brick_string_alloc(max);
	struct list_head *tmp;
	int dent_count = 0;
	int brick_count = 0;
	int pos = 0;

	if (unlikely(!txt || !mars_global)) {
		brick_string_free(txt);
		return NULL;
	}

	txt[--max] = '\0'; // safeguard

	down_read(&mars_global->brick_mutex);
	for (tmp = mars_global->brick_anchor.next; tmp != &mars_global->brick_anchor; tmp = tmp->next) {
		struct mars_brick *test;
		brick_count++;
		test = container_of(tmp, struct mars_brick, global_brick_link);
		pos += scnprintf(
			txt + pos, max - pos,
			"brick button=%d off=%d on=%d path='%s'\n",
			test->power.button,
			test->power.led_off,
			test->power.led_on,
			test->brick_path
			);
	}
	up_read(&mars_global->brick_mutex);

	down_read(&mars_global->dent_mutex);
	for (tmp = mars_global->dent_anchor.next; tmp != &mars_global->dent_anchor; tmp = tmp->next) {
		struct mars_dent *dent;
		dent_count++;
		dent = container_of(tmp, struct mars_dent, dent_link);
#if 0 // usually there is not enough space in PAGE_SIZE
		pos += scnprintf(
			txt + pos, max - pos,
			"dent stamp=%ld.%09ld path='%s' value='%s'\n",
			dent->new_stat.mtime.tv_sec, dent->new_stat.mtime.tv_nsec,
			SAFE_STR(dent->d_path),
			SAFE_STR(dent->new_link)
			);
#endif
	}
	up_read(&mars_global->dent_mutex);

	pos += scnprintf(
		txt + pos, max - pos,
		"SUMMARY: brick_count=%d dent_count=%d\n",
		brick_count,
		dent_count
		);

	return txt;
}

#define INIT_MAX 32
static char *exit_names[INIT_MAX] = {};
static void (*exit_fn[INIT_MAX])(void) = {};
static int exit_fn_nr = 0;

#define DO_INIT(name)						\
	MARS_DBG("=== starting module " #name "...\n");		\
	do {							\
		if ((status = init_##name()) < 0) goto done;	\
		exit_names[exit_fn_nr] = #name;			\
		exit_fn[exit_fn_nr++] = exit_##name;		\
	} while (0)


void (*_mars_remote_trigger)(bool do_all);
EXPORT_SYMBOL_GPL(_mars_remote_trigger);

static void exit_main(void)
{
	MARS_DBG("====================== stopping everything...\n");
	if (mars_global)
		mars_global->global_power.button = false;
	if (main_thread) {
		MARS_DBG("=== stopping main thread...\n");
		mars_net_is_alive = false;
		mars_trigger();
		MARS_INF("stopping main thread...\n");
		brick_thread_stop(main_thread);
	}

	mars_info = NULL;
	_mars_remote_trigger = NULL;

	while (exit_fn_nr > 0) {
		MARS_DBG("=== stopping module %s ...\n", exit_names[exit_fn_nr - 1]);
		exit_fn[--exit_fn_nr]();
	}

	MARS_DBG("====================== stopped everything.\n");
	exit_say();
	printk(KERN_INFO "stopped MARS\n");
	/* Workaround for nasty race: some kernel threads have not yet
	 * really finished even _after_ kthread_stop() and may execute
	 * some code which will disappear right after return from this
	 * function.
	 * A correct solution would probably need the help of the kernel
	 * scheduler.
	 */
	brick_msleep(1000);
}

static int __init init_main(void)
{
#ifdef MARS_HAS_PREPATCH
	extern int min_free_kbytes;
	int new_limit = 4096;
#endif
	struct kstat dummy;
	int status = mars_stat("/mars/uuid", &dummy, true);

	if (unlikely(status < 0)) {
		printk(KERN_ERR "cannot load MARS: cluster UUID is missing. Mount /mars/, and/or use {create,join}-cluster first.\n");
		return -ENOENT;
	}

	/* This must come first to be effective */
	status = mars_stat(SAY_TEST_STR, &dummy, true);
	if (!status)
		init_say();

#ifdef MARS_HAS_PREPATCH
	// bump the min_free limit
	if (min_free_kbytes < new_limit)
		min_free_kbytes = new_limit;
#endif

	printk(KERN_INFO "loading MARS, BUILDTAG=%s BUILDHOST=%s BUILDDATE=%s\n", BUILDTAG, BUILDHOST, BUILDDATE);

	/* be careful: order is important!
	 */
	DO_INIT(brick_mem);
	DO_INIT(brick);
	DO_INIT(mars);
	DO_INIT(mars_mapfree);
#ifdef CONFIG_MARS_DEBUG // otherwise currently unused
	DO_INIT(mars_dummy);
	DO_INIT(mars_check);
	DO_INIT(mars_buf);
	DO_INIT(mars_usebuf);
#endif
	DO_INIT(mars_net);
	DO_INIT(mars_client);
	DO_INIT(mars_aio);
	DO_INIT(mars_sio);
	DO_INIT(mars_bio);
	DO_INIT(mars_server);
	DO_INIT(mars_copy);
	DO_INIT(log_format);
	DO_INIT(mars_trans_logger);
	DO_INIT(mars_if);

	DO_INIT(sy);
	DO_INIT(sy_net);
	DO_INIT(mars_proc);

#ifdef CONFIG_MARS_MEM_PREALLOC
	brick_pre_reserve[5] = 64;
	brick_mem_reserve();
#endif

	status = compute_emergency_mode();
	if (unlikely(status < 0)) {
		MARS_ERR("Sorry, your /mars/ filesystem is too small!\n");
		goto done;
	}

	get_lamport(NULL, &modprobe_stamp);

	main_thread = brick_thread_create(_main_thread, NULL, "mars_main");
	if (unlikely(!main_thread)) {
		status = -ENOENT;
		goto done;
	}

done:
	if (status < 0) {
		MARS_ERR("module init failed with status = %d, exiting.\n", status);
		exit_main();
	}
	_mars_remote_trigger = __mars_remote_trigger;
	mars_info = _mars_info;
	return status;
}

// force module loading
const void *dummy1 = &client_brick_type;
const void *dummy2 = &server_brick_type;

MODULE_DESCRIPTION("MARS");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@{schoebel-theuer,1und1}.de>");
MODULE_VERSION(BUILDTAG " (" BUILDHOST " " BUILDDATE ")");
MODULE_LICENSE("GPL");

#ifdef MARS_HAS_PREPATCH
MODULE_INFO(prepatch, "has_prepatch");
#else
MODULE_INFO(prepatch, "no_prepatch");
#endif
#ifdef ENABLE_MARS_AIO
MODULE_INFO(io_driver, "aio");
#else
MODULE_INFO(io_driver, "sio");
#endif

#ifndef CONFIG_MARS_DEBUG
MODULE_INFO(debug, "production");
#else
MODULE_INFO(debug, "DEBUG");
#endif
#ifdef CONFIG_MARS_DEBUG_MEM
MODULE_INFO(io, "BAD_PERFORMANCE");
#endif
#ifdef CONFIG_MARS_DEBUG_ORDER0
MODULE_INFO(memory, "EVIL_PERFORMANCE");
#endif

module_init(init_main);
module_exit(exit_main);
