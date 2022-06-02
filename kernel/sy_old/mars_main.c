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

int usable_features_version = -1;
int usable_strategy_version = -1;

int marsadm_version_major = 0;
int marsadm_version_minor = 0;

static int _tmp_marsadm_version_major = -1;
static int _tmp_marsadm_version_minor = -1;

int usable_marsadm_version_major;
int usable_marsadm_version_minor;

__u32 disabled_log_digests = 0;
__u32 disabled_net_digests = 0;

static int _tmp_features_version = OPTIONAL_FEATURES_VERSION;
static int _tmp_strategy_version = OPTIONAL_STRATEGY_VERSION;

static __u32 _tmp_digest_mask    = MREF_CHKSUM_MD5_OLD;
static __u32 _tmp_compression_mask = MREF_COMPRESS_ANY;

static struct lamport_time oneshot_stamp;
static struct lamport_time _tmp_oneshot_stamp;
static char *oneshot_peer = NULL;
static char *_tmp_oneshot_peer = NULL;

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

int mars_min_update = 10;

struct lamport_time modprobe_stamp;

const char *my_uuid;

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
bool _compat_additional;

#ifdef CONFIG_MARS_DEBUG
int mars_test_additional_peers = 0;
#endif

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

void invalidate_user_cache(void)
{
	const char *path;

	path = path_make("/mars/cache-%s/invalid", my_id());
	ordered_symlink("1", path, NULL);
	brick_string_free(path);
}

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
	while (start && start->key) {
		brick_string_free(start->val);
		brick_string_free(start->old_val);
		start++;
	}
}

static
void _show_vals(struct key_value_pair *start,
	       const char *path,
	       const char *add,
	       bool silent)
{
	while (start && start->key) {
		char *dst = path_make("%s/actual-%s/msg-%s%s", path, my_id(), add, start->key);

		// show the old message for some keep_time if no new one is available
		if (!start->val && start->old_val &&
		    (long long)start->last_jiffies  + mars_keep_msg * HZ <= (long long)jiffies) {
			start->val = start->old_val;
			start->old_val = NULL;
		}
		if (silent) {
			brick_string_free(start->val);
			/* remove old message with minimum update frequency */
			if (!compat_deletions) {
				const char *check = ordered_readlink(dst, NULL);
				bool gone = (!check || !*check);

				brick_string_free(check);
				if (gone)
					ordered_symlink(MARS_DELETED_STR, dst, NULL);
				goto done;
			}
		}
		if (start->val) {
			char *src = path_make("%lld.%09ld %lld.%09ld %s",
					      (s64)start->system_stamp.tv_sec, start->system_stamp.tv_nsec,
					      (s64)start->lamport_stamp.tv_sec, start->lamport_stamp.tv_nsec,
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
		}
	done:
		brick_string_free(dst);
		start++;
	}
}

static inline
void show_vals(struct key_value_pair *start, const char *path, const char *add)
{
	_show_vals(start, path, add, false);
}

static inline
void assign_keys(struct key_value_pair *start, const char * const * keys)
{
	while (start && *keys) {
		start->key = *keys;
		start++;
		keys++;
	}
}

static inline
struct key_value_pair *find_key(struct key_value_pair *start, const char *key)
{
	while (start && start->key) {
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
const char * const rot_keys[] = {
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
	"inf-sync-start",
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

#define NR_ROT_KEYS (sizeof(rot_keys) / sizeof(char *))

#define make_rot_msg(rot, key, fmt, args...)			\
	make_msg(find_key((rot)->msgs, key), fmt, ##args)


#define IS_EXHAUSTED()             (mars_emergency_mode > 0)
#define IS_EMERGENCY_SECONDARY()   (mars_emergency_mode > 1)
#define IS_EMERGENCY_PRIMARY()     (mars_emergency_mode > 2)
#define IS_JAMMED()                (mars_emergency_mode > 3)

static bool write_alivelinks = false;
static bool compat_alivelinks = false;
static bool needed_compat_alivelinks = false;

/* for safety, consider both the old and new alivelink path */
static
void get_alivelink_stamp(const char *name, const char *peer,
			 struct lamport_time *stamp)
{
	const char *peer_time_path1 = NULL;
	const char *peer_time_path2 = NULL;
	struct kstat peer_time_stat1 = {};
	struct kstat peer_time_stat2 = {};

	peer_time_path1 = path_make("/mars/actual-%s/%s", peer, name);
	peer_time_path2 = path_make("/mars/%s-%s", name, peer);
	mars_stat(peer_time_path1, &peer_time_stat1, true);
	mars_stat(peer_time_path2, &peer_time_stat2, true);
	*stamp = peer_time_stat1.mtime;
	if (lamport_time_compare(&peer_time_stat1.mtime,
				 &peer_time_stat2.mtime) < 0) {
		needed_compat_alivelinks = true;
		*stamp = peer_time_stat2.mtime;
	}
	brick_string_free(peer_time_path1);
	brick_string_free(peer_time_path2);
}

static
bool is_alive(const char *peer)
{
	struct lamport_time now;
	struct lamport_time peer_time = {};

	get_real_lamport(&now);
	now.tv_sec -= 30;
	get_alivelink_stamp("alive", peer, &peer_time);
	return peer_time.tv_sec &&
		lamport_time_compare(&now, &peer_time) < 0;
}

/* for safety, consider both the old and new alivelink path */
static
const char *get_alivelink(const char *name, const char *peer)
{
	const char *path1 = path_make("/mars/actual-%s/%s", peer, name);
	const char *path2 = path_make("/mars/%s-%s", name, peer);
	struct lamport_time stamp1 = {};
	struct lamport_time stamp2 = {};
	const char *result1 = ordered_readlink(path1, &stamp1);
	const char *result2 = ordered_readlink(path2, &stamp2);

	if (lamport_time_compare(&stamp1, &stamp2) < 0) {
		needed_compat_alivelinks = true;
		brick_string_free(result1);
		result1 = result2;
	} else {
		brick_string_free(result2);
	}

	brick_string_free(path1);
	brick_string_free(path2);
	return result1;
}

static
void get_marsadm_version(const char *peer)
{
	const char *str = get_alivelink("marsadm-version", peer);
	int major = 0;
	int minor = 0;

	if (str && *str) {
		sscanf(str, "%d.%d", &major, &minor);
	}
	brick_string_free(str);
	if (!strcmp(peer, my_id())) {
		marsadm_version_major = major;
		marsadm_version_minor = minor;
	}
	if (_tmp_marsadm_version_major < 0 ||
	    _tmp_marsadm_version_major < major ||
	    (_tmp_marsadm_version_major == major &&
	     _tmp_marsadm_version_minor < minor)) {
		_tmp_marsadm_version_major = major;
		_tmp_marsadm_version_minor = minor;
	}
}

static
void __make_alivelink_str_old(const char *name, const char *src, bool lazy)
{
	char *dst = path_make("/mars/%s-%s", name, my_id());

	if (!src || !dst) {
		MARS_ERR("cannot make alivelink paths\n");
		goto err;
	}
	if (lazy) {
		char *check = mars_readlink(dst, NULL);
		bool ok = (check && !strcmp(check, src));

		brick_string_free(check);
		if (ok) {
			MARS_DBG("symlink '%s' -> '%s' has not changed\n", src, dst);
			goto err;
		}
	}
	MARS_DBG("'%s' -> '%s'\n", src, dst);
	if (write_alivelinks)
		ordered_symlink(src, dst, NULL);
err:
	brick_string_free(dst);
}

static
void __make_alivelink_str(const char *name, const char *src, bool lazy)
{
	char *dst = path_make("/mars/actual-%s/%s", my_id(), name);

	if (!src || !dst) {
		MARS_ERR("cannot make alivelink paths\n");
		goto err;
	}
	if (compat_alivelinks)
		__make_alivelink_str_old(name, src, lazy);
	if (lazy) {
		char *check = mars_readlink(dst, NULL);
		bool ok = (check && !strcmp(check, src));

		brick_string_free(check);
		if (ok) {
			MARS_DBG("symlink '%s' -> '%s' has not changed\n", src, dst);
			goto err;
		}
	}
	MARS_DBG("'%s' -> '%s'\n", src, dst);
	if (write_alivelinks)
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
	__make_alivelink("total-space", present / (1024 * 1024), true);

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
void _timeout_prev(struct mars_brick *brick)
{
	int i;

	for (i = 0; i < brick->nr_inputs; i++) {
		struct mars_input *this_input;
		struct mars_output *prev_output;
		struct mars_brick *prev_brick;

		this_input = (void *)brick->inputs[i];
		if (!this_input)
			continue;
		prev_output = this_input->connect;
		if (!prev_output)
			continue;
		prev_brick = prev_output->brick;
		if (!prev_brick)
			continue;
		MARS_DBG("'%s' %d '%s' io_timeout\n",
			 brick->brick_path,
			 i,
			 prev_brick->brick_path);
		prev_brick->power.io_timeout = 1;
	}
}

static
struct mars_brick *_kill_brick(struct mars_brick *brick)
{
	int status;

	MARS_DBG("brick '%s' forceful shutdown\n", brick->brick_path);

	/* any predecessors should timeout ASAP */
	_timeout_prev(brick);

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

typedef int (*main_worker_fn)(struct mars_dent *dent);

struct main_class {
	main_worker_fn cl_prepare;
	main_worker_fn cl_forward;
	main_worker_fn cl_backward;
	char  *cl_name;
	short  cl_len;
	char   cl_type;
	bool   cl_hostcontext;
	bool   cl_serial;
	bool   cl_use_channel;
	short  cl_father;
	short  cl_childs;
};

// the order is important!
enum {
	// root element: this must have index 0
	CL_ROOT,
	// global ID
	CL_UUID,
	// global userspace
	CL_GLOBAL_USERSPACE,
	CL_DEFAULTS0,
	CL_DEFAULTS,
	// global todos
	CL_GLOBAL_TODO,
	// replacement for DNS in kernelspace
	CL_IPS,
	CL_GBL_ACTUAL,
	CL_COMPAT_DELETIONS, /* transient, to re-disappear */
	// resource definitions
	CL_RESOURCE,
	/* subdir items */
	CL_DEFAULTS_ITEMS0,
	CL_DEFAULTS_ITEMS,
	CL_GLOBAL_TODO_DELETE,
	CL_GLOBAL_TODO_DELETED,
	CL_PEERS,
	/* Resource items */
	CL_RESOURCE_USERSPACE,
	CL_RES_DEFAULTS0,
	CL_RES_DEFAULTS,
	CL_RES_TODO,
	CL_RES_ACTUAL,
	CL_DATA,
	CL_SIZE,
	CL_PRIMARY,
	CL__FILE,
	CL_CONNECT,
	CL_SYNC,
	CL__COPY,
	CL__DIRECT,
	CL_LOG,
	CL_REPLAYSTATUS,
	CL_DEVICE,
};

/* Performance optimization:
 * Check whether an incative subtree can be skipped.
 */
static
void skip_scan_resource(struct mars_dent *dent)
{
	const char *probe_path;
	const char *probe_link;

	if (!dent->d_name ||
	    !dent->d_path ||
	    strncmp(dent->d_name, "resource-", 9)) {
		dent->d_no_scan = false;
		dent->d_running = true;
		MARS_DBG("no check '%s'\n", dent->d_path);
		return;
	}

	probe_path = path_make("%s/device-%s", dent->d_path, my_id());
	probe_link = ordered_readlink(probe_path, NULL);
	dent->d_no_scan = (!probe_link || !probe_link[0]);
	brick_string_free(probe_path);
	brick_string_free(probe_link);
	if (!dent->d_no_scan)
		dent->d_running = true;
	else if (!dent->d_private)
		dent->d_running = false;
	MARS_DBG("d_no_scan=%d d_running=%d '%s'\n",
		 dent->d_no_scan,
		 dent->d_running,
		 dent->d_path);
}

///////////////////////////////////////////////////////////////////////

/* Per-resource information (not only for logfile rotation)
 */

static inline
void assign_dent(struct mars_dent **ptr, struct mars_dent *new_dent)
{
	struct mars_dent *old_dent = *ptr;

	if (old_dent == new_dent)
		return;
	if (old_dent)
		atomic_dec(&old_dent->d_count);
	*ptr = new_dent;
	if (new_dent)
		atomic_inc(&new_dent->d_count);
}

#define INFS_MAX (TL_INPUT_LOG2 - TL_INPUT_LOG1 + 1)

struct mars_rotate {
	struct list_head rot_head;
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
	const char *log_from_peer;
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
	struct lamport_time found_double_logfile;
	int inf_prev_sequence;
	int inf_old_sequence;
	long long flip_start;
	loff_t sync_copy_last;
	loff_t sync_copy_last_old;
	loff_t dev_size;
	loff_t start_pos;
	loff_t end_pos;
	int nr_members;
	int tmp_members;
	int retry_log_from;
	int retry_recovery;
	int max_sequence;
	int flip_round;
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
	bool is_attached;
	bool res_shutdown;
	bool has_error;
	bool has_double_logfile;
	bool has_hole_logfile;
	bool allow_update;
	bool rot_activated;
	bool old_fetch_on;
	bool want_sync;
	bool forbid_replay;
	bool replay_mode;
	bool todo_primary;
	bool stop_logger;
	bool checked_reboot;
	bool is_primary;
	bool old_is_primary;
	bool was_primary_before;
	bool had_primary_crash;
	bool created_hole;
	bool is_log_damaged;
	bool has_emergency;
	bool log_is_really_damaged;
	struct mutex inf_mutex;
	bool infs_is_dirty[INFS_MAX];
	struct trans_logger_info infs[INFS_MAX];
	struct trans_logger_info current_inf;
	struct key_value_pair msgs[NR_ROT_KEYS];
};

static struct rw_semaphore rot_sem = __RWSEM_INITIALIZER(rot_sem);
static LIST_HEAD(rot_anchor);

static
const char *get_primary_host(struct mars_rotate *rot)
{
	char  *tmp = path_make("%s/primary", rot->parent_path);
	const char *primary = ordered_readlink(tmp, NULL);

	brick_string_free(tmp);
	return primary;
}

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

	if (!strcmp(str, MARS_DELETED_STR))
		str = "";

	brick_string_free(dent->d_args);
	dent->d_args = brick_strdup(str);

	for (i = 0; i < count; i++) {
		char *test = strchr(str, MARS_DELIM);
		char *tmp;
		int len;

		if (test)
			len = (test - str);
		else
			len = strlen(str);

		if (unlikely(len <= 0) && *dent->d_args)
			MARS_ERR("arg %d of '%s' is empty\n",
				 i, dent->d_args);
		
		tmp = brick_string_alloc(len + 1);
		strncpy(tmp, str, len);
		tmp[len] = '\0';
		brick_string_free(dent->d_argv[i]);
		dent->d_argv[i] = tmp;

		str += len;
		if (test && *str)
			str++;
	}
	if (*dent->d_args)
		status = 0;

done:
	return status;
}

static
int _check_switch(const char *path)
{
	int res = 0;
	const char *val_str = NULL;
 
 	/* Upon shutdown, treat all switches as "off"
 	 */
 	if (!mars_global->global_power.button)
 		goto done;
 
	val_str = ordered_readlink(path, NULL);
	if (!val_str || !val_str[0])
 		goto done;
	sscanf(val_str, "%d", &res);
 	MARS_DBG("'%s' -> %d\n", path, res);
 
 done:
	brick_string_free(val_str);
	return res;
}

static
int _check_allow(const char *parent_path, const char *name)
{
	int res = 0;
	char *path = path_make("%s/todo-%s/%s", parent_path, my_id(), name);

	if (!path)
		goto done;

	res = _check_switch(path);

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
int compare_replaylinks(struct mars_rotate *rot,
			const char *hosta,
			const char *hostb,
			loff_t *save_a,
			loff_t *save_b)
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

	a = ordered_readlink(linka, NULL);
	if (unlikely(!a || !a[0])) {
		MARS_ERR_TO(rot->log_say, "cannot read replaylink '%s'\n", linka);
		goto done;
	}
	b = ordered_readlink(linkb, NULL);
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

	/* The seqence number is equal.
	 * Now the base offsets are comparable.
	 */

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
	} else if (save_a)
		*save_a = offa;
	count = sscanf(b + posb, "%lld", &offb);
	if (unlikely(count != 1)) {
		MARS_ERR_TO(rot->log_say, "replay link '%s' -> '%s' is malformed\n", linkb, b);
	} else if (save_b)
		*save_b = offb;

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
int _update_link_when_necessary(struct mars_rotate *rot,
				const char *type,
				const char *old, const char *new,
				bool do_force)
{
	char *check = NULL;
	struct lamport_time limit;
	struct lamport_time stamp = {};
	int status = -EINVAL;
	bool res = false;

	if (unlikely(!old || !new))
		goto out;
	if (do_force)
		goto force;

	get_real_lamport(&limit);

	/* Check whether something really has changed (avoid
	 * useless/disturbing timestamp updates)
	 * However, some minimum update frequency should not be
	 * undershot too much.
	 */
	check = ordered_readlink(new, &stamp);
	limit.tv_sec += mars_min_update;
	if (check &&
	    !strcmp(check, old) &&
	    (!stamp.tv_sec ||
	     (lamport_time_compare(&stamp, &limit) <= 0))) {
		MARS_DBG("%s symlink '%s' -> '%s' has not changed\n", type, old, new);
		res = 0;
		goto out;
	}

 force:
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

	res = _update_link_when_necessary(rot, "replay", old, new, false);

out:
	brick_string_free(new);
	brick_string_free(old);
	return res;
}

static
int _update_version_link(struct mars_rotate *rot,
			 struct trans_logger_info *inf,
			 bool do_check,
			 bool do_force)
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
			char *skip_link = ordered_readlink(skip_path, NULL);
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
		prev_link = ordered_readlink(prev, NULL);
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

	res = _update_link_when_necessary(rot , "version", old, new, do_force);

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
bool _is_trans_input_fully_working(struct trans_logger_input *trans_input)
{
	struct mars_brick *prev_brick;

	if (!trans_input ||
	    !trans_input->connect)
		return false;

	prev_brick = (void *)trans_input->connect->brick;
	if (!prev_brick ||
	    !prev_brick->power.button ||
	    !prev_brick->power.led_on)
		return false;
	return true;
}

static
bool is_trans_input_fully_working(struct mars_rotate *rot, int input_nr)
{
	struct trans_logger_input *trans_input;

	trans_input = rot->trans_brick->inputs[input_nr];
	return _is_trans_input_fully_working(trans_input);
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
		int inf_nr;

		if (!is_trans_input_fully_working(rot, i))
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
		count += _update_version_link(rot, &rot->current_inf,
					      true, false);
		if (min > rot->inf_old_sequence) {
			mars_sync();
			rot->inf_old_sequence = min;
		}
	}
	if (count) {
		if (rot->current_inf.inf_min_pos == rot->current_inf.inf_max_pos)
			mars_trigger();
		if (rot->todo_primary | rot->is_primary | rot->old_is_primary)
			mars_remote_trigger(MARS_TRIGGER_TO_REMOTE);
	}
}

static
void _recover_versionlink(struct mars_rotate *rot,
			  const char *host,
			  int sequence,
			  loff_t end_pos)
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

	/* Here we force an update, even when nothing changes.
	 * So the effect of repair can be seen via timestamp.
	 */
	_update_version_link(rot, &inf, false, true);
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
	int code = MARS_TRIGGER_LOCAL;

	strncpy(inf.inf_host, new_host, sizeof(inf.inf_host));

	MARS_DBG("new_host = '%s' new_sequence = %d end_pos = %lld\n", new_host, new_sequence, end_pos);

	_update_replay_link(rot, &inf);
	_update_version_link(rot, &inf, false, false);

	if (rot->todo_primary | rot->is_primary | rot->old_is_primary)
		code |= MARS_TRIGGER_TO_REMOTE;
	mars_remote_trigger(code);
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

static
int __show_stamp(const char *path, const char *name, struct lamport_time *stamp)
{
	char *src;
	char *dst = NULL;
	int status = -EINVAL;

	src = path_make("%lld.%09ld",
			(s64)stamp->tv_sec,
			stamp->tv_nsec);
	dst = path_make("%s/actual-%s/%s", path, my_id(), name);

	MARS_DBG("symlink '%s' -> '%s'\n", dst, src);
	status = ordered_symlink(src, dst, NULL);

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
		mars_remote_trigger(MARS_TRIGGER_LOCAL | MARS_TRIGGER_TO_REMOTE);
	}
}

static
void _show_brick_status(struct mars_brick *brick,
			const char *path,
			const char *name)
{
	const char *new_name;

	new_name = path_make("%s-on", name);
	_show_actual(path, new_name,
		     brick ? brick->power.button & brick->power.led_on : false);
	brick_string_free(new_name);
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
int __make_copy(struct mars_dent *belongs,
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

	if (!switch_path) {
		goto done;
	}

	// don't generate empty aio files if copy does not yet exist
	switch_copy = _check_switch(switch_path);
	copy = mars_find_brick(mars_global, &copy_brick_type, copy_path);
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
			make_brick_all(mars_global,
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
		MARS_DBG("'%s' io_timeout=%d\n",
			 aio->brick_path,
			 aio->power.io_timeout);
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
		make_brick_all(mars_global,
			       belongs,
			       _set_copy_params,
			       &cc,
			       cc.fullpath[1],
			       (const struct generic_brick_type*)&copy_brick_type,
			       (const struct generic_brick_type*[]){NULL,NULL,NULL,NULL},
			       switch_copy ? 2 : -1,
			       "%s",
			       (const char *[]){"%s", "%s"},
			       2,
			       copy_path,
			       cc.fullpath[0],
			       cc.fullpath[1]);
	if (copy) {
		struct copy_brick *_copy = (void*)copy;
		make_msg(msg_pair,
			 "from = '%s' to = '%s'"
			 " on = %d start_pos = %lld end_pos = %lld"
			 " actual_pos = %lld actual_stamp = %lld.%09ld"
			 " ops_rate = %d amount_rate = %d"
			 " read_fly = %d write_fly = %d error_code = %d nr_errors = %d",
			 argv[0],
			 argv[1],
			 _copy->power.led_on,
			 _copy->copy_start,
			 _copy->copy_end,
			 _copy->copy_last,
			 (s64)_copy->copy_last_stamp.tv_sec, _copy->copy_last_stamp.tv_nsec,
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

static bool start_full_fetch;
static bool tmp_full_fetch;

struct push_info {
	struct list_head push_head;
	const char *src;
	const char *dst;
	int cmd_code;
};

static DECLARE_RWSEM(peer_list_lock);
static int peer_count = 0;
static
struct list_head peer_anchor = LIST_HEAD_INIT(peer_anchor);

struct mars_peerinfo {
	struct mars_global *remote_global;
	char *peer;
	char *peer_ip;
	char *rebase_dir;
	char *peer_dir_list;
	struct mars_socket socket;
	struct task_struct *peer_thread;
	/* protects:
	 * peer->remote_global
	 * peer->push_anchor, push->push_head
	 */
	struct mutex peer_lock;
	/* Protected by global peer_list_lock */
	struct list_head peer_head;
	struct list_head push_anchor;
	struct lamport_time remote_start_stamp;
	unsigned long create_jiffies;
	unsigned long last_remote_jiffies;
	int maxdepth;
	int features_version;
	int strategy_version;
	__u32 available_mask;
	int  nr_dents;
	bool need_destruct;
	bool in_destruct;
	bool to_terminate;
	bool has_terminated;
	bool to_remote_trigger;
	bool from_remote_trigger;
	bool do_entire_once;
	bool oneshot;
	bool no_fetch;
	bool got_info;
	bool silent;
};

static
char *make_peer_dir_list(const char *mypeer)
{
	char *res;

	res = path_make("|/mars/defaults-%s/"
			"|/mars/actual-%s/",
			mypeer,
			mypeer
			);
	return res;
}

static
void _init_peer(struct mars_peerinfo *peer, const char *peer_name, const char *peer_ip)
{
	/* determine marsadm version once per peer */
	get_marsadm_version(peer_name);

	peer->peer = brick_strdup(peer_name);
	if (peer_ip)
		peer->peer_ip = brick_strdup(peer_ip);

	peer->peer_dir_list = make_peer_dir_list(peer_name);


	peer->maxdepth = 2;
	peer->features_version = 0;
	peer->strategy_version = 0;
	peer->available_mask = 0;

	mutex_init(&peer->peer_lock);
	INIT_LIST_HEAD(&peer->peer_head);
	INIT_LIST_HEAD(&peer->push_anchor);
	peer->create_jiffies = jiffies;

	/* always trigger on peer startup */
	peer->from_remote_trigger = true;
	peer->to_remote_trigger = true;
}


static
struct mars_peerinfo *new_peer(const char *peer_name, const char *peer_ip)
{
	struct mars_peerinfo *peer;

	peer = brick_zmem_alloc(sizeof(struct mars_peerinfo));

	_init_peer(peer, peer_name, peer_ip);

	down_write(&peer_list_lock);
	list_add_tail(&peer->peer_head, &peer_anchor);
	peer_count++;
	up_write(&peer_list_lock);

	return peer;
}

static
struct mars_dent *find_peer_dent(const char *peer_name)
{
	const char *peer_path;
	struct mars_dent *res;

	peer_path = path_make("/mars/ips/ip-%s", peer_name);
	res = mars_find_dent(mars_global, peer_path);
	brick_string_free(peer_path);
	return res;
}

static
struct mars_peerinfo *find_peer(const char *peer_name)
{
	struct mars_dent *peer_dent;
	struct mars_peerinfo *res = NULL;

	peer_dent = find_peer_dent(peer_name);
	if (peer_dent)
		res = peer_dent->d_private;
	return res;
}

static int _kill_peer(struct mars_peerinfo *peer);
static int run_bones(struct mars_peerinfo *peer);

static
void show_peers(void)
{
	struct mars_peerinfo * to_kill = NULL;
	struct list_head *tmp;

	down_read(&peer_list_lock);
	MARS_DBG("PEER_count = %d\n", peer_count); 
	for (tmp = peer_anchor.next; tmp != &peer_anchor; tmp = tmp->next) {
		struct mars_peerinfo *peer;

		peer = container_of(tmp, struct mars_peerinfo, peer_head);
		MARS_DBG("PEER '%s' oneshot=%d alive=%d trigg=%d/%d\n",
			 peer->peer,
			 peer->oneshot,
			 mars_socket_is_alive(&peer->socket),
			 peer->to_remote_trigger,
			 peer->from_remote_trigger);

		if (peer->need_destruct &&
		    (peer->has_terminated ||
		     !mars_net_is_alive))
			to_kill = peer;
	}
	up_read(&peer_list_lock);

	/* As a side effect, kill any terminated floating peers.
	 */
	if (to_kill) {
		run_bones(to_kill);
		_kill_peer(to_kill);
		brick_mem_free(to_kill);
		mars_running_additional_peers--;
	}
}

static
int peer_thread(void *data);

static
int start_peer(struct mars_peerinfo *peer)
{
	static int serial = 0;

	if (peer->peer_thread) {
		if (!peer->has_terminated) {
			MARS_DBG("peer thread '%s' already running\n",
				 peer->peer);
			return 0;
		}
		brick_thread_stop(peer->peer_thread);
		peer->peer_thread = NULL;
	}

	if (!mars_net_is_alive)
		return 0;

	peer->to_terminate = false;
	peer->has_terminated = false;
	peer->peer_thread =
		brick_thread_create(peer_thread,
				    peer,
				    "peer%d/%s",
				    serial++,
				    peer->peer);
	if (unlikely(!peer->peer_thread)) {
		peer->has_terminated = true;
		MARS_ERR("cannot start peer thread '%s'\n", peer->peer);
		return -ENOMEM;
	}
	MARS_DBG("started peer thread '%s'\n", peer->peer);
	return 0;
}

static
void peer_destruct(void *_peer);

bool _push_info(const char *peer_name,
		const char *peer_ip,
		const char *src,
		const char *dst,
		int cmd_code)
{
	struct mars_dent *peer_dent;
	struct mars_peerinfo *_peer = NULL;
	struct mars_peerinfo *peer = NULL;
	struct push_info *push;

	if (unlikely(!peer_name ||
		     !peer_name[0] ||
		     !strcmp(peer_name, my_id()))) {
		MARS_WRN("invalid peer_name '%s'\n", peer_name);
		return false;
	}

	peer_dent = find_peer_dent(peer_name);

	/* ignore any existing peers talking on a different IP */
	if (peer_dent && peer_ip) {
		struct mars_peerinfo *check_peer;

		check_peer = peer_dent->d_private;
		if (check_peer && check_peer->peer_ip &&
		    strcmp(check_peer->peer_ip, peer_ip))
			peer_dent = NULL;

	}
	if (peer_dent) {
		peer = peer_dent->d_private;
		if (peer &&
		    unlikely(READ_ONCE(peer->in_destruct))) {
			MARS_WRN("peer '%s' %p is under destruction\n",
				 peer_name, peer);
			return false;
		}
	}
	/* Create a dynamic peer.
	 * Only needed in special cases like join-cluster /
	 * merge-cluster / etc.
	 */
	if (!peer) {
		_peer = new_peer(peer_name, peer_ip);
		peer = _peer;
		if (peer_dent && !peer_dent->d_private) {
			/* Register this one as a semi-permanent peer.
			 * This is needed for two-way communication.
			 */
			peer_dent->d_private = peer;
			peer_dent->d_private_destruct = peer_destruct;
		} else {
			/* Register this one as a temporary peer.
			 * Only one-way communication.
			 */
			mars_running_additional_peers++;
			peer->need_destruct = true;
			peer->oneshot = true;
			peer->do_entire_once = true;
			peer->silent = true;
			/* pure push: do not fetch from remote */
			peer->no_fetch = true;
			peer->from_remote_trigger = false;
			peer->to_remote_trigger = true;
		}
		MARS_DBG("new peer %p\n", peer);
	}
	push = brick_zmem_alloc(sizeof(struct push_info));
	INIT_LIST_HEAD(&push->push_head);
	push->src = brick_strdup(src);
	push->dst = brick_strdup(dst);
	push->cmd_code = cmd_code;

	mutex_lock(&peer->peer_lock);
	list_add_tail(&push->push_head, &peer->push_anchor);
	mutex_unlock(&peer->peer_lock);

	if (_peer)
		start_peer(_peer);
	mars_trigger();
	return true;
}

/* Please use this only for _initialization_ of new memberships etc,
 * but never for ordinary operations.
 * Normally, the PULL PRINCIPLE is the prefered one.
 * TODO: more security considerations beyond port firewalling.
 */
bool push_link(const char *peer_name,
	       const char *peer_ip,
	       const char *src,
	       const char *dst)
{
	return _push_info(peer_name, peer_ip,
			  src, dst, CMD_PUSH_LINK);
}

bool push_check(const char *peer_name,
		const char *peer_ip,
		const char *path)
{
	return _push_info(peer_name, peer_ip,
			  my_id(), path, CMD_PUSH_CHECK);
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
#ifdef CONFIG_MARS_SEPARATE_PORTS
	const char *tmp = path_make("%s@%s:%d", file, peer, mars_net_default_port + MARS_TRAFFIC_REPLICATION);
#else
	const char *tmp = path_make("%s@%s", file, peer);
#endif
	const char *argv[2] = { tmp, file };
	struct copy_brick *copy = NULL;
	struct key_value_pair *msg_pair;
	loff_t start_pos;
	bool do_start = true;
	int status = -ENOMEM;

	if (unlikely(!rot || !tmp))
		goto done;

	msg_pair = find_key(rot->msgs, "inf-fetch");

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
	if (do_start && !_check_allow(rot->parent_path, "attach")) {
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
	if (do_start && !_check_allow(parent->d_path, "attach")) {
		MARS_DBG("disabling fetch due to detach\n");
		make_msg(msg_pair, "disabling fetch due to detach");
		do_start = false;
	}
#endif
	if (do_start && !_check_allow(parent->d_path, "connect")) {
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

	status = __make_copy(NULL,
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
		if (do_start)
			rot->retry_log_from = 0;
#if 0
		// FIXME: code is dead
		if (copy->append_mode && copy->power.led_on &&
		    end_pos > copy->copy_end) {
			MARS_DBG("appending to '%s' %lld => %lld\n", copy_path, copy->copy_end, end_pos);
			// FIXME: use corrected length from mars_get_info() / see _set_copy_params()
			copy->copy_end = end_pos;
		}
#endif
		/* When done, immediately trigger next fetch from peers */
		if (rot->old_fetch_on && !copy->power.led_on) {
			mars_remote_trigger(MARS_TRIGGER_LOCAL | MARS_TRIGGER_FROM_REMOTE);
		}
		rot->old_fetch_on = copy->power.led_on;
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
	/* Try to prefer the peer which created the logfile.
	 * This need not coincide with the current primary.
	 * Reason: transitive fetch may get stuck in a cycle.
	 */
	if (rot->log_from_peer &&
	    strcmp(peer, rot->log_from_peer) &&
	    (remote_dent->d_serial < rot->repair_log_seq ||
	     remote_dent->d_serial > rot->repair_log_seq + 1 ||
	     rot->retry_log_from++ <= rot->nr_members)) {
		MARS_DBG("peer '%s' != '%s' not the origin of '%s'\n",
			 peer, rot->log_from_peer,
			 rot->replay_link ? rot->replay_link->new_link : "");
		status = -EAGAIN;
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
void touch_systemd_trigger(const char *filename)
{
	struct file *f;
	const int flags = O_CREAT | O_NOFOLLOW | O_RDWR;
	const int prot = 0600;
	struct lamport_time now;
	int len;
	loff_t dummy_pos = 0;
	mm_segment_t oldfs;
	char str[32];

	get_real_lamport(&now);

	len = snprintf(str, sizeof(str),
		       "%lld.%09ld\n",
		       (s64)now.tv_sec, now.tv_nsec);
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	f = filp_open(filename, flags, prot);
	if (!f || IS_ERR(f)) {
		/* remove any .deleted symlink and try again */
		mars_unlink(filename);
		f = filp_open(filename, flags, prot);
	}
	if (f && !IS_ERR(f)) {
#ifdef MARS_HAS_KERNEL_READ
		(void)kernel_write(f, str, len, &dummy_pos);
#else
		(void)vfs_write(f, str, len, &dummy_pos);
#endif
		filp_close(f, NULL);
	}
	set_fs(oldfs);
}

static
bool systemd_per_resource_trigger(const char *remote_path)
{
	const char *trig_path;

	/* Ignore any userspace activities */
	if (strstr(remote_path, "/userspace/"))
		return false;

	/* Fallback to global trigger upon global activities */
	if (strstr(remote_path, "/todo-global/"))
		return true;

	trig_path = backskip_replace(remote_path, '/',
				     false,
				     "/systemd-trigger");
	/* error fallback to global trigger */
	if (unlikely(!trig_path))
		return true;
	if (unlikely(!trig_path[0])) {
		brick_string_free(trig_path);
		return true;
	}

	touch_systemd_trigger(trig_path);
	brick_string_free(trig_path);
	return false;
}

static
int run_bone(struct mars_peerinfo *peer, struct mars_dent *remote_dent)
{
	int status = 0;
	struct kstat local_stat = {};
	const char *remote_path;
	const char *to_free = NULL;
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

	remote_path = remote_dent->d_path;
	/* Allow rebasing to a different root */
	if (peer->rebase_dir && remote_path) {
		if (*remote_path == '/')
			to_free = path_make("%s%s",
				    peer->rebase_dir, remote_path);
		else
			to_free = path_make("%s/%s",
				    peer->rebase_dir, remote_path);
		remote_path = to_free;
	}
	if (remote_dent->new_link &&
	    !strncmp(remote_path, "/mars/todo-global/delete-", 25)) {
		if (remote_dent->d_serial < mars_global->deleted_my_border) {
			MARS_DBG("ignoring deletion '%s' at border %d\n",
				 remote_path,
				 mars_global->deleted_my_border);
			goto done;
		}
	}

	/* Skip unwanted directories */
	if (S_ISDIR(remote_dent->new_stat.mode) &&
	    remote_dent->d_rest &&
	    remote_path &&
	    strncmp(remote_path, "/mars/", 6) &&
	    !find_peer_dent(remote_dent->d_rest)) {
		MARS_DBG("skipping remote dir '%s' for unknown peer '%s'\n",
			 remote_path,
			 remote_dent->d_rest);
		goto done;
	}

	status = mars_stat(remote_path, &local_stat, true);
	stat_ok = (status >= 0);

	is_deleted = remote_dent->new_link &&
		!strcmp(remote_dent->new_link, MARS_DELETED_STR);

	if (stat_ok) {
		update_mtime = lamport_time_compare(&remote_dent->new_stat.mtime, &local_stat.mtime) > 0;
		update_ctime = lamport_time_compare(&remote_dent->new_stat.ctime, &local_stat.ctime) > 0;

		MARS_IO("timestamps '%s' remote = %lld.%09ld local = %lld.%09ld\n",
			remote_path,
			(s64)remote_dent->new_stat.mtime.tv_sec, remote_dent->new_stat.mtime.tv_nsec,
			(s64)local_stat.mtime.tv_sec, local_stat.mtime.tv_nsec);

#ifdef MARS_HAS_PREPATCH
		if ((remote_dent->new_stat.mode & S_IRWXU) !=
		   (local_stat.mode & S_IRWXU) &&
		   update_ctime) {
			mode_t newmode = local_stat.mode;
			MARS_DBG("chmod '%s' 0x%xd -> 0x%xd\n", remote_path, newmode & S_IRWXU, remote_dent->new_stat.mode & S_IRWXU);
			newmode &= ~S_IRWXU;
			newmode |= (remote_dent->new_stat.mode & S_IRWXU);
			mars_chmod(remote_path, newmode);
			run_trigger = true;
		}
#endif
	}

	if (S_ISDIR(remote_dent->new_stat.mode)) {
		if (!_is_usable_dir(remote_dent->d_name)) {
			MARS_DBG("ignoring directory '%s'\n", remote_path);
			goto done;
		}
		if (!stat_ok) {
			status = mars_mkdir(remote_path);
			MARS_DBG("create directory '%s' status = %d\n", remote_path, status);
#ifdef MARS_HAS_PREPATCH
			if (status >= 0) {
				mars_chmod(remote_path, remote_dent->new_stat.mode);
			}
#endif
		}
	} else if (S_ISLNK(remote_dent->new_stat.mode) && remote_dent->new_link) {
		/* is something in /mars/ips/ (or a guest membership) updated ? */
		if ((!stat_ok ||
		     lamport_time_compare(&remote_dent->new_stat.mtime,
					  &local_stat.mtime) > 0) &&
		    (!strncmp(remote_dent->d_name, "device-", 7) ||
		     !strncmp(remote_path, MARS_IP_STR, strlen(MARS_IP_STR))))
			invalidate_user_cache();

		/* Important: not not create .deleted values
		 * unless the object already exists.
		 */
		if (is_deleted ?
		    (stat_ok && update_mtime) :
		    (!stat_ok || update_mtime)) {
			/* safeguard any replacement of files with symlinks */
			if (stat_ok && S_ISREG(local_stat.mode)) {
				(void)mars_unlink(remote_path);
			}
			status = ordered_symlink(remote_dent->new_link,
						 remote_path,
						 &remote_dent->new_stat.mtime);
			MARS_DBG("create symlink '%s' -> '%s' status = %d\n",
				 remote_path, remote_dent->new_link, status);
			run_trigger = true;
			if (status >= 0 &&
			    !peer->rebase_dir &&
			    (!strncmp(remote_dent->d_name, "primary", 7) ||
			     !strncmp(remote_dent->d_name, "systemd", 7)))
				run_systemd_trigger |=
					systemd_per_resource_trigger(remote_path);
		}
	} else if (S_ISREG(remote_dent->new_stat.mode) &&
		   _is_peer_logfile(remote_dent->d_name, my_id())) {
		const char *parent_path = backskip_replace(remote_path, '/', false, "");

		if (likely(parent_path)) {
			struct mars_dent *parent;
			struct mars_rotate *rot;

			parent = mars_find_dent(mars_global, parent_path);
			if (unlikely(!parent)) {
				MARS_DBG("ignoring non-existing local resource '%s'\n", parent_path);
			// don't copy old / outdated logfiles
			} else if ((rot = parent->d_private) &&
				   rot->relevant_serial > remote_dent->d_serial) {
				MARS_DBG("ignoring outdated remote logfile '%s' (behind %d)\n", remote_path, rot->relevant_serial);
			} else {
				struct mars_dent *local_dent;

				local_dent = mars_find_dent(mars_global, remote_path);
				status = check_logfile(peer->peer, remote_dent, local_dent, parent, local_stat.size);
			}
			brick_string_free(parent_path);
		}
	} else {
		MARS_DBG("ignoring '%s'\n", remote_path);
	}

 done:
	brick_string_free(to_free);
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
	struct mars_global *tmp_global;
	struct lamport_time remote_start_stamp;
	struct list_head *tmp;
	bool run_trigger = false;
	bool run_systemd_trigger = false;
	int status = 0;

	mutex_lock(&peer->peer_lock);
	remote_start_stamp = peer->remote_start_stamp;
	tmp_global = peer->remote_global;
	peer->remote_global = NULL;
	mutex_unlock(&peer->peer_lock);

	MARS_DBG("tmp_global %p '%s'\n",
		 tmp_global, peer->peer);

	if (!tmp_global)
		return 0;

	for (tmp = tmp_global->dent_anchor.next;
	     tmp != &tmp_global->dent_anchor; tmp = tmp->next) {
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
	}

	if (peer->rebase_dir) {
		const char *got_path;

		got_path = path_make("%s/got-%s",
				     peer->rebase_dir,
				     peer->peer);
		ordered_symlink("1", got_path, NULL);
		brick_string_free(got_path);
	}

	if (remote_start_stamp.tv_sec) {
		const char *src;
		const char *dst;

		src = path_make("%lld.%09ld",
				(s64)remote_start_stamp.tv_sec,
				remote_start_stamp.tv_nsec);
		dst = path_make("/mars/actual-%s/read-stamp",
				peer->peer);
		/* Notice: while src shows the remote Lamport stamp when
		 * the link tree was initially read, the target Lamport stamp
		 * indicates when all the info was merged locally.
		 */
		ordered_symlink(src, dst, NULL);
		brick_string_free(src);
		brick_string_free(dst);
	}

	mars_free_dent_all(tmp_global);
	free_mars_global(tmp_global);

	if (run_trigger) {
		mars_trigger();
	}
	if (run_systemd_trigger) {
		touch_systemd_trigger("/mars/userspace/systemd-trigger");
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

#define make_peer_msg(peer, pair, fmt, args...)			\
	if (!peer->silent)					\
		make_msg(pair, fmt, ##args)

static
void report_peer_connection(struct mars_peerinfo *peer,
			    struct key_value_pair *peer_pairs)
{
	if (strcmp(peer->peer, my_id()))
		return;

	_show_vals(peer_pairs,
		   "/mars",
		   "needed-connection-with-",
		   peer->silent);
}

static
int peer_action_dent_list(struct mars_peerinfo *peer,
			  const char *real_peer,
			  const char *paths,
			  struct key_value_pair *peer_pairs,
			  struct lamport_time *start_stamp)
{
	struct mars_global *new_global = alloc_mars_global();
	struct mars_global *old_global = NULL;
	int status;

	MARS_DBG("fetching remote dentries from '%s' '%s'\n",
		 peer->peer, paths);

	status = mars_recv_dent_list(new_global, &peer->socket);
	if (unlikely(status < 0))
		goto free;

	if (likely(!list_empty(&new_global->dent_anchor))) {
		LIST_HEAD(old_list);
		struct mars_dent *peer_uuid;

		MARS_DBG("got remote dentries from %s\n", peer->peer);

		peer_uuid = mars_find_dent(new_global, "/mars/uuid");
		if (unlikely(!peer_uuid || !peer_uuid->new_link)) {
			MARS_ERR("peer %s has no uuid\n", peer->peer);
			make_peer_msg(peer, peer_pairs,
				      "peer '%s' has no UUID",
				      peer->peer);
			status = -EPROTO;
			goto free;
		}
		if (unlikely(my_uuid && *my_uuid &&
			     strcmp(peer_uuid->new_link, my_uuid) &&
			     strcmp(my_uuid, "(any)") &&
			     strcmp(peer_uuid->new_link, "(any)"))) {
			MARS_ERR("UUID mismatch '%s' != '%s' for peer '%s'\n",
				 peer_uuid->new_link, my_uuid,
				 peer->peer);
			make_peer_msg(peer, peer_pairs,
				      "UUID mismatch with '%s', own cluster '%s' is trying to communicate with a foreign cluster '%s'",
				      peer->peer,
				      my_uuid,
				      peer_uuid->new_link);
			status = -EPROTO;
			goto free;
		}

		make_peer_msg(peer, peer_pairs,
			      "CONNECTED %s(%s) fetching '%s'",
			      peer->peer, real_peer,
			      paths);

		/* All right: replace the old global ptr with the new one */
		mutex_lock(&peer->peer_lock);
		peer->remote_start_stamp = *start_stamp;
		old_global = peer->remote_global;
		peer->remote_global = new_global;
		new_global = NULL;
		mutex_unlock(&peer->peer_lock);

		peer->nr_dents++;
		peer->last_remote_jiffies = jiffies;

		mars_trigger();

		status = 0;
	}

 free:
	if (old_global) {
		mars_free_dent_all(old_global);
		free_mars_global(old_global);
	}
	if (new_global) {
		mars_free_dent_all(new_global);
		free_mars_global(new_global);
	}
	return status;
}

/* React on different types of peer responses
 */
static
int peer_actions(struct mars_peerinfo *peer,
		 const char *real_peer,
		 const char *paths,
		 struct key_value_pair *peer_pairs)
{
	struct mars_cmd inter_cmd = {
	};
	int status;

	/* Compatibility to old protocol: we cannot send/recv cmds */
	if (!peer->socket.s_common_proto_level)
		return peer_action_dent_list(peer,
					     real_peer,
					     paths,
					     peer_pairs,
					     &inter_cmd.cmd_stamp);

	/* New protocoal with extensible cases */
	status = mars_recv_cmd(&peer->socket, &inter_cmd);
	if (unlikely(status < 0)) {
		MARS_WRN("communication error on inter_cmd receive, status = %d\n", status);
		goto done;
	}

	switch (inter_cmd.cmd_code) {
	case CMD_GETENTS:
	{
		status = peer_action_dent_list(
				peer,
				real_peer,
				paths,
				peer_pairs,
				&inter_cmd.cmd_stamp);
		break;
	}
	default:
		/* do nothing, ignore any unknown inter_cmd */
		break;
	}

 done:
	brick_string_free(inter_cmd.cmd_str1);
	brick_string_free(inter_cmd.cmd_str2);
	return status;
}

static
int peer_thread(void *data)
{
	struct mars_peerinfo *peer = data;
	const char *real_peer = NULL;
	const char *old_transl = NULL;
	struct sockaddr_storage sockaddr = {};
	struct key_value_pair peer_pairs[] = {
		{ peer->peer },
		{ NULL }
	};
	int pause_time = 0;
	bool do_kill = false;
	bool repeated = false;
	int status;

	if (!peer || !mars_net_is_alive)
		return -1;

	/* check whether name is resolvable */
	if (!peer->peer_ip) {
		old_transl = mars_translate_hostname(peer->peer);
		if (!old_transl || !strcmp(old_transl, peer->peer)) {
			static struct lamport_time full_fetch_stamp;
			struct lamport_time now;

			get_real_lamport(&now);
			MARS_ERR("unknown peer '%s'\n",
				 peer->peer);

			/* desperate: try to fetch /mars/ips/ not too frequently */
			if (!full_fetch_stamp.tv_sec ||
			    now.tv_sec - full_fetch_stamp.tv_sec > 60) {
				full_fetch_stamp = now;
				start_full_fetch = true;
			}
		}
	}
	real_peer = path_make("%s:%d",
			      peer->peer_ip ? peer->peer_ip : peer->peer,
			      mars_net_default_port + MARS_TRAFFIC_META);
	MARS_INF("-------- %s peer thread starting on peer '%s' (%s)\n",
		 peer->peer_ip,
		 peer->peer, real_peer);

	status = mars_create_sockaddr(&sockaddr, real_peer);
	if (unlikely(status < 0)) {
		MARS_ERR("host '%s' unusable remote address '%s' (%s)\n",
			 peer->peer_ip,
			 real_peer, peer->peer);
		goto done;
	}

        while (peer_thead_should_run(peer)) {
		struct mars_cmd cmd = {
			.cmd_int1 = peer->maxdepth,
		};
		LIST_HEAD(tmp_push_list);

		if (likely(repeated))
			report_peer_connection(peer, peer_pairs);
		repeated = true;

		if (!mars_socket_is_alive(&peer->socket)) {
			make_peer_msg(peer, peer_pairs,
				      "connection to '%s' (%s) is dead",
				      peer->peer, real_peer);
			status = mars_create_sockaddr(&sockaddr, real_peer);
			if (unlikely(status < 0)) {
				MARS_ERR("unusable remote address '%s' (%s)\n", real_peer, peer->peer);
				make_peer_msg(peer, peer_pairs,
					      "unusable remote address '%s' (%s)\n",
					      real_peer, peer->peer);
				brick_msleep(100);
				continue;
			}
			if (do_kill) {
				do_kill = false;
				_peer_cleanup(peer);
				brick_msleep(100);
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
				make_peer_msg(peer, peer_pairs,
					      "connection to '%s' (%s) could not be established: status = %d",
					      peer->peer, real_peer, status);
				/* additional threads should give up immediately */
				if (peer->oneshot)
					break;
				brick_msleep(200);
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
		} else if (!peer->oneshot && old_transl) {
			const char *new_transl;
			bool need_shutdown;

			/* check whether IP assignment has changed */
			new_transl = mars_translate_hostname(peer->peer);
			need_shutdown =
				(new_transl &&
				 strcmp(old_transl, new_transl));
			if (need_shutdown) {
				MARS_INF("IP assignment %d '%s' -> '%s'\n", 
					 mars_socket_is_alive(&peer->socket),
					 old_transl, new_transl);
				brick_string_free(old_transl);
				old_transl = new_transl;
				mars_shutdown_socket(&peer->socket);
				brick_msleep(100);
				continue;
			}
			brick_string_free(new_transl);
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
			status = mars_send_cmd(&peer->socket, &cmd, false);
			if (unlikely(status < 0)) {
				goto send_error;
			}
		}

		mutex_lock(&peer->peer_lock);
		list_replace_init(&peer->push_anchor, &tmp_push_list);
		mutex_unlock(&peer->peer_lock);

		while (status >= 0 && !list_empty(&tmp_push_list)) {
			struct mars_cmd cmd_push = {
				.cmd_int1 = peer->maxdepth,
			};
			struct push_info *push;

			push = container_of(tmp_push_list.next, struct push_info, push_head);
			cmd_push.cmd_code = push->cmd_code;
			cmd_push.cmd_str1 = brick_strdup(push->src);
			cmd_push.cmd_str2 = brick_strdup(push->dst);
			status = mars_send_cmd(&peer->socket, &cmd_push, false);
			MARS_INF("PUSH_LINK '%s' '%s' status=%d\n",
				 cmd_push.cmd_str1,
				 cmd_push.cmd_str2,
				 status);
			brick_string_free(cmd_push.cmd_str1);
			brick_string_free(cmd_push.cmd_str2);
			if (status < 0)
				break;

			mutex_lock(&peer->peer_lock);
			list_del_init(&push->push_head);
			mutex_unlock(&peer->peer_lock);

			brick_string_free(push->src);
			brick_string_free(push->dst);
			brick_mem_free(push);
		}
		if (status < 0) {
			if (list_empty(&tmp_push_list))
				goto send_error;
			/* try working the push list next time */
			mutex_lock(&peer->peer_lock);
			list_replace_init(&tmp_push_list, &peer->push_anchor);
			mutex_unlock(&peer->peer_lock);
			goto send_error;
		} else if (peer->no_fetch) {
			/* Needed for split-cluster: do not fetch metadata from
			 * another cluster group.
			 */
			brick_msleep(200);
			if (!mars_global->global_power.button)
				break;
			if (peer->oneshot) {
				bool empty_pushes;

				mutex_lock(&peer->peer_lock);
				empty_pushes = !!list_empty(&peer->push_anchor);
				mutex_unlock(&peer->peer_lock);
				if (empty_pushes ||
				    jiffies - peer->create_jiffies >
				    mars_scan_interval * 2 * HZ)
					break;
			}
			continue;
		} else {
			peer->to_remote_trigger = false;
			cmd.cmd_code = CMD_GETENTS;
			if (!peer->oneshot &&
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
		send_error:
			MARS_WRN("communication error on send, status = %d\n", status);
			if (do_kill) {
				do_kill = false;
				_peer_cleanup(peer);
			}
			goto free_and_restart;
		}

		status = peer_actions(peer,
				      real_peer,
				      cmd.cmd_str1,
				      peer_pairs);
		brick_string_free(cmd.cmd_str1);
		brick_string_free(cmd.cmd_str2);
		if (unlikely(status < 0)) {
			MARS_WRN("communication error on receive, status = %d\n", status);
			if (do_kill) {
				do_kill = false;
				_peer_cleanup(peer);
			}
			goto restart;
		}
		peer->got_info = true;

		/* check whether oneshot peers have finished their job */
		if (peer->oneshot &&
		    (peer->nr_dents > 0 ||
		     !mars_global->global_power.button ||
		     jiffies - peer->create_jiffies >
		       mars_scan_interval * 2 * HZ))
			break;

		/* Re-determine marsadm versions once per hour.
		 * Software installations are not too frequently ;)
		 */
		if (jiffies - peer->create_jiffies > 3600 * HZ) {
			peer->create_jiffies = jiffies;
			get_marsadm_version(peer->peer);
		}

		brick_msleep(100);
		if (!peer->to_terminate && !brick_thread_should_stop()) {
			bool old_oneshot = peer->oneshot;

			if (pause_time < mars_propagate_interval)
				pause_time++;
			wait_event_interruptible_timeout(remote_event,
							 (peer->to_remote_trigger | peer->from_remote_trigger) ||
							 !peer_thead_should_run(peer) ||
							 (old_oneshot != peer->oneshot) ||
							 (mars_global && !mars_global->global_power.button),
							 pause_time * HZ);
		}
		continue;

	free_and_restart:
		brick_string_free(cmd.cmd_str1);
		brick_string_free(cmd.cmd_str2);
	restart:
		/* additional threads should give up immediately */
		if (peer->oneshot)
			break;
		brick_msleep(200);
	}

	MARS_INF("-------- peer thread terminating\n");

	clear_vals(peer_pairs);
	make_peer_msg(peer, peer_pairs,
		      "NOT connected %s(%s)",
		      peer->peer, real_peer);
	report_peer_connection(peer, peer_pairs);

	if (do_kill) {
		_peer_cleanup(peer);
	}

done:
	clear_vals(peer_pairs);
	brick_string_free(old_transl);
	brick_string_free(real_peer);
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
	tmp = path_make("%lld.%09ld",
			(s64)now.tv_sec, now.tv_nsec);
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

void mars_remote_trigger(int code)
{
	struct list_head *tmp;
	int count = 0;

	if (code & MARS_TRIGGER_FULL)
		start_full_fetch = true;

	down_read(&peer_list_lock);
	for (tmp = peer_anchor.next; tmp != &peer_anchor; tmp = tmp->next) {
		struct mars_peerinfo *peer = container_of(tmp, struct mars_peerinfo, peer_head);

		/* skip some peers when requested */
		if (!(code & (MARS_TRIGGER_TO_REMOTE_ALL | MARS_TRIGGER_FULL)) &&
		    peer->oneshot)
			continue;

		count++;
		if (code & MARS_TRIGGER_FULL)
			peer->do_entire_once = true;
		if (code & MARS_TRIGGER_FROM_REMOTE)
			peer->from_remote_trigger = true;
		if (code & (MARS_TRIGGER_TO_REMOTE | MARS_TRIGGER_TO_REMOTE_ALL))
			peer->to_remote_trigger = true;
	}
	up_read(&peer_list_lock);

	MARS_DBG("triggered %d peers code=0x%x\n", count, code);
	wake_up_interruptible_all(&remote_event);

	if (code & MARS_TRIGGER_LOCAL)
		mars_trigger();
}

static
bool is_shutdown(void)
{
	int used = atomic_read(&global_mshadow_count);

	if (used  > 0) {
		MARS_INF("global shutdown delayed: there are %d buffers in use, occupying %lld bytes\n",
			 used,
			 (s64)atomic64_read(&global_mshadow_used));
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

void _activate_peer(struct mars_dent *peer_dent,
		    const char *peer_name,
		    const char *peer_ip,
		    bool oneshot)
{
	struct mars_peerinfo *peer;

	if (!mars_net_is_alive)
		return;

	peer = peer_dent->d_private;
	if (!peer) {
		peer = new_peer(peer_name, peer_ip);
		if (oneshot) {
			mars_running_additional_peers++;
			peer->need_destruct = true;
		} else {
			peer_dent->d_private = peer;
			peer_dent->d_private_destruct = peer_destruct;
		}
		MARS_DBG("new peer %p '%s' %d\n",
			 peer, peer_name, oneshot);
		peer->oneshot = oneshot;
		peer->do_entire_once = oneshot;
		peer->silent = oneshot;
	} else if (oneshot && !peer->oneshot && !peer_ip) {
		MARS_DBG("reuse existing peer %p '%s'\n",
			 peer, peer_name);
		peer->do_entire_once = true;
		peer->from_remote_trigger = true;
		peer->to_remote_trigger = true;
	} else if (peer->oneshot != oneshot) {
		MARS_DBG("peer %p '%s' oneshot %d -> %d\n",
			 peer, peer_name,
			 peer->oneshot, oneshot);
		peer->oneshot = oneshot;
		peer->do_entire_once = oneshot;
		peer->silent = oneshot;
	}
	/* idempotence: (res)tart any (terminated) peer */
	start_peer(peer);
}

void activate_peer(const char *peer_name,
		   const char *peer_ip,
		   const char *rebase_dir,
		   bool oneshot)
{
	struct mars_dent *peer_dent;

	MARS_DBG("peer_name='%s' peer_name='%s' peer_name='%s' oneshot=%d\n",
		 peer_name, peer_ip, rebase_dir, oneshot);

	if (unlikely(!peer_name ||
		     !peer_name[0] ||
		     !strcmp(peer_name, my_id())))
		return;

	peer_dent = find_peer_dent(peer_name);
	/* When the IP is given, create a floating peer.
	 */
	if (peer_ip &&
	    (!peer_dent ||
	     !peer_dent->new_link ||
	     strcmp(peer_dent->new_link, peer_ip) != 0 ||
	     rebase_dir)) {
		struct mars_peerinfo *peer;

		peer = new_peer(peer_name, peer_ip);
		MARS_DBG("new FLOATING peer %p '%s' '%s'\n",
			 peer, peer_name, peer_ip);
		mars_running_additional_peers++;
		peer->need_destruct = true;
		peer->oneshot = true;
		peer->do_entire_once = true;
		peer->silent = true;
		if (rebase_dir)
			peer->rebase_dir = brick_strdup(rebase_dir);
		start_peer(peer);
		return;
	}
	if (unlikely(!peer_dent)) {
		MARS_ERR("peer '%s' does not exist in /mars/ips/\n",
			 peer_name);
		return;
	}
	_activate_peer(peer_dent, peer_name, peer_ip, oneshot);
}

static int _kill_peer(struct mars_peerinfo *peer)
{
	struct mars_global *old_global;
	LIST_HEAD(tmp_push_list);

	if (!peer)
		return 0;

	down_write(&peer_list_lock);
	if (!list_empty(&peer->peer_head))
		peer_count--;
	list_del_init(&peer->peer_head);
	up_write(&peer_list_lock);

	WRITE_ONCE(peer->in_destruct, true);

	MARS_INF("stopping peer thread...\n");
	if (peer->peer_thread) {
		brick_thread_stop(peer->peer_thread);
		peer->peer_thread = NULL;
	}

	mutex_lock(&peer->peer_lock);
	old_global = peer->remote_global;
	peer->remote_global = NULL;
	list_replace_init(&peer->push_anchor, &tmp_push_list);
	mutex_unlock(&peer->peer_lock);

	while (!list_empty(&tmp_push_list)) {
		struct push_info *push;

		push = container_of(tmp_push_list.next, struct push_info, push_head);
		mutex_lock(&peer->peer_lock);
		list_del_init(&push->push_head);
		mutex_unlock(&peer->peer_lock);
		brick_string_free(push->src);
		brick_string_free(push->dst);
		brick_mem_free(push);
	}
	if (old_global) {
		mars_free_dent_all(old_global);
		free_mars_global(old_global);
	}
	brick_string_free(peer->peer);
	brick_string_free(peer->peer_ip);
	brick_string_free(peer->peer_dir_list);
	brick_string_free(peer->rebase_dir);
	return 0;
}

static
void peer_destruct(void *_peer)
{
	struct mars_peerinfo *peer = _peer;

	if (likely(peer))
		_kill_peer(peer);
}

/*  1 = make oneshot peer
 *  0 = ordindary long-running peer
 * -1 = do not activate
 */
static
int _need_oneshot(struct mars_dent *dent, const char *peer_name)
{
	struct mars_peerinfo *peer;
	struct lamport_time *stamp;

#ifdef CONFIG_MARS_DEBUG
	if (mars_test_additional_peers == 1)
		return 1;
	else if (mars_test_additional_peers == -1)
		return 0;
#endif

	/* Check whether enough scalability features are installed.
	 */
	if (unlikely(usable_strategy_version < 0)) {
		/* We are in the very first round after modprobe.
		 * Wait until features are determined globally.
		 */
		return -1;
	}
	/* Old behaviour, may lead to "fork bombs".
	 * Do not use on big clusters.
	 */
	if (_compat_additional)
		return 0;

	/* From here on, the new push operations & friends are available.
	 * We try to avoid O(n^2) peer activation storms in very big clusters,
	 * e.g. after a mass reboot / modprobe, as may happen after a
	 * mass power outage of thousands of servers.
	 * The new ssh-free push method will _selectively_ activate any
	 * necessary peer, in place of the old catch-all.
	 */

#ifdef CONFIG_MARS_DEBUG
	if (mars_test_additional_peers == 2)
		return 1;
	else if (mars_test_additional_peers == -2)
		return -1;
#endif

	/* Determine second-highest oneshot stamp during cyclic round.
	 * Skip any ordinary working peers.
	 */
	peer = dent->d_private;
	stamp = &dent->new_stat.mtime;
	if ((!peer ||
	     !peer->peer_thread ||
	     peer->has_terminated) &&
	    (!oneshot_stamp.tv_sec ||
	     lamport_time_compare(stamp, &oneshot_stamp) < 0) &&
	    (!_tmp_oneshot_stamp.tv_sec ||
	     lamport_time_compare(stamp, &_tmp_oneshot_stamp) > 0)) {
		_tmp_oneshot_stamp = *stamp;
		brick_string_free(_tmp_oneshot_peer);
		_tmp_oneshot_peer = brick_strdup(peer_name);
	}

	/* Are we the previously selected oneshot peer? */
	if (oneshot_peer && !strcmp(peer_name, oneshot_peer)) {
		brick_string_free(oneshot_peer);
		return 1;
	}

	/* default under the new regime: do not activate */
	return -1;
}

static
int _make_peer(struct mars_dent *dent)
{
	struct mars_peerinfo *peer;
	char *mypeer;
	char *parent_path;
	const char *feature_str;
	int oneshot_code;
	int status = 0;

	if (!dent->new_link ||
	    !dent->d_parent ||
	    !dent->d_parent->d_path) {
		MARS_DBG("cannot work\n");
		return 0;
	}
	parent_path = dent->d_parent->d_path;
	mypeer = dent->d_rest;
	if (!mypeer) {
		status = _parse_args(dent, dent->new_link, 1);
		if (status < 0)
			goto done;
		mypeer = dent->d_argv[0];
	}

	oneshot_code = _need_oneshot(dent, mypeer);
	peer = dent->d_private;
	if (!peer) {
		/* Avoid oneshot storms right after masses of modprobe,
		 * which might occur after mass reboot.
		 * Important for clusters with thousands of peers.
		 */
		if (oneshot_code < 0)
			return 0;
		_activate_peer(dent, mypeer, NULL, oneshot_code > 0);
		peer = dent->d_private;
		if (unlikely(!peer))
			return 0;
	} else if (oneshot_code > 0) {
		_activate_peer(dent, mypeer, NULL, true);
	}

	if (tmp_full_fetch) {
		peer->do_entire_once = true;
		start_peer(peer);
	}

	/* Determine remote features and digest mask */
	feature_str = get_alivelink("features", mypeer);
	if (feature_str && feature_str[0]) {
		sscanf(feature_str,
		       "%d,%d,0x%x",
		       &peer->features_version,
		       &peer->strategy_version,
		       &peer->available_mask);
	} else {
		/* Needed during join-cluster */
		MARS_DBG("assuming default versions for '%s'\n", mypeer);
		peer->features_version = OPTIONAL_FEATURES_VERSION;
		peer->strategy_version = OPTIONAL_STRATEGY_VERSION;
		/* Safeguard: peer->available_mask is _not_ set */
	}
	MARS_DBG("versions '%s': %d %d 0x%x\n",
		 mypeer,
		 peer->features_version,
		 peer->strategy_version,
		 peer->available_mask);
	/* else/anyway: treat missing features as 0 = worst case */
	if (peer->features_version < 3) {
		peer->strategy_version = 0;
		peer->available_mask = 0;
	}

	brick_string_free(feature_str);

	/* at least one digest must remain usable */
	peer->available_mask |= MREF_CHKSUM_MD5_OLD;
	/* only active peers shall count for usable masks */
	if (peer->got_info && !peer->oneshot) {
		_tmp_digest_mask &= peer->available_mask;
		_tmp_compression_mask &= peer->available_mask;
		if (peer->features_version < _tmp_features_version)
			_tmp_features_version = peer->features_version;
		if (peer->strategy_version < _tmp_strategy_version)
			_tmp_strategy_version = peer->strategy_version;
	}

	status = start_peer(peer);
	if (status < 0)
		return status;

	/* This must be called by the main thread in order to
	 * avoid nasty races.
	 * The peer thread does nothing but fetching the dent list.
	 */
	status = run_bones(peer);

done:
	return status;
}

static int kill_scan(struct mars_dent *dent)
{
	struct mars_peerinfo *peer = dent->d_private;
	int res;

	if (mars_global->global_power.button || !peer) {
		return 0;
	}
	dent->d_private = NULL;
	res = _kill_peer(peer);
	brick_mem_free(peer);
	return res;
}

static int make_scan(struct mars_dent *dent)
{
	int status;

	/* don't initialize new connections with myself */
	if (!dent->d_private && !strcmp(dent->d_rest, my_id())) {
		return 0;
	}
	status = _make_peer(dent);
#if 1
	/* Hack, to disappear:
	 * Backward compatibility to old marsadm versions.
	 * Push my IP to any _preliminary_ peer link.
	 */
	if (dent->new_stat.mtime.tv_sec < 100 &&
	    dent->new_link) {
		struct mars_peerinfo *peer = dent->d_private;

		MARS_DBG("HACK status=%d peer=%p\n", status, peer);
		if (!peer) {
			activate_peer(dent->d_rest, NULL, NULL, false);
		} else {
			const char *dst;
			const char *src;

			dst = path_make("/mars/ips/ip-%s", my_id());
			src = ordered_readlink(dst, NULL);
			if (src && *src && !READ_ONCE(peer->in_destruct)) {
				bool empty_pushes;

				mutex_lock(&peer->peer_lock);
				empty_pushes = !!list_empty(&peer->push_anchor);
				mutex_unlock(&peer->peer_lock);
				if (empty_pushes && !READ_ONCE(peer->in_destruct))
					push_link(dent->d_rest, NULL, src, dst);
			}
			brick_string_free(src);
			brick_string_free(dst);
		}
	}
#endif
	return status;
}


static
int kill_any(struct mars_dent *dent)
{
	struct list_head *tmp;

	if (mars_global->global_power.button || !is_shutdown()) {
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
	mars_kill_dent(mars_global, dent);
	return 1;
}

/*********************************************************************/

/* launching peer threads from external, e.g. /proc */

struct launch_info {
	struct list_head launch_head;
	const char *peer_name;
	const char *peer_ip;
	const char *rebase_dir;
	bool oneshot;
};

static DECLARE_RWSEM(launch_lock);
static
struct list_head launch_anchor = LIST_HEAD_INIT(launch_anchor);

void launch_peer(const char *peer_name,
		 const char *peer_ip,
		 const char *rebase_dir,
		 bool oneshot)
{
	struct launch_info *launch;

	if (!mars_net_is_alive)
		return;

	launch = brick_zmem_alloc(sizeof(struct launch_info));
	INIT_LIST_HEAD(&launch->launch_head);
	launch->peer_name  = brick_strdup(peer_name);
	if (peer_ip)
		launch->peer_ip    = brick_strdup(peer_ip);
	if (rebase_dir)
		launch->rebase_dir = brick_strdup(rebase_dir);
	launch->oneshot    = oneshot;
	down_write(&launch_lock);
	list_add_tail(&launch->launch_head, &launch_anchor);
	up_write(&launch_lock);
}

static
void launch_all(bool cleanup)
{
	down_write(&launch_lock);
	while (!list_empty(&launch_anchor)) {
		struct launch_info *launch;

		launch = container_of(launch_anchor.next, struct launch_info, launch_head);
		list_del_init(&launch->launch_head);
		if (!cleanup && mars_net_is_alive)
			activate_peer(launch->peer_name,
				      launch->peer_ip,
				      launch->rebase_dir,
				      launch->oneshot);
		brick_string_free(launch->peer_name);
		brick_string_free(launch->peer_ip);
		brick_string_free(launch->rebase_dir);
		brick_mem_free(launch);
	}
	up_write(&launch_lock);
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
	set_fs(KERNEL_DS);
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
  const char *res = ordered_readlink(_linkpath, NULL);

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

static
long long versionlink_loglen(const char *linkval)
{
	long long res = 0;
	const char *test = linkval;
	int arg_nr;
	int count;

	/* get the third comma-separated arg */
	for (arg_nr = 1; arg_nr < 3; arg_nr++) {
		test = strchr(test, MARS_DELIM);
		if (unlikely(!test) || !*(++test)) {
			MARS_ERR("replay link '%s' has only %d args\n",
				 linkval, arg_nr - 1);
			return res;
		}
	}
	count = sscanf(test, "%lld", &res);
	if (unlikely(count < 1)) {
		MARS_ERR("replay link '%s': no recognizable logfile size\n",
			 linkval);
	}
	return res;
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
	    !_check_allow(rot->parent_path, "connect"))
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
	mars_remote_trigger(MARS_TRIGGER_LOCAL | MARS_TRIGGER_TO_REMOTE);

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
		MARS_DBG("update info links\n");
		write_info_links(rot);
		del_channel(rot->log_say);
		rot->log_say = NULL;
		assign_dent(&rot->replay_link, NULL);
		assign_dent(&rot->aio_dent, NULL);
		assign_dent(&rot->first_log, NULL);
		assign_dent(&rot->last_log, NULL);
		assign_dent(&rot->relevant_log, NULL);
		assign_dent(&rot->next_relevant_log, NULL);
		assign_dent(&rot->prev_log, NULL);
		assign_dent(&rot->next_log, NULL);
		assign_dent(&rot->syncstatus_dent, NULL);
		brick_string_free(rot->log_from_peer);
		brick_string_free(rot->fetch_path);
		brick_string_free(rot->fetch_peer);
		brick_string_free(rot->avoid_peer);
		brick_string_free(rot->preferred_peer);
		brick_string_free(rot->parent_path);
		brick_string_free(rot->parent_rest);
		brick_string_free(rot->fetch_next_origin);
		clear_vals(rot->msgs);
	}
}

/* This must be called once at every round of logfile checking.
 */
static
int make_log_init(struct mars_dent *dent)
{
	struct mars_dent *parent = dent->d_parent;
	struct mars_brick *bio_brick;
	struct mars_brick *aio_brick;
	struct mars_brick *trans_brick;
	struct mars_rotate *rot;
	struct mars_dent *replay_link;
	struct mars_dent *aio_dent;
	struct mars_output *output;
	const char *parent_path;
	const char *replay_path = NULL;
	const char *aio_path = NULL;
	loff_t logrot_limit;
	bool switch_on;
	int status = 0;

	if (!mars_global->global_power.button) {
		goto done;
	}
	status = -EINVAL;
	if (!parent)
		goto done;
	CHECK_PTR(parent, done);
	parent_path = parent->d_path;
	CHECK_PTR(parent_path, done);

	rot = parent->d_private;
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
		parent->d_private = rot;
		parent->d_private_destruct = rot_destruct;
		assign_keys(rot->msgs, rot_keys);

		down_write(&rot_sem);
		list_add_tail(&rot->rot_head, &rot_anchor);
		up_write(&rot_sem);
	}

	assign_dent(&rot->replay_link, NULL);
	assign_dent(&rot->aio_dent, NULL);
	rot->aio_brick = NULL;
	assign_dent(&rot->first_log, NULL);
	assign_dent(&rot->last_log, NULL);
	assign_dent(&rot->relevant_log, NULL);
	rot->relevant_serial = 0;
	rot->relevant_brick = NULL;
	assign_dent(&rot->next_relevant_log, NULL);
	assign_dent(&rot->prev_log, NULL);
	assign_dent(&rot->next_log, NULL);
	brick_string_free(rot->fetch_next_origin);
	rot->max_sequence = 0;
	// reset the split brain detector only when conflicts have gone for a number of rounds
	if (rot->split_brain_serial && rot->split_brain_round++ > 3)
		rot->split_brain_serial = 0;
	rot->fetch_next_serial = 0;
	rot->has_error = false;
	brick_string_free(rot->preferred_peer);

	activate_peer(dent->d_rest, NULL, NULL, false);

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
	
	MARS_DBG("update info links\n");
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

	replay_link = mars_find_dent(mars_global, replay_path);
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
	brick_string_free(rot->log_from_peer);
	parse_logfile_name(replay_link->d_argv[0],
			   &rot->repair_log_seq,
			   &rot->log_from_peer);

	assign_dent(&rot->replay_link, replay_link);

	/* Fetch AIO dentry of the logfile.
	 */
	if (rot->trans_brick) {
		struct trans_logger_input *trans_input = rot->trans_brick->inputs[rot->trans_brick->old_input_nr];

		if (_is_trans_input_fully_working(trans_input)) {
			aio_path = path_make("%s/log-%09d-%s",
					     parent_path,
					     trans_input->inf.inf_sequence,
					     trans_input->inf.inf_host);
			MARS_DBG("using logfile '%s' from trans_input %d (new=%d)\n",
				 SAFE_STR(aio_path),
				 rot->trans_brick->old_input_nr,
				 rot->trans_brick->log_input_nr);
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

	aio_dent = mars_find_dent(mars_global, aio_path);
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
	assign_dent(&rot->aio_dent, aio_dent);

	// check whether attach is allowed
	switch_on = _check_allow(parent->d_path, "attach");
	if (switch_on && rot->res_shutdown) {
		MARS_ERR("cannot start transaction logger: resource shutdown mode is currently active\n");
		switch_on = false;
	}

	/* Fetch / make the AIO brick instance
	 */
	aio_brick =
		make_brick_all(mars_global,
			       aio_dent,
			       _set_aio_params,
			       NULL,
			       aio_path,
			       (const struct generic_brick_type*)&aio_brick_type,
			       (const struct generic_brick_type*[]){},
			       switch_on ||
			        (rot->trans_brick &&
				 !rot->trans_brick->power.led_off) ? 2 : -1,
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
		if (likely(new_path &&
			   !mars_find_dent(mars_global, new_path))) {
			MARS_INF("old logfile size = %lld, creating new logfile '%s'\n",
				 rot->aio_info.current_size, new_path);
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
		make_brick_all(mars_global,
			       replay_link,
			       _set_trans_params,
			       NULL,
			       aio_path,
			       (const struct generic_brick_type*)&trans_logger_brick_type,
			       (const struct generic_brick_type*[]){NULL},
			       switch_on ? 1 : 0,
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

static
void _report_double_logfile(struct mars_rotate *rot,
			    const char *info,
			    const char *a, const char *b)
{
	rot->has_double_logfile = true;

	/* Some ratelimiting, based on pauses / interval logic.
	 * We can neither rely on Myquist, nor can we assume
	 * that Distributed Races will not occur.
	 * So we cannot guarantee almost anything, not even
	 * whether this special scenario will be reported at all.
	 */
	if (!rot->found_double_logfile.tv_sec) {
		get_real_lamport(&rot->found_double_logfile);
	} else {
		/* avoid some register thrashing */
		struct lamport_time now;
		struct lamport_time next_msg;
		bool enough;

		get_real_lamport(&now);
		next_msg = now;
		next_msg.tv_sec -= 5;
		enough = lamport_time_compare(&next_msg,
					      &rot->found_double_logfile) < 0;
		rot->found_double_logfile = now;
		if (enough)
			return;
	}

	MARS_ERR("DOUBLE LOGFILES %s '%s' <=> '%s'\n",
		 info, a, b);
}

/* Note: this is strictly called in d_serial order.
 * This is important!
 */
static
int make_log_step(struct mars_dent *dent)
{
	struct mars_dent *parent = dent->d_parent;
	struct mars_rotate *rot;
	struct trans_logger_brick *trans_brick;
	struct mars_dent *prev_log;
	int replay_log_nr = 0;
	int status = -EINVAL;

	if (!parent)
		goto err;
	CHECK_PTR(parent, err);
	rot = parent->d_private;
	if (!rot)
		goto err;
	CHECK_PTR(rot, err);

	status = 0;
	if (!S_ISREG(dent->new_stat.mode)) {
		MARS_DBG("no logfile '%s' -> '%s'\n",
			 dent->d_path, dent->new_link);
		goto done;
	}
	trans_brick = rot->trans_brick;
	if (!mars_global->global_power.button ||
	    !trans_brick ||
	    rot->has_error) {
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
		assign_dent(&rot->first_log, dent);

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
					assign_dent(&rot->relevant_log, dent);
				} else if (!rot->has_double_logfile) {
					_report_double_logfile(rot, "relevant",
							       dent->d_path,
							       rot->relevant_log->d_path);
				}
			} else if (_next_is_acceptable(rot, rot->relevant_log, dent)) {
				assign_dent(&rot->next_relevant_log, dent);
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
					assign_dent(&rot->next_relevant_log, dent);
				} else if (!rot->has_double_logfile) {
					_report_double_logfile(rot, "next_relevant",
							       dent->d_path,
							       rot->next_relevant_log->d_path);
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
	assign_dent(&rot->last_log, dent);

	/* Remember the relevant log.
	 */
	if (!rot->relevant_log && rot->aio_dent->d_serial == dent->d_serial) {
		rot->relevant_serial = dent->d_serial;
		assign_dent(&rot->relevant_log, dent);
		rot->has_double_logfile = false;
		rot->has_hole_logfile = false;
	}

ok:
	/* All ok: switch over the indicators.
	 */
	MARS_DBG("next_log = '%s'\n", dent->d_path);
	assign_dent(&rot->prev_log, rot->next_log);
	assign_dent(&rot->next_log, dent);

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
	const char *vers_link = NULL;
	int status = 0;

	if (!dent)
		goto done;
	
	status = -EINVAL;
	/* may happen after delete-resource */
	if (!dent->d_path)
		goto done;
	CHECK_PTR(dent->d_path, done);
	parent = dent->d_parent;
	if (!parent)
		goto done;
	CHECK_PTR(parent, done);
	CHECK_PTR(rot->replay_link, done);
	CHECK_PTR(rot->aio_brick, done);
	CHECK_PTR(rot->aio_dent, done);
	CHECK_PTR(rot->aio_dent->d_path, done);

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

	/* Shorten the end position when sync wants to run.
	 * Avoids unnecessary delay when the sync is starting again.
	 */
	if (rot->want_sync && !rot->todo_primary && rot->parent_path) {
		loff_t min_pos = -1;
		const char *primary = get_primary_host(rot);

		if (likely(primary && primary[0]) && strcmp(primary, "(none)")) {
			int cmp = compare_replaylinks(rot, primary, my_id(), &min_pos, NULL);

			MARS_DBG("want_sync compare=%d min_pos=%lld\n",
				 cmp, min_pos);
			/* prevent sequence number to pass by */
			if (cmp < 0) {
				MARS_INF("disallow passby due to sync\n");
				brick_string_free(primary);
				status = -EAGAIN;
				goto done;
			}
		}
		if (min_pos >= 0 &&
		    min_pos < *newpos) {
			MARS_INF("shortening replay from %lld to %lld due to sync\n",
				 *newpos, min_pos);
			*newpos = min_pos;
		}
		if (unlikely(*oldpos_end > *newpos)) {
			MARS_INF("also shortening from %lld to %lld\n",
				 *oldpos_end, *newpos);
			*oldpos_end = min_pos;
		}
		brick_string_free(primary);
	}

	if (unlikely(rot->aio_info.current_size < *oldpos_start)) {
		status = -EBADF;
		/* Allow primary --force even when logfiles are truncated / damaged.
		 */
		if (rot->todo_primary && !rot->is_primary &&
		    !rot->fetch_brick &&
		    !_check_allow(parent->d_path, "connect") &&
		    _check_allow(rot->parent_path, "attach")) {
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
	struct trans_logger_brick *trans_brick;
	int log_nr = 0;
	loff_t start_pos = 0;
	loff_t dirty_pos = 0;
	loff_t end_pos = 0;
	int status = 0;

	if (!dent)
		goto done;

	status = -EINVAL;
	CHECK_PTR(dent, done);
	parent = dent->d_parent;
	if (!parent)
		goto done;
	CHECK_PTR(parent, done);

	status = 0;
	trans_brick = rot->trans_brick;
	if (!mars_global->global_power.button ||
	    !trans_brick ||
	    rot->has_error) {
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
			/* Check whether we had a primary crash.
			 */
			if (rot->todo_primary && !rot->is_primary) {
				rot->was_primary_before =
					rot->aio_dent &&
					rot->aio_dent->d_rest &&
					!strcmp(rot->aio_dent->d_rest, my_id());
			} else {
				rot->was_primary_before = false;
			}
			if (rot->was_primary_before) {
				const char *own_versionlink_path = NULL;
				const char *own_versionlink = NULL;

				own_versionlink = get_versionlink(rot->parent_path,
								  log_nr,
								  my_id(),
								  &own_versionlink_path);
				if (own_versionlink) {
					long long vers_loglen = versionlink_loglen(own_versionlink);

					rot->had_primary_crash =
						vers_loglen > end_pos ||
						vers_loglen > rot->aio_dent->new_stat.size;
				} else {
					rot->had_primary_crash = true;
				}
				brick_string_free(own_versionlink_path);
				brick_string_free(own_versionlink);
				_recover_versionlink(rot, my_id(), log_nr, end_pos);
			} else {
				rot->had_primary_crash = false;
			}
			/* Only rotate when appropriate.
			 */
			if (next_relevant_log && !rot->log_is_really_damaged) {
				int replay_tolerance = _get_tolerance(rot);
				bool skip_new = !!rot->todo_primary;
				bool possible;

				if (rot->had_primary_crash)
					replay_tolerance = 0;

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

				/* Check whether secondary should wait.
				 * Crashed primary might look like "OK", as if they
				 * had no load.
				 */
				if (possible &&
				    !rot->todo_primary && !rot->is_primary &&
				    next_relevant_log->new_stat.size <= 0) {
					const char *primary = get_primary_host(rot);

					if (primary && primary[0] && primary[0] != '(' &&
					    !is_alive(primary)) {
						possible = false;
					}
					brick_string_free(primary);
				}
				if (possible) {
					MARS_INF_TO(rot->log_say,
						    "start switchover from transaction log '%s' to '%s'\n",
						    dent->d_path,
						    rot->next_relevant_log->d_path);
					_make_new_replaylink(rot,
							     rot->next_relevant_log->d_rest,
							     rot->next_relevant_log->d_serial,
							     0);
				} else {
					bool want_bypass =
						(rot->todo_primary &&
						 !_check_allow(parent->d_path,
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
	assign_dent(&rot->prev_log, rot->next_log);
	assign_dent(&rot->next_log, dent);

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

			MARS_DBG("update info links\n");
			write_info_links(rot);
			MARS_INF("cleanup old transaction log (%d -> %d)\n", old_nr, log_nr);
			status = mars_disconnect((void*)trans_input);
			if (unlikely(status < 0)) {
				MARS_ERR("disconnect failed\n");
			} else {
				/* Once again: now the other input should be active */
				MARS_DBG("update info links\n");
				write_info_links(rot);
				mars_remote_trigger(MARS_TRIGGER_LOCAL | MARS_TRIGGER_TO_REMOTE);
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
	    rot->next_relevant_log->d_parent &&
	    _check_allow(rot->parent_path, "attach") &&
	    (rot->next_relevant_log->d_serial == trans_brick->inputs[log_nr]->inf.inf_sequence + 1 ||
	     trans_brick->cease_logging) &&
	    (next_nr = _get_free_input(trans_brick)) >= 0) {
		struct trans_logger_input *trans_input;
		int status;
		
		MARS_DBG("start switchover %d -> %d\n", old_nr, next_nr);
		
		rot->next_relevant_brick =
			make_brick_all(mars_global,
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
	if (unlikely(!rot->relevant_log->d_parent)) {
		MARS_ERR("parent of %p is missing, this should not happen\n",
			 rot->relevant_log);
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
	if (!trans_brick->power.led_off ||
	    rot->trans_brick->inputs[TL_INPUT_LOG1]->connect ||
	    rot->trans_brick->inputs[TL_INPUT_LOG2]->connect) {
		MARS_DBG("stopping not yet finished %d %d %d\n",
			 trans_brick->power.led_off,
			 rot->trans_brick->inputs[TL_INPUT_LOG1]->connect != NULL,
			 rot->trans_brick->inputs[TL_INPUT_LOG2]->connect != NULL);
		mars_trigger();
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
		make_brick_all(mars_global,
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

		MARS_DBG("update info links\n");
		write_info_links(rot);
		for (i = TL_INPUT_LOG1; i <= TL_INPUT_LOG2; i++) {
			struct trans_logger_input *trans_input;
			trans_input = trans_brick->inputs[i];
			if (trans_input && !trans_input->is_operating) {
				(void)mars_disconnect((void*)trans_input);
			}
		}
	}
	MARS_DBG("update info links\n");
	write_info_links(rot);
	mars_remote_trigger(MARS_TRIGGER_LOCAL | MARS_TRIGGER_FROM_REMOTE | MARS_TRIGGER_TO_REMOTE);

done:
	return status;
}

/* secondaries must ensure that logrotate has stabilized */
static
bool _is_secondary_fixing_safe(struct mars_rotate *rot)
{
	if (!rot->trans_brick)
		return false;
	if (rot->trans_brick->replay_code == -EAGAIN)
		return false;
	if (!rot->relevant_log)
		return false;
	if (!rot->next_relevant_log)
		return false;
	if (rot->max_sequence > rot->next_relevant_log->d_serial)
		return false;
	return true;
}

static
int make_log_finalize(struct mars_dent *dent)
{
	struct mars_dent *parent = dent->d_parent;
	struct mars_rotate *rot;
	struct trans_logger_brick *trans_brick;
	struct copy_brick *fetch_brick;
	bool is_stopped;
	int status = -EINVAL;

	if (!parent)
		goto err;
	CHECK_PTR(parent, err);
	rot = parent->d_private;
	if (!rot)
		goto err;
	CHECK_PTR(rot, err);
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
		int limit = _check_allow(parent->d_path, "emergency-limit");
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
			char *new_path = path_make("%s/log-%09d-%s", rot->parent_path, new_sequence + 1, my_id());
			unsigned char *new_val = ordered_readlink(new_path, NULL);
			bool is_deleted = is_deleted_link(new_val);

			if (is_deleted) {
				char *new_vers = path_make("%s/version-%09d-%s", rot->parent_path, new_sequence, my_id());
				char *new_vval = path_make("00000000000000000000000000000000,log-%09d-%s,0:", new_sequence, my_id());
				MARS_INF_TO(rot->log_say, "EMERGENCY: creating new logfile '%s'\n", new_path);
				ordered_symlink(new_vval, new_vers, NULL);
				_create_new_logfile(new_path);
				rot->created_hole = true;
				brick_string_free(new_vers);
				brick_string_free(new_vval);
			}
			brick_string_free(new_path);
			brick_string_free(new_val);
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
		MARS_DBG("update info links\n");
		write_info_links(rot);
		if (trans_brick->replay_code == TL_REPLAY_FINISHED) {
			MARS_INF_TO(rot->log_say, "logfile replay ended successfully at position %lld\n", trans_brick->replay_current_pos);
			if (rot->replay_code >= TL_REPLAY_RUNNING)
				rot->replay_code = trans_brick->replay_code;
		} else if (trans_brick->replay_code < TL_REPLAY_RUNNING ||
			   ((rot->todo_primary ||
			     /* secondaries must ensure that logrotate has stabilized */
			     _is_secondary_fixing_safe(rot)) && 
			    (trans_brick->replay_code == TL_REPLAY_INCOMPLETE ||
			     trans_brick->replay_end_pos - trans_brick->replay_current_pos < trans_brick->replay_tolerance))) {
			if (trans_brick->replay_code < 0) {
				MARS_ERR_TO(rot->log_say,
				    "logfile replay stopped with error = %d at position %lld + %lld\n",
				    trans_brick->replay_code,
				    trans_brick->replay_current_pos,
				    trans_brick->replay_end_pos - trans_brick->replay_current_pos);
			}
			make_rot_msg(rot, "err-replay-stop",
				     "logfile replay stopped with error = %d at position %lld + %lld",
				     trans_brick->replay_code,
				     trans_brick->replay_current_pos,
				     trans_brick->replay_end_pos - trans_brick->replay_current_pos);
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
				trans_brick->replay_code = TL_REPLAY_FINISHED;
				rot->replay_code = TL_REPLAY_RUNNING;
				MARS_INF_TO(rot->log_say,
					    "exceptional switchover from '%s' to '%s'\n",
					    rot->relevant_log->d_path,
					    rot->next_relevant_log->d_path);
				_make_new_replaylink(rot,
						     rot->next_relevant_log->d_rest,
						     rot->next_relevant_log->d_serial,
						     0);
				assign_dent(&rot->next_relevant_log, NULL);
				rot->aio_brick = NULL;
				goto done;
			/* Designated primary must exceptionally accept a damaged
			 * logfile without successor for recovery under all circumstances.
			 */
			} else if (rot->todo_primary &&
				   rot->relevant_log &&
				   !rot->next_relevant_log &&
				   (!rot->fetch_brick ||
				    !_check_allow(parent->d_path, "connect"))) {
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
	if (rot->stop_logger) {
		status = _stop_trans(rot);
	} else if (trans_brick->power.button &&
		   trans_brick->power.led_on &&
		   !trans_brick->power.led_off) {
		bool do_stop = true;
		if (trans_brick->replay_mode) {
			rot->is_log_damaged =
				(trans_brick->replay_code == -EAGAIN ||
				 trans_brick->replay_code == TL_REPLAY_INCOMPLETE) &&
				trans_brick->replay_end_pos - trans_brick->replay_current_pos < trans_brick->replay_tolerance;
			do_stop = trans_brick->replay_code != TL_REPLAY_RUNNING ||
				!mars_global->global_power.button ||
				!_check_allow(parent->d_path, "allow-replay") ||
				!_check_allow(parent->d_path, "attach") ;

		} else {
			do_stop =
				!rot->if_brick &&
				!rot->is_primary &&
				(!rot->todo_primary ||
				 !_check_allow(parent->d_path, "attach"));
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
			     _check_allow(parent->d_path, "attach") &&
			     _check_allow(parent->d_path, "allow-replay")));

		if (do_start && rot->forbid_replay) {
			MARS_INF("cannot start replay because sync wants to start\n");
			make_rot_msg(rot, "inf-replay-start",
				     "cannot start replay because sync wants to start");
			do_start = false;
		}

		if (do_start && rot->sync_brick && !rot->sync_brick->power.led_off) {
			MARS_INF("cannot start replay because sync is running\n");
			if (!rot->sync_brick->power.button)
				make_rot_msg(rot, "inf-replay-start",
				     "cannot start replay because sync has not yet stopped");
			do_start = false;
		}

		MARS_DBG("rot->replay_mode = %d rot->start_pos = %lld rot->end_pos = %lld | do_start = %d\n", rot->replay_mode, rot->start_pos, rot->end_pos, do_start);

		if (do_start) {
			status = _start_trans(rot);
		}
	}

done:
	rot->stop_logger =
		trans_brick &&
		!trans_brick->power.button &&
		(!trans_brick->power.led_off ||
		 rot->trans_brick->inputs[TL_INPUT_LOG1]->connect ||
		 rot->trans_brick->inputs[TL_INPUT_LOG2]->connect);

	// check whether some copy has finished
	fetch_brick = (struct copy_brick *)
		mars_find_brick(mars_global,
				&copy_brick_type,
				rot->fetch_path);
	MARS_DBG("fetch_path = '%s' fetch_brick = %p\n",
		 rot->fetch_path, fetch_brick);
	if (fetch_brick &&
	    (fetch_brick->power.led_off ||
	     fetch_brick->power.force_off ||
	     fetch_brick->copy_error ||
	     !mars_global->global_power.button ||
	     !_check_allow(parent->d_path, "connect") ||
	     !_check_allow(parent->d_path, "attach") ||
	     (fetch_brick->copy_last == fetch_brick->copy_end &&
	      (rot->fetch_next_is_available > 0 ||
	       rot->fetch_round++ > 3)))) {
		_timeout_prev((void *)fetch_brick);
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
		bool do_attach = _check_allow(parent->d_path, "attach");
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
int make_primary(struct mars_dent *dent)
{
	struct mars_dent *parent;
	struct mars_rotate *rot;
	int status = -EINVAL;

	parent = dent->d_parent;
	if (!parent)
		goto done;
	CHECK_PTR(parent, done);
	rot = parent->d_private;
	if (!rot)
		goto done;
	CHECK_PTR(rot, done);

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
		mars_global->global_power.button &&
		_check_allow(rot->parent_path, "attach") &&
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
int make_bio(struct mars_dent *dent)
{
	struct mars_rotate *rot;
	struct mars_brick *brick;
	bool switch_on;
	int status = 0;

	if (!dent->d_parent) {
		goto done;
	}
	rot = dent->d_parent->d_private;
	if (!rot)
		goto done;

	rot->tmp_members++;

	/* for detach, both the logger and the bio must be gone */
	if (rot->trans_brick)
		rot->is_attached = true;
	else if (rot->sync_brick)
		rot->is_attached = true;
	else if (!rot->bio_brick)
		rot->is_attached = false;
	_show_actual(rot->parent_path, "is-attached", rot->is_attached);

	if (rot->rot_activated)
		activate_peer(dent->d_rest, NULL, NULL, false);
	if (strcmp(dent->d_rest, my_id()))
		goto done;

	activate_rot(rot);

	switch_on = _check_allow(rot->parent_path, "attach");
	if (switch_on && rot->res_shutdown) {
		MARS_ERR("cannot access disk: resource shutdown mode is currently active\n");
		switch_on = false;
	}

	brick =
		make_brick_all(mars_global,
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
	if (brick->type == (void *)&bio_brick_type)
		__show_actual(rot->parent_path,
			      "disk-error",
			      ((struct bio_brick *)brick)->error);
	else if (brick->type == (void *)&aio_brick_type && brick->outputs[0])
		__show_actual(rot->parent_path,
			      "disk-error",
			      ((struct aio_brick *)brick)->outputs[0]->error);
	else if (brick->type == (void *)&sio_brick_type && brick->outputs[0])
		__show_actual(rot->parent_path,
			      "disk-error",
			      ((struct sio_brick *)brick)->outputs[0]->error);

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

static int make_replay(struct mars_dent *dent)
{
	struct mars_dent *parent = dent->d_parent;
	int status = 0;

	if (!parent || !dent->new_link) {
		MARS_DBG("nothing to do\n");
		goto done;
	}

	status = make_log_finalize(dent);
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
			      atomic_read(&if_brick->read_flying_count) +
			      atomic_read(&if_brick->write_flying_count));
		__show_actual(rot->parent_path, "if-state",
			      if_brick->error_code);
		__show_stamp(rot->parent_path, "if-completion-stamp",
			     &if_brick->completion_stamp);
		open_count = atomic_read(&if_brick->open_count);
	}
	_show_brick_status((void *)if_brick, rot->parent_path, "if");
	__show_actual(rot->parent_path, "open-count", open_count);

	if (open_count != rot->old_open_count) {
		rot->old_open_count = open_count;
		mars_remote_trigger(MARS_TRIGGER_TO_REMOTE);
	}
}

static
int make_dev(struct mars_dent *dent)
{
	struct mars_dent *parent = dent->d_parent;
	struct mars_rotate *rot = NULL;
	struct mars_brick *dev_brick;
	bool switch_on;
	int status = 0;

	if (!parent || !dent->new_link) {
		MARS_ERR("nothing to do '%s'\n", dent->d_rest);
		return -EINVAL;
	}
	rot = parent->d_private;
	if (!rot || !rot->parent_path) {
		MARS_DBG("no rot '%s'\n", dent->d_rest);
		goto err;
	}
	activate_peer(dent->d_rest, NULL, NULL, false);
	if (strcmp(dent->d_rest, my_id())) {
		MARS_DBG("nothing to do\n");
		goto err;
	}
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
		 _check_allow(rot->parent_path, "attach"));
	if (!mars_global->global_power.button) {
		switch_on = false;
	}
	if (switch_on && rot->res_shutdown) {
		MARS_ERR("cannot create device: resource shutdown mode is currently active\n");
		switch_on = false;
	}

	dev_brick =
		make_brick_all(mars_global,
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

done:
	_show_dev(rot);
	rot->is_primary =
		rot->if_brick && !rot->if_brick->power.led_off;	
	_show_primary(rot, parent);
err:
	return status;
}

static
int kill_dev(struct mars_dent *dent)
{
	struct mars_dent *parent = dent->d_parent;
	int status = kill_any(dent);

	if (status > 0 && parent) {
		struct mars_rotate *rot = parent->d_private;
		if (rot) {
			rot->if_brick = NULL;
		}
	}
	return status;
}

static int _make_direct(struct mars_dent *dent)
{
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

	switch_on = _check_allow(dent->d_parent->d_path, "attach");

	brick = 
		make_brick_all(mars_global,
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
		make_brick_all(mars_global,
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
	if (do_dealloc)
		brick_string_free(src_path);
	return status;
}

static int _make_copy(struct mars_dent *dent)
{
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

	status = __make_copy(dent,
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
	brick_string_free(copy_path);
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
	loff_t copy_last = copy->copy_last;
	int status = -EINVAL;

	if (!peer || peer[0] == '(')
		goto done;

	/* create syncpos symlink when necessary */
	if (copy_last == copy->copy_end && !rot->sync_finish_stamp.tv_sec) {
		get_lamport(NULL, &rot->sync_finish_stamp);
		MARS_DBG("sync finished at timestamp %lld\n",
			 (s64)rot->sync_finish_stamp.tv_sec);
		/* Give the remote replay position a chance to become
		 * recent enough.
		 */
		mars_remote_trigger(MARS_TRIGGER_TO_REMOTE);
		status = -EAGAIN;
		goto done;
	}
	if (rot->sync_finish_stamp.tv_sec) {
		struct lamport_time peer_time = {};

		get_alivelink_stamp("alive", peer, &peer_time);
		if (unlikely(!peer_time.tv_sec)) {
			MARS_ERR("cannot stat '%s' alivelinks\n",
				 peer);
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
		peer_replay_link = ordered_readlink(peer_replay_path, NULL);
		if (unlikely(!peer_replay_link || !peer_replay_link[0])) {
			MARS_ERR("cannot read peer replay link '%s'\n", peer_replay_path);
			goto done;
		}

		_crashme(3, true);

		status = _update_link_when_necessary(rot, "syncpos", peer_replay_link, syncpos_path, false);
		/* Sync is only marked as finished when the syncpos
		 * production was successful and timestamps are recent enough.
		 */
		if (unlikely(status < 0))
			goto done;
		if (lamport_time_compare(&peer_time, &rot->sync_finish_stamp) < 0) {
			MARS_INF("peer replay link '%s' is not recent enough (%lld < %lld)\n",
				 peer_replay_path,
				 (s64)peer_time.tv_sec,
				 (s64)rot->sync_finish_stamp.tv_sec);
			mars_remote_trigger(MARS_TRIGGER_TO_REMOTE);
			status = -EAGAIN;
			goto done;
		}
	}

	src = path_make("%lld", copy_last);
	dst = path_make("%s/syncstatus-%s", rot->parent_path, my_id());

	_crashme(4, true);

	status = _update_link_when_necessary(rot, "syncstatus", src, dst, false);
	if (!status)
		rot->sync_copy_last = copy_last;

	brick_string_free(src);
	brick_string_free(dst);
	src = path_make("%lld,%lld", copy->verify_ok_count, copy->verify_error_count);
	dst = path_make("%s/verifystatus-%s", rot->parent_path, my_id());

	_crashme(5, true);

	(void)_update_link_when_necessary(rot, "verifystatus", src, dst, false);

	memset(&rot->sync_finish_stamp, 0, sizeof(rot->sync_finish_stamp));
done:
	brick_string_free(src);
	brick_string_free(dst);
	brick_string_free(peer_replay_link);
	brick_string_free(peer_replay_path);
	brick_string_free(syncpos_path);
	return status;
}

struct syncstatus_cookie {
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
	     (copy->copy_last > copy->copy_start) ||
	     (copy->copy_last == copy->copy_end && copy->copy_end > 0))) {
		status = _update_syncstatus(cc->rot, copy, cc->peer);
	}
	return status;
}

static int make_sync(struct mars_dent *dent)
{
	struct mars_rotate *rot;
	loff_t start_pos = 0;
	loff_t end_pos = 0;
	const char *size_str = NULL;
	const char *syncfrom_str = NULL;
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
	rot = dent->d_parent->d_private;

	do_start = _check_allow(dent->d_parent->d_path, "attach");

	/* Determine peer
	 */
	tmp = path_make("%s/primary", dent->d_parent->d_path);
	peer = ordered_readlink(tmp, NULL);
	if (is_deleted_link(peer)) {
		MARS_ERR("cannot determine primary, symlink '%s'\n", tmp);
		if (do_start)
			make_rot_msg(rot, "inf-sync-start",
			     "cannot sync because no primary is designated");
		status = 0;
		goto done;
	}

	/* Analyze replay position
	 */
	status = sscanf(dent->new_link, "%lld", &start_pos);
	if (status != 1) {
		if (strcmp(dent->new_link, ".deleted"))
			MARS_ERR("bad syncstatus symlink syntax '%s' (%s)\n",
				 dent->new_link, dent->d_path);
		if (do_start)
			make_rot_msg(rot, "inf-sync-start",
			     "cannot sync because syncstatus link is bad");
		do_start = false;
	}

	rot->allow_update = true;
	assign_dent(&rot->syncstatus_dent, dent);

	/* Sync necessary?
	 */
	brick_string_free(tmp);
	tmp = path_make("%s/size", dent->d_parent->d_path);
	status = -ENOMEM;
	if (unlikely(!tmp))
		goto done;
	size_str = ordered_readlink(tmp, NULL);
	if (is_deleted_link(size_str)) {
		MARS_ERR("cannot determine size '%s'\n", tmp);
		if (do_start)
			make_rot_msg(rot, "inf-sync-start",
			     "cannot sync because size link is missing");
		status = -ENOENT;
		goto done;
	}
	status = sscanf(size_str, "%lld", &end_pos);
	if (status != 1) {
		MARS_ERR("bad size symlink syntax '%s' (%s)\n", size_str, tmp);
		if (do_start)
			make_rot_msg(rot, "inf-sync-start",
			     "cannot sync because size link is bad");
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
		make_rot_msg(rot, "inf-sync-start",
			     "cannot start sync because logfiles are discontiguous");
		start_pos = 0;
		do_start = false;
	}

	/* stop sync when primary is unknown
	 */
	if (do_start &&
	    (!peer || !peer[0] || !strcmp(peer, "(none)"))) {
		MARS_INF("cannot start sync, no primary is designated\n");
		make_rot_msg(rot, "inf-sync-start",
			     "cannot start sync because no primary is designated");
		start_pos = 0;
		do_start = false;
	}

	/* Check syncfrom link (when existing)
	 */
	brick_string_free(tmp);
	tmp = path_make("%s/syncfrom-%s", dent->d_parent->d_path, my_id());
	syncfrom_str = ordered_readlink(tmp, NULL);
	if (do_start &&
	    !is_deleted_link(syncfrom_str) &&
	    strcmp(syncfrom_str, peer)) {
		MARS_WRN("cannot start sync, primary has changed: '%s' != '%s'\n",
			 syncfrom_str, peer);
		make_rot_msg(rot, "inf-sync-start",
			     "cannot start sync because primary has changed");
		start_pos = 0;
		do_start = false;
	}

	/* Obey global sync limit
	 */
	if (do_start) {
		_global_sync_nr++;
		if (_global_sync_nr > global_sync_limit && global_sync_limit > 0) {
			make_rot_msg(rot, "inf-sync-start",
			     "do not start sync due to global synclimit");
			do_start = false;
		}
	}
	rot->want_sync = do_start;

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
	if (do_start) {
		MARS_DBG("update info links\n");
		write_info_links(rot);
	}
	rot->forbid_replay = (do_start &&
			      compare_replaylinks(rot, peer, my_id(), NULL, NULL) < 0);
	if (rot->forbid_replay) {
		MARS_INF("cannot start sync because my data is newer than the remote one at '%s'!\n", peer);
		make_rot_msg(rot, "inf-sync-start",
			     "ensure data consistency: cannot start sync because replay has gone too far");
		do_start = false;
	}

	/* Flip between replay and sync
	 */
	if (do_start && rot->replay_mode && rot->end_pos > rot->start_pos &&
	    mars_sync_flip_interval >= 8) {
		if (!rot->flip_start) {
			/* Give replay a chance to jump in, e.g. when
			 * multiple logrotates are necessary, or when
			 * logfiles are damaged, etc.
			 * Exception: the current logfile cannot be freed
			 * anyway.
			 */
			if (!rot->next_relevant_log ||
			    rot->flip_round++ > 0) {
				rot->flip_start = jiffies;
				rot->flip_round = 0;
			} else {
				do_start = false;
			}
		} else if ((long long)jiffies - rot->flip_start > mars_sync_flip_interval * HZ &&
			   rot->sync_brick &&
			   rot->sync_brick->power.led_on &&
			   rot->sync_copy_last != rot->sync_copy_last_old) {
			rot->sync_copy_last_old = rot->sync_copy_last;
			do_start = false;
			rot->flip_start = 0;
			rot->flip_round = 0;
			mars_trigger();
		}
	} else {
		rot->flip_start = 0;
		rot->flip_round = 0;
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
	MARS_DBG("start_pos = %lld end_pos = %lld sync_finish_stamp=%lld do_start=%d\n",
		 start_pos, end_pos,
		 (s64)rot->sync_finish_stamp.tv_sec,
		 do_start);

	/* Now do it....
	 */
	{
		const char *argv[2] = { src, dst };
		struct syncstatus_cookie cc = {
			.rot = rot,
			.peer = peer,
		};

		status = __make_copy(dent,
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
	brick_string_free(peer);
	brick_string_free(size_str);
	brick_string_free(syncfrom_str);
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

/* Deprecated, to disappear */
static
int make_connect(struct mars_dent *dent)
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

static int prepare_delete(struct mars_dent *dent)
{
	struct kstat stat;
	struct kstat *to_delete = NULL;
	struct mars_dent *target;
	struct mars_dent *response;
	const char *response_path = NULL;
	struct mars_brick *brick;
	int max_serial = 0;
	int status;

	if (!dent || !dent->new_link || !dent->d_path) {
		goto err;
	}

	brick = mars_find_brick(mars_global, NULL, dent->new_link);
	if (brick &&
	    unlikely((brick->nr_outputs > 0 && brick->outputs[0] && brick->outputs[0]->nr_connected) ||
		     (brick->type == (void*)&if_brick_type && !brick->power.led_off))) {
		MARS_WRN("target '%s' cannot be deleted, its brick '%s' in use\n", dent->new_link, SAFE_STR(brick->brick_name));
		goto done;
	}

	status = 0;
	target = mars_find_dent(mars_global, dent->new_link);
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
		if (dent->d_serial <= mars_global->deleted_border) {
			MARS_DBG("removing deletion symlink '%s'\n", dent->d_path);
			dent->d_killme = true;
			mars_unlink(dent->d_path);
		}
	}

 done:
	// tell the world that we have seen this deletion... (even when not yet accomplished)
	response_path = path_make("/mars/todo-global/deleted-%s", my_id());
	response = mars_find_dent(mars_global, response_path);
	if (response && response->new_link) {
		sscanf(response->new_link, "%d", &max_serial);
	}
	if (dent->d_serial > max_serial) {
		char response_val[16];
		max_serial = dent->d_serial;
		mars_global->deleted_my_border = max_serial;
		snprintf(response_val, sizeof(response_val), "%09d", max_serial);
		ordered_symlink(response_val, response_path, NULL);
	}

 err:
	brick_string_free(response_path);
	return 0;
}

static int check_deleted(struct mars_dent *dent)
{
	int serial = 0;
	int status;

	if (!dent || !dent->new_link) {
		goto done;
	}

	status = sscanf(dent->new_link, "%d", &serial);
	if (status != 1 || serial <= 0) {
		MARS_WRN("cannot parse symlink '%s' -> '%s'\n", dent->d_path, dent->new_link);
		goto done;
	}

	if (!strcmp(dent->d_rest, my_id())) {
		mars_global->deleted_my_border = serial;
		if (mars_global->deleted_my_border != mars_global->old_deleted_my_border) {
			mars_global->old_deleted_my_border = mars_global->deleted_my_border;
			mars_remote_trigger(MARS_TRIGGER_TO_REMOTE);
		}
	}

	/* Compute the minimum of the deletion progress among
	 * the resource members.
	 */
	if (serial < mars_global->deleted_min || !mars_global->deleted_min)
		mars_global->deleted_min = serial;

	
 done:
	return 0;
}

/* transient, to re-disappear */
static
int get_compat_deletions(struct mars_dent *dent)
{
	if (dent && dent->new_link)
		sscanf(dent->new_link, "%d", &compat_deletions);
	return 0;
}

static
int make_res(struct mars_dent *dent)
{
	MARS_DBG("init '%s'\n", dent->d_path);
	dent->d_skip_fn = skip_scan_resource;
	dent->d_running = true;

	return 0;
}

static
int kill_res(struct mars_dent *dent)
{
	struct mars_rotate *rot = dent->d_private;

	if (unlikely(!rot || !rot->parent_path)) {
		MARS_DBG("nothing to do\n");
		goto done;
	}
	dent->d_running = true;

	show_vals(rot->msgs, rot->parent_path, "");

	if (!dent->d_no_scan) {
		MARS_DBG("resource '%s' is active, nothing to kill.\n",
			 rot->parent_path);
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
		dent->d_running = false;
	}

 done:
	MARS_DBG("d_running=%d\n", dent->d_running);
	return 0;
}

static
int make_uuid(struct mars_dent *dent)
{
	if (!dent->new_link || !*dent->new_link)
		return -EAGAIN;

	if (my_uuid && !strcmp(my_uuid, dent->new_link))
		return 0;

	brick_string_free(my_uuid);
	my_uuid = brick_strdup(dent->new_link);
	/* Do not write alivelinks before {create,join}-cluster
	 * has been exectued.
	 */
	write_alivelinks = true;
	return 0;
}

static
int make_defaults(struct mars_dent *dent)
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
		.cl_childs = CL_UUID,
	},

	/* UUID, indentifying the whole cluster.
	 */
	[CL_UUID] = {
		.cl_name = "uuid",
		.cl_len = 4,
		.cl_type = 'l',
		.cl_father = CL_ROOT,
		.cl_forward = make_uuid,
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

	/* Subdirectory for defaults...
	 */
	[CL_DEFAULTS0] = {
		.cl_name = "defaults",
		.cl_len = 8,
		.cl_type = 'd',
		.cl_childs = CL_DEFAULTS_ITEMS0,
		.cl_hostcontext = false,
		.cl_father = CL_ROOT,
	},
	[CL_DEFAULTS] = {
		.cl_name = "defaults-",
		.cl_len = 9,
		.cl_type = 'd',
		.cl_childs = CL_DEFAULTS_ITEMS,
		.cl_hostcontext = true,
		.cl_father = CL_ROOT,
	},

	/* Subdirectory for global controlling items...
	 */
	[CL_GLOBAL_TODO] = {
		.cl_name = "todo-global",
		.cl_len = 11,
		.cl_type = 'd',
		.cl_childs = CL_GLOBAL_TODO_DELETE,
		.cl_hostcontext = false,
		.cl_father = CL_ROOT,
	},

	/* Directory containing the addresses of all peers
	 */
	[CL_IPS] = {
		.cl_name = "ips",
		.cl_len = 3,
		.cl_type = 'd',
		.cl_childs = CL_PEERS,
		.cl_father = CL_ROOT,
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
	/* transient, to re-disappear */
	[CL_COMPAT_DELETIONS] = {
		.cl_name = "compat-deletions",
		.cl_len = 16,
		.cl_type = 'l',
		.cl_hostcontext = false,
		.cl_father = CL_ROOT,
		.cl_forward = get_compat_deletions,
	},

	/* Directory containing all items of a resource
	 */
	[CL_RESOURCE] = {
		.cl_name = "resource-",
		.cl_len = 9,
		.cl_type = 'd',
		.cl_childs = CL_RESOURCE_USERSPACE,
		.cl_use_channel = true,
		.cl_father = CL_ROOT,
		.cl_forward = make_res,
		.cl_backward = kill_res,
	},

	/* Subdir items
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

	/* Subdirectory for resource-specific userspace items...
	 */
	[CL_RESOURCE_USERSPACE] = {
		.cl_name = "userspace",
		.cl_len = 9,
		.cl_type = 'd',
		.cl_hostcontext = false,
		.cl_father = CL_RESOURCE,
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

	/* Subdirectory for controlling items...
	 */
	[CL_RES_TODO] = {
		.cl_name = "todo-",
		.cl_len = 5,
		.cl_type = 'd',
		.cl_hostcontext = false,
		.cl_father = CL_RESOURCE,
	},

	/* Subdirectory for actual state
	 */
	[CL_RES_ACTUAL] = {
		.cl_name = "actual-",
		.cl_len = 7,
		.cl_type = 'd',
		.cl_hostcontext = false,
		.cl_father = CL_RESOURCE,
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
	 * (deprectated, to disappear)
	 */
	[CL_CONNECT] = {
		.cl_name = "connect-",
		.cl_len = 8,
		.cl_type = 'l',
		.cl_hostcontext = true,
		.cl_father = CL_RESOURCE,
		.cl_forward = make_connect,
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
		.cl_hostcontext = false,
		.cl_father = CL_RESOURCE,
#ifdef RUN_DEVICE
		.cl_forward = make_dev,
#endif
		.cl_backward = kill_dev,
	},

	{}
};

/* Helper routine to pre-determine the relevance of a name from the filesystem.
 * Caution: this is called as a callback from iterate_dir() and friends.
 * Don't deadlock by producing any filesystem output within this!
 */
int main_checker(struct mars_dent *parent,
		 const char *_name, int namlen,
		 unsigned int d_type,
		 int *prefix,
		 int *serial,
		 bool *use_channel)
{
	int parent_class;
	int start_class;
	int class;
	int status = -2;
#ifdef MARS_DEBUGGING
	const char *name = brick_strndup(_name, namlen);
	if (!name)
		return -ENOMEM;
#else
	const char *name = _name;
#endif

	parent_class = CL_ROOT;
	if (parent)
		parent_class = parent->d_class;
	start_class = main_classes[parent_class].cl_childs;
	for (class = start_class; ; class++) {
		const struct main_class *test = &main_classes[class];
		int len = test->cl_len;

		/* end of subdir */
		if (test->cl_father != parent_class)
			break;
		/* end of table */
		if (!test->cl_name)
			break;

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
			if (namlen-len != my_id_len() ||
			    memcmp(name+len, my_id(), namlen-len)) {
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
	if (!dent->new_stat.mode) {
		/* ignore silently */
		return -EINVAL;
	}

	is_deleted = dent->new_link &&
		!strcmp(dent->new_link, MARS_DELETED_STR);

	switch (main_classes[class].cl_type) {
	case 'd':
		if (!S_ISDIR(dent->new_stat.mode) && !is_deleted) {
			MARS_ERR_ONCE(dent,
				      "'%s' should be a directory, but is 0x%x\n",
				      dent->d_path, dent->new_stat.mode);
			return -EINVAL;
		}
		break;
	case 'f':
		if (!S_ISREG(dent->new_stat.mode) && !is_deleted) {
			MARS_ERR_ONCE(dent,
				      "'%s' should be a regular file, but is 0x%x\n",
				      dent->d_path, dent->new_stat.mode);
			return -EINVAL;
		}
		break;
	case 'F':
		if (!S_ISREG(dent->new_stat.mode) && !S_ISLNK(dent->new_stat.mode)) {
			MARS_ERR_ONCE(dent,
				      "'%s' should be a regular file or a symlink, but is 0x%x\n",
				      dent->d_path, dent->new_stat.mode);
			return -EINVAL;
		}
		break;
	case 'l':
		if (!S_ISLNK(dent->new_stat.mode)) {
			MARS_ERR_ONCE(dent,
				      "'%s' should be a symlink, but is 0x%x\n",
				      dent->d_path, dent->new_stat.mode);
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
		MARS_ERR_ONCE(dent,
			      "'%s' class %d has unimplemented type %d\n",
			      dent->d_path,
			      class,
			      main_classes[class].cl_type);
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
			MARS_DBG("--- start working %s on '%s' rest='%s'\n",
				 direction ? "backward" : "forward",
				 dent->d_path,
				 dent->d_rest);
		status = worker(dent);
		MARS_DBG("--- done, worked %s on '%s', status = %d\n",
			 direction ? "backward" : "forward",
			 dent->d_path,
			 status);
		return status;
	}
	return 0;
}

static unsigned int main_round = 0;
static DECLARE_WAIT_QUEUE_HEAD(main_round_event);

void wait_main_round(void)
{
	unsigned int old_main_round = main_round;
	int i;

	for (i = 2; i > 0; i--) {
		mars_trigger();
		wait_event_interruptible_timeout(main_round_event,
						 old_main_round != main_round,
						 60 * HZ);
	}
}

#define SAY_TEST_STR CONFIG_MARS_LOGDIR "/5.total.log"

static int _main_thread(void *data)
{
	long long last_rollover = jiffies;
	char *id = my_id();
	int status = 0;

	if (!id || strlen(id) < 2) {
		MARS_ERR("invalid hostname\n");
		status = -EFAULT;
		goto done;
	}	

	MARS_INF("-------- starting as host '%s' ----------\n", id);

        while (mars_global->global_power.button ||
	       peer_count > 0 ||
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

		MARS_DBG("-------- %d/%d NEW ROUND %d %d %d ---------\n",
			 mars_global->global_power.button,
			 mars_net_is_alive,
			 atomic_read(&server_handler_count),
			 peer_count,
			 !list_empty(&mars_global->brick_anchor));

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
		if (start_full_fetch &&
		    mars_running_additional_peers <= mars_run_additional_peers) {
			tmp_full_fetch = true;
			start_full_fetch = false;
		}

		status = mars_dent_work(mars_global,
					"/mars",
					sizeof(struct mars_dent),
					main_checker, main_worker,
					mars_global,
					3, true);

		tmp_full_fetch = false;
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

		usable_marsadm_version_major = _tmp_marsadm_version_major;
		usable_marsadm_version_minor = _tmp_marsadm_version_minor;
		_tmp_marsadm_version_major = -1;
		_tmp_marsadm_version_minor = -1;
		get_marsadm_version(my_id());
		MARS_DBG("usable_version %d %d %d.%d\n",
			 usable_features_version,
			 usable_strategy_version,
			 marsadm_version_major,
			 marsadm_version_minor);

		_compat_additional =
			usable_strategy_version < 4 ||
			usable_marsadm_version_major < 2 ||
			(usable_marsadm_version_major == 2 &&
			 usable_marsadm_version_minor < 9);

		/* possibly start additional background peers */
		if (!_tmp_oneshot_peer) {
			/* rollover */
			oneshot_stamp.tv_sec = 0;
		} else if (mars_running_additional_peers < mars_run_additional_peers) {
			brick_string_free(oneshot_peer);
			oneshot_peer = _tmp_oneshot_peer;
			_tmp_oneshot_peer = NULL;
			oneshot_stamp = _tmp_oneshot_stamp;
			_tmp_oneshot_stamp.tv_sec = 0;
		}

		/* determine compat_* variables */
		compat_alivelinks =
			needed_compat_alivelinks ||
			!(usable_strategy_version >= 3 &&
			  (marsadm_version_major > 2 ||
			   (marsadm_version_major == 2 &&
			    marsadm_version_minor >= 8)));
		needed_compat_alivelinks = false;

		__make_alivelink("compat-alivelinks", compat_alivelinks, true);

		down_read(&rot_sem);
		for (tmp = rot_anchor.next; tmp != &rot_anchor; tmp = tmp->next) {
			struct mars_rotate *rot = container_of(tmp, struct mars_rotate, rot_head);

			rot->rot_activated = false;
			rot->nr_members = rot->tmp_members;
			rot->tmp_members = 0;
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

		/* main_round point */
		main_round++;
		wake_up_interruptible_all(&main_round_event);
		launch_all(false);

		brick_msleep(100);

		wait_event_interruptible_timeout(mars_global->main_event,
						 mars_global->main_trigger,
						 mars_scan_interval * HZ);

		mars_global->main_trigger = false;
		trigger_mode = mars_global->trigger_mode;
		mars_global->trigger_mode = 0;
		/* avoid self-trigger loops */
		trigger_mode &= ~(MARS_TRIGGER_LOCAL);
		if (trigger_mode) {
			mars_remote_trigger(trigger_mode);
		}
	}

done:
	MARS_INF("-------- cleaning up ----------\n");
	mars_remote_trigger(MARS_TRIGGER_TO_REMOTE);
	brick_msleep(1000);

	down_write(&rot_sem);
	while (!list_empty(&rot_anchor)) {
		struct mars_rotate *rot;

		rot = container_of(rot_anchor.next, struct mars_rotate, rot_head);
		up_write(&rot_sem);
		rot_destruct(rot);
		down_write(&rot_sem);
	}
	up_write(&rot_sem);

	mars_free_dent_all(mars_global);
	mars_kill_brick_all(mars_global, &mars_global->brick_anchor, false);

	show_vals(gbl_pairs, "/mars", "");
	show_statistics(mars_global, "main");

	brick_string_free(mars_resource_list);
	brick_string_free(tmp_resource_list);
	brick_string_free(my_uuid);

	brick_string_free(_tmp_oneshot_peer);
	brick_string_free(oneshot_peer);

	launch_all(true);

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
			"dent stamp=%lld.%09ld path='%s' value='%s'\n",
			(s64)dent->new_stat.mtime.tv_sec, dent->new_stat.mtime.tv_nsec,
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


static
int init_global_mem(void)
{
	mars_global = alloc_mars_global();
	return 0;
}

static
void exit_global_mem(void)
{
	free_mars_global(mars_global);
}

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
	int round = 0;
	int status;

	/* Disallow /mars residing on the root filesystem.
	 * Suchalike may cause a plethora of interferences
	 * between the block layer and higher layers.
	 * We insist on Dijkstra's layering rules as close as possible.
	 * TODO in long term: try to avoid a filesystem at block layer.
	 * However, this will induce a very high effort.
	 */
	for (;;) {
		if (mars_is_mountpoint("/mars/"))
			break;
		/* MARS logging infrastructure is not yet available.
		 */
		if (++round <= 3) {
			printk(KERN_WARNING "Waiting for mountpoint /mars to appear\n");
			msleep(1000 * round);
			continue;
		}
		printk(KERN_ERR "/mars is no mountpoint\n");
		return -EINVAL;
	}

	status = mars_stat("/mars/uuid", &dummy, true);
	if (unlikely(status < 0)) {
		printk(KERN_WARNING "Cluster UUID is missing on /mars/uuid.\n");
		printk(KERN_WARNING "Maybe /mars is invalid, if it already should be initialized.\n");
		printk(KERN_WARNING "You can initialize it via marsadm {create,join}-cluster.\n");
		printk(KERN_WARNING "Please read mars-user-manual.pdf first.\n");
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
	DO_INIT(global_mem);
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

#ifdef MARS_HAS_PREPATCH_V2
MODULE_INFO(prepatch, "has_prepatch_v2");
#elif defined(MARS_HAS_PREPATCH)
MODULE_INFO(prepatch, "has_prepatch_v1");
#else
MODULE_INFO(prepatch, "no_prepatch");
#endif
#ifdef ENABLE_MARS_AIO
MODULE_INFO(io_driver, "aio");
#else
MODULE_INFO(io_driver, "sio");
#endif

/* New modinfo on combined debugging info.
 * Format: kernel_options | mars_options
 * where only the most relevant option (AFAICS)
 * is reported.
 * Please extend the kernel-specific list for better
 * sysadmin informations. Sysadmins should not react
 * surprised, as far as possible.
 */
#if defined(CONFIG_KASAN)
#define KERN_DEBUG_INFO "CONFIG_KASAN"
#elif defined(CONFIG_DEBUG_PAGEALLOC)
#define KERN_DEBUG_INFO "CONFIG_DEBUG_PAGEALLOC"
#else
#define KERN_DEBUG_INFO  "assumed_production_kernel"
#endif

/* MARS-specific debugging (defined at compiletime):
 * Such options should always start with CONFIG_MARS_*
 */
#if defined(CONFIG_MARS_DEBUG_ORDER0)
#define MARS_DEBUG_INFO "CONFIG_MARS_DEBUG_MEM | CONFIG_MARS_DEBUG_ORDER0"
#elif defined(CONFIG_MARS_DEBUG_MEM)
#define MARS_DEBUG_INFO "CONFIG_MARS_DEBUG_MEM"
#elif defined(CONFIG_MARS_DEBUG_DEFAULT)
#define MARS_DEBUG_INFO "CONFIG_MARS_DEBUG_DEFAULT"
#elif defined(CONFIG_MARS_DEBUG)
#define MARS_DEBUG_INFO "CONFIG_MARS_DEBUG"
#elif defined(CONFIG_MARS_CHECKS)
#define MARS_DEBUG_INFO "CONFIG_MARS_CHECKS"
#else
#define MARS_DEBUG_INFO "mars_production"
#endif

/* Currently, MARS debugging is more or less orthogonal
 * to kernel debugging.
 * The new report syntax tries to transport this to
 * sysadmins.
 */
MODULE_INFO(debug, KERN_DEBUG_INFO " | " MARS_DEBUG_INFO);

/* Old style module info (may disappear in future)
 */
#ifdef CONFIG_MARS_DEBUG_MEM
MODULE_INFO(io, "BAD_PERFORMANCE");
#endif
#ifdef CONFIG_MARS_DEBUG_ORDER0
MODULE_INFO(memory, "EVIL_PERFORMANCE");
#endif

module_init(init_main);
module_exit(exit_main);
