// (c) 2011 Thomas Schoebel-Theuer / 1&1 Internet AG

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
#include <linux/debug_locks.h>

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

loff_t global_total_space = 0;
EXPORT_SYMBOL_GPL(global_total_space);

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

int mars_rollover_interval = CONFIG_MARS_ROLLOVER_INTERVAL;
EXPORT_SYMBOL_GPL(mars_rollover_interval);

int mars_scan_interval = CONFIG_MARS_SCAN_INTERVAL;
EXPORT_SYMBOL_GPL(mars_scan_interval);

int mars_propagate_interval = CONFIG_MARS_PROPAGATE_INTERVAL;
EXPORT_SYMBOL_GPL(mars_propagate_interval);

int mars_sync_flip_interval = CONFIG_MARS_SYNC_FLIP_INTERVAL;
EXPORT_SYMBOL_GPL(mars_sync_flip_interval);

int mars_fast_fullsync =
#ifdef CONFIG_MARS_FAST_FULLSYNC
	1
#else
	0
#endif
	;
EXPORT_SYMBOL_GPL(mars_fast_fullsync);

int mars_emergency_mode = 0;
EXPORT_SYMBOL_GPL(mars_emergency_mode);

int mars_reset_emergency = 1;
EXPORT_SYMBOL_GPL(mars_reset_emergency);

#define IS_EXHAUSTED()             (mars_emergency_mode > 0)
#define IS_EMERGENCY_SECONDARY()   (mars_emergency_mode > 1)
#define IS_EMERGENCY_PRIMARY()     (mars_emergency_mode > 2)
#define IS_JAMMED()                (mars_emergency_mode > 3)

static
void _make_alivelink_str(const char *name, const char *src)
{
	char *dst = path_make("/mars/%s-%s", name, my_id());
	if (!src || !dst) {
		MARS_ERR("cannot make alivelink paths\n");
		goto err;
	}
	MARS_DBG("'%s' -> '%s'\n", src, dst);
	mars_symlink(src, dst, NULL, 0);
err:
	brick_string_free(dst);
}

static
void _make_alivelink(const char *name, loff_t val)
{
	char *src = path_make("%lld", val);
	_make_alivelink_str(name, src);
	brick_string_free(src);
}

static
int compute_emergency_mode(void)
{
	loff_t rest = 0;
	loff_t limit = 0;
	int mode = 4;

	mars_remaining_space("/mars", &global_total_space, &rest);

#define CHECK_LIMIT(LIMIT_VAR)					\
	if (LIMIT_VAR > 0)					\
		limit += (loff_t)LIMIT_VAR * 1024 * 1024;	\
	if (rest < limit) {					\
		mars_emergency_mode = mode;			\
		goto done;					\
	}							\
	mode--;							\

	CHECK_LIMIT(global_free_space_4);
	CHECK_LIMIT(global_free_space_3);
	CHECK_LIMIT(global_free_space_2);
	CHECK_LIMIT(global_free_space_1);

	/* No limit has hit.
	 * Decrease the emergeny mode only in single steps.
	 */
	if (mars_reset_emergency && mars_emergency_mode > 0) {
		mars_emergency_mode--;
	}

done:
	_make_alivelink("emergency", mars_emergency_mode);

	global_remaining_space = rest - limit;
	_make_alivelink("rest-space", global_remaining_space / (1024 * 1024));

	limit += global_free_space_0;
	if (unlikely(global_total_space < limit)) {
		return -ENOMEM;
	}
	return 0;
}

///////////////////////////////////////////////////////////////////

static struct task_struct *main_thread = NULL;

typedef int (*light_worker_fn)(void *buf, struct mars_dent *dent);

struct light_class {
	char *cl_name;
	int    cl_len;
	char   cl_type;
	bool   cl_hostcontext;
	bool   cl_serial;
	bool   cl_use_channel;
	int    cl_father;
	light_worker_fn cl_prepare;
	light_worker_fn cl_forward;
	light_worker_fn cl_backward;
};

///////////////////////////////////////////////////////////////////////

// needed for logfile rotation

#define MAX_INFOS 4

struct mars_rotate {
	struct mars_global *global;
	struct copy_brick *sync_brick;
	struct mars_dent *replay_link;
	struct mars_dent *aio_dent;
	struct aio_brick *aio_brick;
	struct mars_info aio_info;
	struct trans_logger_brick *trans_brick;
	struct mars_dent *first_log;
	struct mars_dent *relevant_log;
	struct mars_brick *relevant_brick;
	struct mars_dent *next_relevant_log;
	struct mars_brick *next_relevant_brick;
	struct mars_dent *next_next_relevant_log;
	struct mars_dent *prev_log;
	struct mars_dent *next_log;
	struct mars_dent *syncstatus_dent;
	struct if_brick *if_brick;
	const char *copy_path;
	const char *parent_path;
	struct say_channel *log_say;
	struct copy_brick *copy_brick;
	struct mars_limiter replay_limiter;
	struct mars_limiter sync_limiter;
	struct mars_limiter file_limiter;
	int inf_prev_sequence;
	long long flip_start;
	loff_t dev_size;
	loff_t total_space;
	loff_t remaining_space;
	loff_t start_pos;
	loff_t end_pos;
	int max_sequence;
	int copy_serial;
	int copy_next_is_available;
	int relevant_serial;
	bool has_error;
	bool allow_update;
	bool forbid_replay;
	bool replay_mode;
	bool todo_primary;
	bool is_primary;
	bool old_is_primary;
	bool copy_is_done;
	bool created_hole;
	spinlock_t inf_lock;
	bool infs_is_dirty[MAX_INFOS];
	struct trans_logger_info infs[MAX_INFOS];
};

///////////////////////////////////////////////////////////////////////

// TUNING

int mars_mem_percent = 20;
EXPORT_SYMBOL_GPL(mars_mem_percent);

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
#define BIO_NOIDLE true
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
	client_brick->io_timeout = 0;
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
	bio_brick->do_noidle = BIO_NOIDLE;
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
	if (rot)
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
		copy_brick->copy_last = 0;
		for (i = 0; i < 2; i++) {
			status = cc->output[i]->ops->mars_get_info(cc->output[i], &cc->info[i]);
			if (status < 0) {
				MARS_WRN("cannot determine current size of '%s'\n", cc->argv[i]);
				goto done;
			}
			MARS_DBG("%d '%s' current_size = %lld\n", i, cc->fullpath[i], cc->info[i].current_size);
		}
		copy_brick->copy_start = cc->info[1].current_size;
		if (cc->start_pos != -1) {
			copy_brick->copy_start = cc->start_pos;
			if (unlikely(cc->info[0].current_size != cc->info[1].current_size)) {
				MARS_ERR("oops, devices have different size %lld != %lld at '%s'\n", cc->info[0].current_size, cc->info[1].current_size, cc->copy_path);
				status = -EINVAL;
				goto done;
			}
			if (unlikely(cc->start_pos > cc->info[0].current_size)) {
				MARS_ERR("bad start position %lld is larger than actual size %lld on '%s'\n", cc->start_pos, cc->info[0].current_size, cc->copy_path);
				status = -EINVAL;
				goto done;
			}
		}
		MARS_DBG("copy_start = %lld\n", copy_brick->copy_start);
		copy_brick->copy_end = cc->info[0].current_size;
		MARS_DBG("copy_end = %lld\n", copy_brick->copy_end);
		if (copy_brick->copy_start < copy_brick->copy_end) {
			status = 1;
			MARS_DBG("copy switch on\n");
		}
	} else if (copy_brick->power.button && copy_brick->power.led_on && copy_brick->copy_last == copy_brick->copy_end && copy_brick->copy_end > 0) {
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
bool _check_switch(struct mars_global *global, const char *path)
{
	int res = false;
	struct mars_dent *allow_dent;

	allow_dent = mars_find_dent(global, path);
	if (!allow_dent || !allow_dent->new_link)
		goto done;
	sscanf(allow_dent->new_link, "%d", &res);
	MARS_DBG("'%s' -> %d\n", path, res);

done:
	return res;
}

static
bool _check_allow(struct mars_global *global, struct mars_dent *parent, const char *name)
{
	int res = false;
	char *path = path_make("%s/todo-%s/%s", parent->d_path, my_id(), name);

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
	*host = NULL;

	count = sscanf(str, "log-%d-%n", seq, &len);
	if (unlikely(count != 1)) {
		MARS_ERR("bad logfile name '%s', count=%d, len=%d\n", str, count, len);
		return 0;
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

	a = mars_readlink(linka);
	if (unlikely(!a)) {
		MARS_ERR_TO(rot->log_say, "cannot read replaylink '%s'\n", linka);
		goto done;
	}
	b = mars_readlink(linkb);
	if (unlikely(!b)) {
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

	if (posa < posb) {
		res = -1;
	} else if (posa > posb) {
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
int _update_replay_link(struct mars_rotate *rot, struct trans_logger_info *inf)
{
	char *check = NULL;
	char *old = NULL;
	char *new = NULL;
	int status;
	int res = 0;

	old = path_make("log-%09d-%s,%lld,%lld", inf->inf_sequence, inf->inf_host, inf->inf_min_pos, inf->inf_max_pos - inf->inf_min_pos);
	if (!old) {
		goto out;
	}
	new = path_make("%s/replay-%s", rot->parent_path, my_id());
	if (!new) {
		goto out;
	}

	/* Check whether something really has changed (avoid
	 * useless/disturbing timestamp updates)
	 */
	check = mars_readlink(new);
	if (check && !strcmp(check, old)) {
		MARS_DBG("replay symlink '%s' -> '%s' has not changed\n", old, new);
		goto out;
	}

	status = mars_symlink(old, new, NULL, 0);
	if (unlikely(status < 0)) {
		MARS_ERR_TO(rot->log_say, "cannot create replay symlink '%s' -> '%s' status = %d\n", old, new, status);
	} else {
		res = 1;
		MARS_DBG("made replay symlink '%s' -> '%s' status = %d\n", old, new, status);
	}

out:
	brick_string_free(new);
	brick_string_free(old);
	brick_string_free(check);
	return res;
}

static
int _update_version_link(struct mars_rotate *rot, struct trans_logger_info *inf)
{
	char *data = brick_string_alloc(0);
	char *old = brick_string_alloc(0);
	char *new = NULL;
	unsigned char *digest = brick_string_alloc(0);
	char *prev = NULL;
	char *check = NULL;
	char *prev_link = NULL;
	char *prev_digest = NULL;
	int len;
	int i;
	int status;
	int res = 0;

	if (unlikely(!data || !digest || !old)) {
		MARS_ERR("no MEM\n");
		goto out;
	}

	if (likely(inf->inf_sequence > 1)) {
		if (unlikely((inf->inf_sequence < rot->inf_prev_sequence ||
			      inf->inf_sequence > rot->inf_prev_sequence + 1) &&
			     rot->inf_prev_sequence != 0)) {
			MARS_ERR_TO(rot->log_say, "SKIP in sequence numbers detected: %d != %d + 1\n", inf->inf_sequence, rot->inf_prev_sequence);
			goto out;
		}
		prev = path_make("%s/version-%09d-%s", rot->parent_path, inf->inf_sequence - 1, my_id());
		if (unlikely(!prev)) {
			MARS_ERR("no MEM\n");
			goto out;
		}
		prev_link = mars_readlink(prev);
		rot->inf_prev_sequence = inf->inf_sequence;
	}

	len = sprintf(data, "%d,%s,%lld:%s", inf->inf_sequence, inf->inf_host, inf->inf_log_pos, prev_link ? prev_link : "");
	
	MARS_DBG("data = '%s' len = %d\n", data, len);

	mars_digest(digest, data, len);

	len = 0;
	for (i = 0; i < mars_digest_size; i++) {
		len += sprintf(old + len, "%02x", digest[i]);
	}

	if (likely(prev_link)) {
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

	/* Check whether something really has changed (avoid
	 * useless/disturbing timestamp updates)
	 */
	check = mars_readlink(new);
	if (likely(check)) {
		if (!strcmp(check, old)) {
			MARS_DBG("version symlink '%s' -> '%s' has not changed\n", old, new);
			goto out;
		}
	}

	status = mars_symlink(old, new, NULL, 0);
	if (unlikely(status < 0)) {
		MARS_ERR_TO(rot->log_say, "cannot create symlink '%s' -> '%s' status = %d\n", old, new, status);
	} else {
		res = 1;
		MARS_DBG("make version symlink '%s' -> '%s' status = %d\n", old, new, status);
	}

out:
	brick_string_free(new);
	brick_string_free(prev);
	brick_string_free(data);
	brick_string_free(digest);
	brick_string_free(old);
	brick_string_free(check);
	brick_string_free(prev_link);
	brick_string_free(prev_digest);
	return res;
}

static
void _update_info(struct trans_logger_info *inf)
{
	struct mars_rotate *rot = inf->inf_private;
	int hash;
	unsigned long flags;

	if (unlikely(!rot)) {
		MARS_ERR("rot is NULL\n");
		goto done;
	}

	MARS_DBG("inf = %p '%s' seq = %d min_pos = %lld max_pos = %lld log_pos = %lld is_applying = %d is_logging = %d\n",
		 inf,
		 SAFE_STR(inf->inf_host),
		 inf->inf_sequence,
		 inf->inf_min_pos,
		 inf->inf_max_pos,
		 inf->inf_log_pos,
		 inf->inf_is_applying,
		 inf->inf_is_logging);

	hash = inf->inf_sequence % MAX_INFOS;
	if (unlikely(rot->infs_is_dirty[hash])) {
		if (unlikely(rot->infs[hash].inf_sequence != inf->inf_sequence)) {
			MARS_ERR_TO(rot->log_say, "buffer %d: sequence trash %d -> %d. is the mar_light thread hanging?\n", hash, rot->infs[hash].inf_sequence, inf->inf_sequence);
		} else {
			MARS_DBG("buffer %d is overwritten (sequence=%d)\n", hash, inf->inf_sequence);
		}
	}

	traced_lock(&rot->inf_lock, flags);
	memcpy(&rot->infs[hash], inf, sizeof(struct trans_logger_info));
	rot->infs_is_dirty[hash] = true;
	traced_unlock(&rot->inf_lock, flags);

	mars_trigger();
done:;
}

static
void write_info_links(struct mars_rotate *rot)
{
	struct trans_logger_info inf;
	int count = 0;
	for (;;) {
		unsigned long flags;
		int hash = -1;
		int min = 0;
		int i;

		traced_lock(&rot->inf_lock, flags);
		for (i = 0; i < MAX_INFOS; i++) {
			if (!rot->infs_is_dirty[i])
				continue;
			if (!min || min > rot->infs[i].inf_sequence) {
				min = rot->infs[i].inf_sequence;
				hash = i;
			}
		}

		if (hash < 0) {
			traced_unlock(&rot->inf_lock, flags);
			break;
		}

		rot->infs_is_dirty[hash] = false;
		memcpy(&inf, &rot->infs[hash], sizeof(struct trans_logger_info));
		traced_unlock(&rot->inf_lock, flags);
		
		MARS_DBG("seq = %d min_pos = %lld max_pos = %lld log_pos = %lld is_applying = %d is_logging = %d\n",
			 inf.inf_sequence,
			 inf.inf_min_pos,
			 inf.inf_max_pos,
			 inf.inf_log_pos,
			 inf.inf_is_applying,
			 inf.inf_is_logging);
		
		if (inf.inf_is_logging || inf.inf_is_applying) {
			count += _update_replay_link(rot, &inf);
		}
		if (inf.inf_is_logging || inf.inf_is_applying) {
			count += _update_version_link(rot, &inf);
		}
	}
	if (count) {
		if (inf.inf_min_pos == inf.inf_max_pos)
			mars_trigger();
		mars_remote_trigger();
	}
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
		.inf_is_applying = true,
	};
	strncpy(inf.inf_host, new_host, sizeof(inf.inf_host));

	MARS_DBG("new_host = '%s' new_sequence = %d end_pos = %lld\n", new_host, new_sequence, end_pos);

	_update_replay_link(rot, &inf);
	_update_version_link(rot, &inf);

#ifdef CONFIG_MARS_FAST_TRIGGER
	mars_trigger();
	mars_remote_trigger();
#endif
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
	status = mars_symlink(src, dst, NULL, 0);

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

	status = mars_symlink(src, dst, NULL, 0);
	MARS_DBG("status symlink '%s' -> '%s' status = %d\n", dst, src, status);
	brick_string_free(dst);
}

static
void _show_status_all(struct mars_global *global)
{
	struct list_head *tmp;
	
	down_read(&global->brick_mutex);
	for (tmp = global->brick_anchor.next; tmp != &global->brick_anchor; tmp = tmp->next) {
		struct mars_brick *test;
		
		test = container_of(tmp, struct mars_brick, global_brick_link);
		if (!test->show_status)
			continue;
		_show_brick_status(test, false);
	}
	up_read(&global->brick_mutex);
}

static
void _show_rate(struct mars_rotate *rot, struct mars_limiter *limiter, bool running, const char *name)
{
	int rate = limiter->lim_rate;
	if (!running)
		rate = 0;
	__show_actual(rot->parent_path, name, rate);
}

///////////////////////////////////////////////////////////////////////

static
int __make_copy(
		struct mars_global *global,
		struct mars_dent *belongs,
		const char *switch_path,
		const char *copy_path,
		const char *parent,
		const char *argv[],
		loff_t start_pos, // -1 means at EOF
		bool verify_mode,
		bool limit_mode,
		struct copy_brick **__copy)
{
	struct mars_brick *copy;
	struct copy_brick *_copy;
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
	int status = -EINVAL;

	if (!switch_path || !global) {
		goto done;
	}

	// don't generate empty aio files if copy does not yet exist
	copy = mars_find_brick(global, &copy_brick_type, copy_path);
	if (!copy && !_check_switch(global, switch_path))
		goto done;

	// create/find predecessor aio bricks
	for (i = 0; i < 2; i++) {
		struct mars_brick *aio;

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
				       false,
				       _set_bio_params,
				       &clc[i],
				       10 * HZ,
				       NULL,
				       (const struct generic_brick_type*)&bio_brick_type,
				       (const struct generic_brick_type*[]){},
				       NULL,
				       1, // start always
				       cc.fullpath[i],
				       (const char *[]){},
				       0);
		if (!aio) {
			MARS_DBG("cannot instantiate '%s'\n", cc.fullpath[i]);
			goto done;
		}
		cc.output[i] = aio->outputs[0];
	}

	cc.copy_path = copy_path;
	cc.start_pos = start_pos;
	cc.verify_mode = verify_mode;

	copy =
		make_brick_all(global,
			       belongs,
			       false,
			       _set_copy_params,
			       &cc,
			       10 * HZ,
			       cc.fullpath[1],
			       (const struct generic_brick_type*)&copy_brick_type,
			       (const struct generic_brick_type*[]){NULL,NULL,NULL,NULL},
			       "%s",
			       (!switch_path[0] || IS_EXHAUSTED()) ? -1 : 0,
			       "%s",
			       (const char *[]){"%s", "%s", "%s", "%s"},
			       4,
			       switch_path,
			       copy_path,
			       cc.fullpath[0],
			       cc.fullpath[0],
			       cc.fullpath[1],
			       cc.fullpath[1]);
	if (!copy) {
		MARS_DBG("creation of copy brick '%s' failed\n", copy_path);
		goto done;
	}
	copy->show_status = _show_brick_status;
	_copy = (void*)copy;
	if (__copy)
		*__copy = _copy;

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

struct mars_peerinfo {
	struct mars_global *global;
	char *peer;
	char *path;
	struct mars_socket socket;
	struct task_struct *peer_thread;
	spinlock_t lock;
	struct list_head remote_dent_list;
	int maxdepth;
};

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
int _update_file(struct mars_rotate *rot, const char *switch_path, const char *copy_path, const char *file, const char *peer, loff_t end_pos)
{
	struct mars_global *global = rot->global;
#ifdef CONFIG_MARS_SEPARATE_PORTS
	const char *tmp = path_make("%s@%s:%d", file, peer, mars_net_default_port + 1);
#else
	const char *tmp = path_make("%s@%s", file, peer);
#endif
	const char *argv[2] = { tmp, file };
	struct copy_brick *copy = NULL;
	int status = -ENOMEM;

	if (unlikely(!tmp || !global))
		goto done;

	MARS_DBG("src = '%s' dst = '%s'\n", tmp, file);
	status = __make_copy(global, NULL, switch_path, copy_path, NULL, argv, -1, false, false, &copy);
	if (status >= 0 && copy) {
		copy->copy_limiter = &rot->file_limiter;
		if ((!copy->append_mode || copy->power.led_off) &&
		    end_pos > copy->copy_end) {
			MARS_DBG("appending to '%s' %lld => %lld\n", copy_path, copy->copy_end, end_pos);
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
	struct copy_brick *copy_brick;
	int status = 0;

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
	if (!rot->copy_path) {
		MARS_WRN("parent has no copy_path\n");
		status = -EINVAL;
		goto done;
	}

	// bookkeeping for serialization of logfile updates
	if (remote_dent->d_serial == rot->copy_serial + 1) {
		rot->copy_next_is_available++;
	}

	// check whether connection is allowed
	switch_path = path_make("%s/todo-%s/connect", parent->d_path, my_id());

	// check whether copy is necessary
	copy_brick = rot->copy_brick;
	MARS_DBG("copy_brick = %p (remote '%s' %d) copy_serial = %d\n", copy_brick, remote_dent->d_path, remote_dent->d_serial, rot->copy_serial);
	if (copy_brick) {
		if (remote_dent->d_serial == rot->copy_serial) {
			// treat copy brick instance underway
			status = _update_file(rot, switch_path, rot->copy_path, remote_dent->d_path, peer, src_size);
			MARS_DBG("re-update '%s' from peer '%s' status = %d\n", remote_dent->d_path, peer, status);
		}
	} else if (!rot->copy_serial && rot->allow_update &&
		   (dst_size < src_size || !local_dent)) {		
		// start copy brick instance
		status = _update_file(rot, switch_path, rot->copy_path, remote_dent->d_path, peer, src_size);
		MARS_DBG("update '%s' from peer '%s' status = %d\n", remote_dent->d_path, peer, status);
		rot->copy_serial = remote_dent->d_serial;
		rot->copy_next_is_available = 0;
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
	bool update_mtime = true;
	bool update_ctime = true;
	bool run_trigger = false;

	if (!strncmp(remote_dent->d_name, ".tmp", 4)) {
		goto done;
	}
	if (!strncmp(remote_dent->d_name, "ignore", 6)) {
		goto done;
	}

	status = mars_stat(remote_dent->d_path, &local_stat, true);
	stat_ok = (status >= 0);

	if (stat_ok) {
		update_mtime = timespec_compare(&remote_dent->new_stat.mtime, &local_stat.mtime) > 0;
		update_ctime = timespec_compare(&remote_dent->new_stat.ctime, &local_stat.ctime) > 0;

		MARS_IO("timestamps '%s' remote = %ld.%09ld local = %ld.%09ld\n", remote_dent->d_path, remote_dent->new_stat.mtime.tv_sec, remote_dent->new_stat.mtime.tv_nsec, local_stat.mtime.tv_sec, local_stat.mtime.tv_nsec);

		if ((remote_dent->new_stat.mode & S_IRWXU) !=
		   (local_stat.mode & S_IRWXU) &&
		   update_ctime) {
			mode_t newmode = local_stat.mode;
			MARS_IO("chmod '%s' 0x%xd -> 0x%xd\n", remote_dent->d_path, newmode & S_IRWXU, remote_dent->new_stat.mode & S_IRWXU);
			newmode &= ~S_IRWXU;
			newmode |= (remote_dent->new_stat.mode & S_IRWXU);
			mars_chmod(remote_dent->d_path, newmode);
			run_trigger = true;
		}

		if (remote_dent->new_stat.uid != local_stat.uid && update_ctime) {
			MARS_IO("lchown '%s' %d -> %d\n", remote_dent->d_path, local_stat.uid, remote_dent->new_stat.uid);
			mars_lchown(remote_dent->d_path, remote_dent->new_stat.uid);
			run_trigger = true;
		}
	}

	if (S_ISDIR(remote_dent->new_stat.mode)) {
		if (!_is_usable_dir(remote_dent->d_name)) {
			MARS_IO("ignoring directory '%s'\n", remote_dent->d_path);
			goto done;
		}
		if (!stat_ok) {
			status = mars_mkdir(remote_dent->d_path);
			MARS_IO("create directory '%s' status = %d\n", remote_dent->d_path, status);
			if (status >= 0) {
				mars_chmod(remote_dent->d_path, remote_dent->new_stat.mode);
				mars_lchown(remote_dent->d_path, remote_dent->new_stat.uid);
			}
		}
	} else if (S_ISLNK(remote_dent->new_stat.mode) && remote_dent->new_link) {
		if (!stat_ok || update_mtime) {
			status = mars_symlink(remote_dent->new_link, remote_dent->d_path, &remote_dent->new_stat.mtime, remote_dent->new_stat.uid);
			MARS_IO("create symlink '%s' -> '%s' status = %d\n", remote_dent->d_path, remote_dent->new_link, status);
			run_trigger = true;
		}
	} else if (S_ISREG(remote_dent->new_stat.mode) && _is_peer_logfile(remote_dent->d_name, my_id())) {
		const char *parent_path = backskip_replace(remote_dent->d_path, '/', false, "");
		if (likely(parent_path)) {
			struct mars_dent *parent = mars_find_dent(peer->global, parent_path);
			struct mars_dent *local_dent = mars_find_dent(peer->global, remote_dent->d_path);
			if (unlikely(!parent)) {
				MARS_IO("ignoring non-existing local resource '%s'\n", parent_path);
			// don't copy old / outdated logfiles
			} else if (parent->d_private &&
				   ((struct mars_rotate *)parent->d_private)->relevant_serial > remote_dent->d_serial) {
				MARS_IO("ignoring outdated remote logfile '%s'\n", remote_dent->d_path);
			} else {
				status = check_logfile(peer->peer, remote_dent, local_dent, parent, local_stat.size);
			}
			brick_string_free(parent_path);
		}
	} else {
		MARS_IO("ignoring '%s'\n", remote_dent->d_path);
	}

 done:
	if (status >= 0) {
		status = run_trigger ? 1 : 0;
	}
	return status;
}

static
int run_bones(struct mars_peerinfo *peer)
{
	LIST_HEAD(tmp_list);
	struct list_head *tmp;
	unsigned long flags;
	bool run_trigger = false;
	int status = 0;

	traced_lock(&peer->lock, flags);
	list_replace_init(&peer->remote_dent_list, &tmp_list);
	traced_unlock(&peer->lock, flags);

	MARS_DBG("remote_dent_list list_empty = %d\n", list_empty(&tmp_list));

	for (tmp = tmp_list.next; tmp != &tmp_list; tmp = tmp->next) {
		struct mars_dent *remote_dent = container_of(tmp, struct mars_dent, dent_link);
		if (!remote_dent->d_path) {
			MARS_DBG("NULL\n");
			continue;
		}
		MARS_IO("path = '%s'\n", remote_dent->d_path);
		status = run_bone(peer, remote_dent);
		if (status > 0)
			run_trigger = true;
		//MARS_DBG("path = '%s' worker status = %d\n", remote_dent->d_path, status);
	}
	mars_free_dent_all(NULL, &tmp_list);
#ifdef CONFIG_MARS_FAST_TRIGGER
	if (run_trigger) {
		mars_trigger();
	}
#endif
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
static atomic_t remote_trigger_count = ATOMIC_INIT(0);
static atomic_t peer_thread_count = ATOMIC_INIT(0);

static
int peer_thread(void *data)
{
	struct mars_peerinfo *peer = data;
	char *real_peer;
	struct sockaddr_storage sockaddr = {};
	int pause_time = 0;
	bool do_kill = false;
	bool flip = false;
	int status;

	if (!peer)
		return -1;

	real_peer = mars_translate_hostname(peer->peer);
	MARS_INF("-------- peer thread starting on peer '%s' (%s)\n", peer->peer, real_peer);

	status = mars_create_sockaddr(&sockaddr, real_peer);
	if (unlikely(status < 0)) {
		MARS_ERR("unusable remote address '%s' (%s)\n", real_peer, peer->peer);
		goto done;
	}

	atomic_inc(&peer_thread_count);

        while (!brick_thread_should_stop()) {
		LIST_HEAD(tmp_list);
		LIST_HEAD(old_list);
		unsigned long flags;
		struct mars_cmd cmd = {
			.cmd_code = CMD_GETENTS,
			.cmd_str1 = peer->path,
			.cmd_int1 = peer->maxdepth,
		};

		if (!mars_socket_is_alive(&peer->socket)) {
			if (do_kill) {
				do_kill = false;
				_peer_cleanup(peer);
				brick_msleep(5000);
				continue;
			}
			if (!mars_net_is_alive) {
				brick_msleep(1000);
				continue;
			}

			status = mars_create_socket(&peer->socket, &sockaddr, false);
			if (unlikely(status < 0)) {
				MARS_INF("no connection to '%s'\n", real_peer);
				brick_msleep(5000);
				continue;
			}
			do_kill = true;
			peer->socket.s_shutdown_on_err = true;
			MARS_DBG("successfully opened socket to '%s'\n", real_peer);
			brick_msleep(100);
			continue;
		}

		/* This is not completely race-free, but does no harm.
		 * In worst case, network propagation will just take
		 * a litte longer (see CONFIG_MARS_PROPAGATE_INTERVAL).
		 */
		if (!flip && atomic_read(&remote_trigger_count) > 0) {
			MARS_DBG("sending notify ... remote_tiogger_count = %d\n", atomic_read(&remote_trigger_count));
			atomic_dec(&remote_trigger_count);
			cmd.cmd_code = CMD_NOTIFY;
			flip = true;
		}

		status = mars_send_struct(&peer->socket, &cmd, mars_cmd_meta);
		if (unlikely(status < 0)) {
			MARS_WRN("communication error on send, status = %d\n", status);
			if (do_kill) {
				do_kill = false;
				_peer_cleanup(peer);
			}
			brick_msleep(2000);
			continue;
		}
		if (cmd.cmd_code == CMD_NOTIFY) {
			flip = false;
			pause_time = 0;
			brick_msleep(1000);
			continue;
		}

		MARS_DBG("fetching remote dentry list\n");
		status = mars_recv_dent_list(&peer->socket, &tmp_list);
		if (unlikely(status < 0)) {
			MARS_WRN("communication error on receive, status = %d\n", status);
			if (do_kill) {
				do_kill = false;
				_peer_cleanup(peer);
			}
			mars_free_dent_all(NULL, &tmp_list);
			brick_msleep(5000);
			continue;
		}

		if (likely(!list_empty(&tmp_list))) {
			MARS_DBG("got remote denties\n");

			traced_lock(&peer->lock, flags);

			list_replace_init(&peer->remote_dent_list, &old_list);
			list_replace_init(&tmp_list, &peer->remote_dent_list);

			traced_unlock(&peer->lock, flags);

			mars_free_dent_all(NULL, &old_list);
		}

		brick_msleep(1000);
		if (!brick_thread_should_stop()) {
			if (pause_time < mars_propagate_interval)
				pause_time++;
			wait_event_interruptible_timeout(remote_event,
							 atomic_read(&remote_trigger_count) > 0 ||
							 (mars_global && mars_global->main_trigger),
							 pause_time * HZ);
		}
	}

	MARS_INF("-------- peer thread terminating\n");

	if (do_kill) {
		_peer_cleanup(peer);
	}

done:
	atomic_dec(&peer_thread_count);
	brick_string_free(real_peer);
	return 0;
}

static
void __mars_remote_trigger(void)
{
	int count = atomic_read(&peer_thread_count);
	atomic_add(count, &remote_trigger_count);
	wake_up_interruptible_all(&remote_event);
}

static
bool is_shutdown(void)
{
	bool res = false;
	int used;
	if ((used = atomic_read(&global_mshadow_count)) > 0) {
		MARS_INF("global shutdown delayed: there are %d buffers in use, occupying %ld bytes\n", used, atomic64_read(&global_mshadow_used));
	} else {
		int rounds = 3;
		while ((used = atomic_read(&mars_global_io_flying)) <= 0) {
			if (--rounds <= 0) {
				res = true;
				break;
			}
			brick_msleep(30);
		}
		if (!res) {
			MARS_INF("global shutdown delayed: there are %d IO requests flying\n", used);
		}
	}
	return res;
}

///////////////////////////////////////////////////////////////////////

// helpers for worker functions

static int _kill_peer(void *buf, struct mars_dent *dent)
{
	LIST_HEAD(tmp_list);
	struct mars_global *global = buf;
	struct mars_peerinfo *peer = dent->d_private;
	unsigned long flags;

	if (global->global_power.button) {
		return 0;
	}
	if (!peer) {
		return 0;
	}

	MARS_INF("stopping peer thread...\n");
	if (peer->peer_thread) {
		brick_thread_stop(peer->peer_thread);
	}
	traced_lock(&peer->lock, flags);
	list_replace_init(&peer->remote_dent_list, &tmp_list);
	traced_unlock(&peer->lock, flags);
	mars_free_dent_all(NULL, &tmp_list);
	brick_string_free(peer->peer);
	brick_string_free(peer->path);
	dent->d_private = NULL;
	brick_mem_free(peer);
	return 0;
}

static int _make_peer(struct mars_global *global, struct mars_dent *dent, char *path)
{
	static int serial = 0;
	struct mars_peerinfo *peer;
	char *mypeer;
	char *parent_path;
	int status = 0;

	if (!global || !global->global_power.button || !dent || !dent->new_link || !dent->d_parent || !(parent_path = dent->d_parent->d_path)) {
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
		peer = dent->d_private;
		peer->global = global;
		peer->peer = brick_strdup(mypeer);
		peer->path = brick_strdup(path);
		peer->maxdepth = 2;
		spin_lock_init(&peer->lock);
		INIT_LIST_HEAD(&peer->remote_dent_list);
	}

	peer = dent->d_private;
	if (!peer->peer_thread) {
		peer->peer_thread = brick_thread_create(peer_thread, peer, "mars_peer%d", serial++);
		if (unlikely(!peer->peer_thread)) {
			MARS_ERR("cannot start peer thread\n");
			return -1;
		}
		MARS_DBG("started peer thread\n");
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
	return _kill_peer(buf, dent);
}

static int make_scan(void *buf, struct mars_dent *dent)
{
	MARS_DBG("path = '%s' peer = '%s'\n", dent->d_path, dent->d_rest);
	// don't connect to myself
	if (!strcmp(dent->d_rest, my_id())) {
		return 0;
	}
	return _make_peer(buf, dent, "/mars");
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
	mars_kill_dent(dent);
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
		filp_close(f, NULL);
		mars_trigger();
	}
}

static
const char *get_replaylink(const char *parent_path, const char *host, const char **linkpath)
{
	const char * _linkpath = path_make("%s/replay-%s", parent_path, host);
	*linkpath = _linkpath;
	if (unlikely(!_linkpath)) {
		MARS_ERR("no MEM\n");
		return NULL;
	}
	return mars_readlink(_linkpath);
}

static
const char *get_versionlink(const char *parent_path, int seq, const char *host, const char **linkpath)
{
	const char * _linkpath = path_make("%s/version-%09d-%s", parent_path, seq, host);
	*linkpath = _linkpath;
	if (unlikely(!_linkpath)) {
		MARS_ERR("no MEM\n");
		return NULL;
	}
	return mars_readlink(_linkpath);
}

static
bool is_switchover_possible(struct mars_rotate *rot, const char *old_log_path, const char *new_log_path, bool skip_new)
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

	if (unlikely(!parse_logfile_name(old_log_name, &old_log_seq, &old_host)))
		goto done;
	if (unlikely(!parse_logfile_name(new_log_name, &new_log_seq, &new_host)))
		goto done;

	// check: are the sequence numbers contiguous?
	if (unlikely(new_log_seq != old_log_seq + 1)) {
		MARS_ERR_TO(rot->log_say, "logfile sequence numbers are not contiguous (%d != %d + 1), old_log_path='%s' new_log_path='%s'\n", new_log_seq, old_log_seq, old_log_path, new_log_path);
		goto done;
	}

	// fetch all the versionlinks and test for their existence.
	own_versionlink = get_versionlink(rot->parent_path, old_log_seq, my_id(), &own_versionlink_path);
	if (unlikely(!own_versionlink)) {
		MARS_ERR_TO(rot->log_say, "cannot read my own versionlink '%s'\n", SAFE_STR(own_versionlink_path));
		goto done;
	}
	old_versionlink = get_versionlink(rot->parent_path, old_log_seq, old_host, &old_versionlink_path);
	if (unlikely(!old_versionlink)) {
		MARS_ERR_TO(rot->log_say, "cannot read old versionlink '%s'\n", SAFE_STR(old_versionlink_path));
		goto done;
	}
	if (!skip_new) {
		new_versionlink = get_versionlink(rot->parent_path, new_log_seq, new_host, &new_versionlink_path);
		if (unlikely(!new_versionlink)) {
			MARS_INF_TO(rot->log_say, "new versionlink '%s' does not yet exist, we must wait for it.\n", SAFE_STR(new_versionlink_path));
			goto done;
		}
	}

	// check: are the versionlinks correct?
	if (unlikely(strcmp(own_versionlink, old_versionlink))) {
		MARS_INF_TO(rot->log_say, "old logfile is not yet completeley transferred, own_versionlink '%s' -> '%s' != old_versionlink '%s' -> '%s'\n", own_versionlink_path, own_versionlink, old_versionlink_path, old_versionlink);
		goto done;
	}

	// check: did I fully apply my old logfile data?
	own_replaylink = get_replaylink(rot->parent_path, my_id(), &own_replaylink_path);
	if (unlikely(!own_replaylink)) {
		MARS_ERR_TO(rot->log_say, "cannot read my own replaylink '%s'\n", SAFE_STR(own_replaylink_path));
		goto done;
	}
	own_r_len    = skip_part(own_replaylink);
	own_v_offset = skip_part(own_versionlink);
	if (unlikely(!own_versionlink[own_v_offset++])) {
		MARS_ERR_TO(rot->log_say, "own version link '%s' -> '%s' is malformed\n", own_versionlink_path, own_versionlink);
		goto done;
	}
	own_v_len    = skip_part(own_versionlink + own_v_offset);
	if (unlikely(own_r_len != own_v_len ||
		     strncmp(own_replaylink, own_versionlink + own_v_offset, own_r_len))) {
		MARS_ERR_TO(rot->log_say, "internal problem: logfile name mismatch between '%s' and '%s'\n", own_replaylink, own_versionlink);
		goto done;
	}
	if (unlikely(!own_replaylink[own_r_len])) {
		MARS_ERR_TO(rot->log_say, "own replay link '%s' -> '%s' is malformed\n", own_replaylink_path, own_replaylink);
		goto done;
	}
	own_r_offset = own_r_len + 1;
	if (unlikely(!own_versionlink[own_v_len])) {
		MARS_ERR_TO(rot->log_say, "own version link '%s' -> '%s' is malformed\n", own_versionlink_path, own_versionlink);
		goto done;
	}
	own_v_offset += own_r_len + 1;
	own_r_len    = skip_part(own_replaylink  + own_r_offset);
	own_v_len    = skip_part(own_versionlink + own_v_offset);
	if (unlikely(own_r_len != own_v_len ||
		     strncmp(own_replaylink + own_r_offset, own_versionlink + own_v_offset, own_r_len))) {
		MARS_INF_TO(rot->log_say, "log replay is not yet finished: '%s' and '%s' are reporting different positions.\n", own_replaylink, own_versionlink);
		goto done;
	}

	// last check: is the new versionlink based on the old one?
	if (!skip_new) {
		len1  = skip_sect(own_versionlink);
		offs2 = skip_sect(new_versionlink);
		if (unlikely(!new_versionlink[offs2++])) {
			MARS_ERR_TO(rot->log_say, "new version link '%s' -> '%s' is malformed\n", new_versionlink_path, new_versionlink);
			goto done;
		}
		len2  = skip_sect(new_versionlink + offs2);
		if (unlikely(len1 != len2 ||
			     strncmp(own_versionlink, new_versionlink + offs2, len1))) {
			MARS_WRN_TO(rot->log_say, "VERSION MISMATCH old '%s' -> '%s' new '%s' -> '%s' ==(%d,%d) ===> check for SPLIT BRAIN!\n", own_versionlink_path, own_versionlink, new_versionlink_path, new_versionlink, len1, len2);
			goto done;
		}
	}

	// report success
	res = true;
	MARS_DBG("VERSION OK '%s' -> '%s'\n", own_versionlink_path, own_versionlink);

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
		write_info_links(rot);
		del_channel(rot->log_say);
		rot->log_say = NULL;
		brick_string_free(rot->copy_path);
		brick_string_free(rot->parent_path);
		rot->copy_path = NULL;
		rot->parent_path = NULL;
	}
}

/* This must be called once at every round of logfile checking.
 */
static
int make_log_init(void *buf, struct mars_dent *dent)
{
	struct mars_global *global = buf;
	struct mars_dent *parent = dent->d_parent;
	struct mars_brick *aio_brick;
	struct mars_brick *trans_brick;
	struct mars_rotate *rot = parent->d_private;
	struct mars_dent *replay_link;
	struct mars_dent *aio_dent;
	struct mars_output *output;
	const char *parent_path;
	const char *replay_path = NULL;
	const char *aio_path = NULL;
	const char *switch_path = NULL;
	int status = 0;

	if (!global->global_power.button) {
		goto done;
	}
	status = -EINVAL;
	CHECK_PTR(parent, done);
	parent_path = parent->d_path;
	CHECK_PTR(parent_path, done);

	if (!rot) {
		const char *copy_path;
		rot = brick_zmem_alloc(sizeof(struct mars_rotate));
		if (unlikely(!rot)) {
			MARS_ERR("cannot allocate rot structure\n");
			status = -ENOMEM;
			goto done;
		}
		spin_lock_init(&rot->inf_lock);		
		copy_path = path_make("%s/logfile-update", parent_path);
		if (unlikely(!copy_path)) {
			MARS_ERR("cannot create copy_path\n");
			brick_mem_free(rot);
			status = -ENOMEM;
			goto done;
		}
		rot->copy_path = copy_path;
		rot->global = global;
		parent->d_private = rot;
		parent->d_private_destruct = rot_destruct;
	}

	rot->replay_link = NULL;
	rot->aio_dent = NULL;
	rot->aio_brick = NULL;
	rot->first_log = NULL;
	rot->relevant_log = NULL;
	rot->relevant_brick = NULL;
	rot->next_relevant_log = NULL;
	rot->next_next_relevant_log = NULL;
	rot->prev_log = NULL;
	rot->next_log = NULL;
	rot->max_sequence = 0;
	rot->copy_next_is_available = 0;
	rot->has_error = false;

	if (dent->new_link)
		sscanf(dent->new_link, "%lld", &rot->dev_size);
	if (!rot->parent_path)
		rot->parent_path = brick_strdup(parent_path);

	if (unlikely(!rot->log_say)) {
		char *name = path_make("%s/logstatus-%s", parent_path, my_id());
		if (likely(name)) {
			rot->log_say = make_channel(name, false);
			brick_string_free(name);
		}
	}
	
	write_info_links(rot);

	mars_remaining_space(parent_path, &rot->total_space, &rot->remaining_space);

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
		if (rot->todo_primary) { // try to create an empty logfile
			_create_new_logfile(aio_path);
		}
		goto done;
	}
	rot->aio_dent = aio_dent;

	/* Fetch / make the AIO brick instance
	 */
	aio_brick =
		make_brick_all(global,
			       aio_dent,
			       false,
			       _set_aio_params,
			       NULL,
			       10 * HZ,
			       aio_path,
			       (const struct generic_brick_type*)&aio_brick_type,
			       (const struct generic_brick_type*[]){},
			       NULL,
			       1, // start always
			       "%s",
			       (const char *[]){},
			       0,
			       aio_path);
	if (!aio_brick) {
		MARS_ERR("cannot access '%s'\n", aio_path);
		status = -EIO;
		goto done;
	}
	rot->aio_brick = (void*)aio_brick;

	/* Fetch the actual logfile size
	 */
	output = aio_brick->outputs[0];
	status = output->ops->mars_get_info(output, &rot->aio_info);
	if (status < 0) {
		MARS_ERR("cannot get info on '%s'\n", aio_path);
		goto done;
	}
	MARS_DBG("logfile '%s' size = %lld\n", aio_path, rot->aio_info.current_size);

	if (rot->is_primary &&
	    global_logrot_auto > 0 &&
	    unlikely(rot->aio_info.current_size >= (loff_t)global_logrot_auto * 1024 * 1024 * 1024)) {
		char *new_path = path_make("%s/log-%09d-%s", parent_path, aio_dent->d_serial + 1, my_id());
		if (likely(new_path && !mars_find_dent(global, new_path))) {
			MARS_INF("old logfile size = %lld, creating new logfile '%s'\n", rot->aio_info.current_size, new_path);
			_create_new_logfile(new_path);
		}
		brick_string_free(new_path);
	}

	// check whether attach is allowed
	switch_path = path_make("%s/todo-%s/attach", parent_path, my_id());

	/* Fetch / make the transaction logger.
	 * We deliberately "forget" to connect the log input here.
	 * Will be carried out later in make_log_step().
	 * The final switch-on will be started in make_log_finalize().
	 */
	trans_brick =
		make_brick_all(global,
			       dent,
			       false,
			       _set_trans_params,
			       NULL,
			       0,
			       aio_path,
			       (const struct generic_brick_type*)&trans_logger_brick_type,
			       (const struct generic_brick_type*[]){NULL},
			       switch_path,
			       0, // let switch decide
			       "%s/logger", 
			       (const char *[]){"%s/data-%s"},
			       1,
			       parent_path,
			       parent_path,
			       my_id());
	status = -ENOENT;
	if (!trans_brick) {
		goto done;
	}
	rot->trans_brick = (void*)trans_brick;
	rot->trans_brick->replay_limiter = &rot->replay_limiter;
	/* For safety, default is to try an (unnecessary) replay in case
	 * something goes wrong later.
	 */
	rot->replay_mode = true;

	status = 0;

done:
	brick_string_free(aio_path);
	brick_string_free(replay_path);
	brick_string_free(switch_path);
	return status;
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
	if (prev_log && prev_log->d_serial + 1 != dent->d_serial) {
		MARS_WRN_TO(rot->log_say, "transaction logs are not consecutive at '%s' (%d ~> %d)\n", dent->d_path, prev_log->d_serial, dent->d_serial);
		// allow the primary to create a hole in the logfile sequence numbers
		if (!rot->todo_primary || prev_log->d_serial + 2 != dent->d_serial) {
			status = -EINVAL;
			goto done;
		}
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
			rot->next_relevant_log = dent;
		} else if (!rot->next_next_relevant_log) {
			rot->next_next_relevant_log = dent;
		}
		MARS_DBG("next_relevant_log = %p next_next_relevant_log = %p\n", rot->next_relevant_log, rot->next_next_relevant_log);
		goto ok;
	}

	/* Preconditions
	 */
	if (!rot->replay_link || !rot->aio_dent || !rot->aio_brick) {
		MARS_DBG("nothing to do on '%s'\n", dent->d_path);
		goto ok;
	}

	/* Remember the relevant log.
	 */
	if (rot->aio_dent->d_serial == dent->d_serial) {
		rot->relevant_serial = dent->d_serial;
		rot->relevant_log = dent;
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

	*newpos = rot->aio_info.current_size;

	if (unlikely(rot->aio_info.current_size < *oldpos_start)) {
		MARS_ERR_TO(rot->log_say, "oops, bad replay position attempted at logfile '%s' (file length %lld should never be smaller than requested position %lld, is your filesystem corrupted?) => please repair this by hand\n", rot->aio_dent->d_path, rot->aio_info.current_size, *oldpos_start);
		status = -EBADF;
		goto done;
	}

	status = 0;
	if (rot->aio_info.current_size > *oldpos_start) {
		MARS_INF_TO(rot->log_say, "transaction log replay is necessary on '%s' from %lld to %lld (dirty region ends at %lld)\n", rot->aio_dent->d_path, *oldpos_start, rot->aio_info.current_size, *oldpos_end);
		status = 2;
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
	return status;
}


static
int _make_logging_status(struct mars_rotate *rot)
{
	struct mars_dent *dent = rot->relevant_log;
	struct mars_dent *parent;
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
		if (!trans_brick->power.button && !trans_brick->power.led_on && trans_brick->power.led_off) {
			if (rot->next_relevant_log) {
				bool skip_new = !rot->next_next_relevant_log && rot->todo_primary;
				MARS_DBG("check switchover from '%s' to '%s' (size = %lld, next_next = %p, skip_new = %d)\n", dent->d_path, rot->next_relevant_log->d_path, rot->next_relevant_log->new_stat.size, rot->next_next_relevant_log, skip_new);
				if (is_switchover_possible(rot, dent->d_path, rot->next_relevant_log->d_path, skip_new)) {
					MARS_INF_TO(rot->log_say, "start switchover from transaction log '%s' to '%s'\n", dent->d_path, rot->next_relevant_log->d_path);
					_make_new_replaylink(rot, rot->next_relevant_log->d_rest, rot->next_relevant_log->d_serial, rot->next_relevant_log->new_stat.size);
				}
			} else if (rot->todo_primary) {
				if (dent->d_serial > log_nr)
					log_nr = dent->d_serial;
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
void _init_trans_input(struct trans_logger_input *trans_input, struct mars_dent *log_dent, struct mars_rotate *rot)
{
	if (unlikely(trans_input->connect || trans_input->is_operating)) {
		MARS_ERR("this should not happen\n");
		return;
	}

	memset(&trans_input->inf, 0, sizeof(trans_input->inf));

	strncpy(trans_input->inf.inf_host, log_dent->d_rest, sizeof(trans_input->inf.inf_host));
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
		return -EEXIST;
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
			MARS_INF("cleanup old transaction log (%d -> %d)\n", old_nr, log_nr);
			status = generic_disconnect((void*)trans_input);
			if (unlikely(status < 0)) {
				MARS_ERR("disconnect failed\n");
			} else {
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
	    (rot->next_relevant_log->d_serial == trans_brick->inputs[log_nr]->inf.inf_sequence + 1 ||
	     trans_brick->cease_logging) &&
	    (next_nr = _get_free_input(trans_brick)) >= 0) {
		struct trans_logger_input *trans_input;
		int status;
		
		MARS_DBG("start switchover %d -> %d\n", old_nr, next_nr);
		
		rot->next_relevant_brick =
			make_brick_all(rot->global,
				       rot->next_relevant_log,
				       false,
				       _set_aio_params,
				       NULL,
				       10 * HZ,
				       rot->next_relevant_log->d_path,
				       (const struct generic_brick_type*)&aio_brick_type,
				       (const struct generic_brick_type*[]){},
				       NULL,
				       0, // let switch decide
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

		_init_trans_input(trans_input, rot->next_relevant_log, rot);

		status = generic_connect((void*)trans_input, (void*)rot->next_relevant_brick->outputs[0]);
		if (unlikely(status < 0)) {
			MARS_ERR_TO(rot->log_say, "internal connect failed\n");
			goto done;
		}
		trans_brick->new_input_nr = next_nr;
		MARS_INF_TO(rot->log_say, "started logrotate switchover from '%s' to '%s'\n", rot->relevant_log->d_path, rot->next_relevant_log->d_path);
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
			       false,
			       _set_aio_params,
			       NULL,
			       10 * HZ,
			       rot->relevant_log->d_path,
			       (const struct generic_brick_type*)&aio_brick_type,
			       (const struct generic_brick_type*[]){},
			       NULL,
			       1, // start always
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
	_init_trans_input(trans_input, rot->relevant_log, rot);

	/* Connect to new transaction log
	 */
	status = generic_connect((void*)trans_input, (void*)rot->relevant_brick->outputs[0]);
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
int _stop_trans(struct mars_rotate *rot, const char *parent_path)
{
	struct trans_logger_brick *trans_brick = rot->trans_brick;
	int status = 0;

	if (!trans_brick) {
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
		for (i = TL_INPUT_LOG1; i <= TL_INPUT_LOG2; i++) {
			struct trans_logger_input *trans_input;
			trans_input = trans_brick->inputs[i];
			if (trans_input && !trans_input->is_operating) {
				if (trans_input->connect)
					(void)generic_disconnect((void*)trans_input);
			}
		}
	}

done:
	return status;
}

static
int make_log_finalize(struct mars_global *global, struct mars_dent *dent)
{
	struct mars_dent *parent = dent->d_parent;
	struct mars_rotate *rot;
	struct trans_logger_brick *trans_brick;
	struct copy_brick *copy_brick;
	int status = -EINVAL;

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
		//brick_say_logging = 0;
		MARS_ERR_TO(rot->log_say, "DISK SPACE IS EXTREMELY LOW on %s\n", rot->parent_path);
		if (rot->todo_primary || rot->is_primary) {
			trans_brick->cease_logging = true;
			rot->inf_prev_sequence = 0; // disable checking
		}
	} else if ((trans_brick->cease_logging | trans_brick->stopped_logging) && rot->created_hole && !IS_EXHAUSTED()) {
		if (!trans_logger_resume) {
			MARS_INF_TO(rot->log_say, "emergency mode on %s could be turned off now, but /proc/sys/mars/logger_resume inhibits it.\n", rot->parent_path);
		} else {
			trans_brick->cease_logging = false;
			rot->created_hole = false;
			MARS_INF_TO(rot->log_say, "emergency mode on %s will be turned off again\n", rot->parent_path);
		}
	}
	if (trans_brick->cease_logging | trans_brick->stopped_logging) {
		MARS_ERR_TO(rot->log_say, "EMERGENCY MODE on %s: stopped transaction logging, and created a hole in the logfile sequence nubers.\n", rot->parent_path);
		/* Create a hole in the sequence of logfile numbers.
		 * The secondaries will later stumble over it.
		 */
		if (trans_brick->inputs[trans_brick->log_input_nr]->inf.inf_max_pos > 0) {
			char *new_path = path_make("%s/log-%09d-%s", rot->parent_path, rot->max_sequence + 2, my_id());
			if (likely(new_path && !mars_find_dent(global, new_path))) {
				MARS_INF_TO(rot->log_say, "EMERGENCY: creating new logfile '%s'\n", new_path);
				_create_new_logfile(new_path);
				rot->created_hole = true;
			}
			brick_string_free(new_path);
		}
	}

	// check whether some copy has finished
	copy_brick = (struct copy_brick*)mars_find_brick(global, &copy_brick_type, rot->copy_path);
	MARS_DBG("copy_path = '%s' copy_brick = %p\n", rot->copy_path, copy_brick);
	if (copy_brick &&
	    (copy_brick->power.led_off ||
	     !global->global_power.button ||
	     (copy_brick->copy_last == copy_brick->copy_end &&
	      rot->copy_next_is_available > 0))) {
		status = mars_kill_brick((void*)copy_brick);
		if (status < 0) {
			MARS_ERR("could not kill copy_brick, status = %d\n", status);
			goto done;
		}
		copy_brick = NULL;
		mars_trigger();
	}
	rot->copy_brick = copy_brick;
	if (!copy_brick) {
		rot->copy_serial = 0;
	}

	if (IS_EMERGENCY_PRIMARY() || (!rot->todo_primary && IS_EMERGENCY_SECONDARY())) {
		MARS_WRN_TO(rot->log_say, "EMERGENCY: the space on /mars/ is very low. Expect some problems!\n");
		if (rot->first_log && rot->first_log != rot->relevant_log) {
			MARS_WRN_TO(rot->log_say, "EMERGENCY: ruthlessly freeing old logfile '%s', don't cry on any ramifications.\n", rot->first_log->d_path);
			mars_unlink(rot->first_log->d_path);
			rot->first_log->d_killme = true;
			// give it a chance to cease deleting next time
			compute_emergency_mode();
		}
	} else if (IS_EXHAUSTED()) {
		MARS_WRN_TO(rot->log_say, "EMERGENCY: the space on /mars/ is becoming low. Stopping all fetches of logfiles for secondary resources.\n");
	}

	if (trans_brick->replay_mode) {
		if (trans_brick->replay_code > 0) {
			MARS_INF_TO(rot->log_say, "logfile apply ended successfully\n");
		} else if (trans_brick->replay_code < 0) {
			MARS_ERR_TO(rot->log_say, "logfile apply stopped with error = %d\n", trans_brick->replay_code);
		}
	}

	/* Stopping is also possible in case of errors
	 */
	if (trans_brick->power.button && trans_brick->power.led_on && !trans_brick->power.led_off) {
		bool do_stop = true;
		if (trans_brick->replay_mode) {
			do_stop = trans_brick->replay_code != 0 ||
				!global->global_power.button ||
				!_check_allow(global, parent, "allow-replay");
		} else {
			do_stop = !rot->is_primary;
		}

		MARS_DBG("replay_mode = %d replay_code = %d is_primary = %d do_stop = %d\n", trans_brick->replay_mode, trans_brick->replay_code, rot->is_primary, (int)do_stop);

		if (do_stop) {
			status = _stop_trans(rot, parent->d_path);
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

		do_start = (!rot->replay_mode ||
			    (rot->start_pos != rot->end_pos &&
			     _check_allow(global, parent, "allow-replay")));

		if (do_start && rot->forbid_replay) {
			MARS_INF("cannot start replay because sync wants to start\n");
			do_start = false;
		}

		if (do_start && rot->sync_brick && !rot->sync_brick->power.led_off) {
			MARS_INF("cannot start replay because sync is running\n");
			do_start = false;
		}

		MARS_DBG("rot->replay_mode = %d rot->start_pos = %lld rot->end_pos = %lld | do_start = %d\n", rot->replay_mode, rot->start_pos, rot->end_pos, do_start);

		if (do_start) {
			status = _start_trans(rot);
		}
	}

done:
	if (rot->trans_brick)
		_show_rate(rot, &rot->replay_limiter, rot->trans_brick->power.led_on, "replay_rate");
	if (rot->copy_brick)
		_show_rate(rot, &rot->file_limiter, rot->copy_brick->power.led_on, "file_rate");
	if (rot->sync_brick)
		_show_rate(rot, &rot->sync_limiter, rot->sync_brick->power.led_on, "sync_rate");
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

	rot->todo_primary =
		global->global_power.button && dent->new_link && !strcmp(dent->new_link, my_id());
	rot->is_primary =
		rot->if_brick && !rot->if_brick->power.led_off;
	MARS_DBG("todo_primary = %d is_primary = %d\n", rot->todo_primary, rot->is_primary);
	status = 0;

done:
	return status;
}

static
int make_bio(void *buf, struct mars_dent *dent)
{
	struct mars_global *global = buf;
	struct mars_brick *brick;
	int status = 0;

	if (!global->global_power.button) {
		goto done;
	}
	brick = mars_find_brick(global, NULL, dent->d_path);
	if (brick) {
		goto check;
	}
	brick =
		make_brick_all(global,
			       dent,
			       false,
			       _set_bio_params,
			       NULL,
			       10 * HZ,
			       dent->d_path,
			       (const struct generic_brick_type*)&bio_brick_type,
			       (const struct generic_brick_type*[]){},
			       NULL,
			       1, // start always
			       dent->d_path,
			       (const char *[]){},
			       0);
	if (unlikely(!brick)) {
		status = -ENXIO;
		goto done;
	}
	brick->outputs[0]->output_name = dent->d_path;
	status = mars_power_button((void*)brick, true, false);
	if (status < 0) {
		kill_any(buf, dent);
		goto done;
	}

check:
	/* Report the actual size of the device.
	 * It may be larger than the global size.
	 */
	if (brick && brick->power.led_on && dent->d_parent) {
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
			(void)mars_symlink(src, dst, NULL, 0);
		}
		brick_string_free(src);
		brick_string_free(dst);
	}

 done:
	return status;
}

static int make_replay(void *buf, struct mars_dent *dent)
{
	struct mars_global *global = buf;
	struct mars_dent *parent = dent->d_parent;
	int status = 0;

	if (!global->global_power.button || !parent || !dent->new_link) {
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
int make_dev(void *buf, struct mars_dent *dent)
{
	struct mars_global *global = buf;
	struct mars_dent *parent = dent->d_parent;
	struct mars_rotate *rot = NULL;
	struct mars_brick *dev_brick;
	struct if_brick *_dev_brick;
	bool switch_on;
	int status = 0;

	if (!parent || !dent->new_link) {
		MARS_ERR("nothing to do\n");
		return -EINVAL;
	}
	rot = parent->d_private;
	if (!rot) {
		MARS_DBG("nothing to do\n");
		goto done;
	}
	if (!rot->trans_brick) {
		MARS_DBG("transaction logger does not exist\n");
		goto done;
	}
	if (!global->global_power.button &&
	   (!rot->if_brick || rot->if_brick->power.led_off)) {
		MARS_DBG("nothing to do\n");
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
		(rot->if_brick && atomic_read(&rot->if_brick->inputs[0]->open_count) > 0) ||
		(rot->todo_primary &&
		 !rot->trans_brick->replay_mode &&
		 rot->trans_brick->power.led_on);
	if (!global->global_power.button) {
		switch_on = false;
	}

	dev_brick =
		make_brick_all(global,
			       dent,
			       false,
			       _set_if_params,
			       rot,
			       10 * HZ,
			       dent->d_argv[0],
			       (const struct generic_brick_type*)&if_brick_type,
			       (const struct generic_brick_type*[]){(const struct generic_brick_type*)&trans_logger_brick_type},
			       NULL,
			       switch_on ? 1 : -1,
			       "%s/device-%s", 
			       (const char *[]){"%s/logger"},
			       1,
			       parent->d_path,
			       dent->d_argv[0],
			       parent->d_path);
	rot->if_brick = (void*)dev_brick;
	if (!dev_brick) {
		MARS_DBG("device not shown\n");
		goto done;
	}
	dev_brick->show_status = _show_brick_status;
	_dev_brick = (void*)dev_brick;
#if 0
	if (_dev_brick->has_closed) {
		_dev_brick->has_closed = false;
		MARS_INF("rotating logfile for '%s'\n", parent->d_name);
		status = mars_power_button((void*)rot->trans_brick, false);
		rot->relevant_log = NULL;
	}
#endif

done:
	_show_primary(rot, parent);
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
	bool do_dealloc = false;

	if (!global->global_power.button || !dent->d_parent || !dent->new_link) {
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
	brick = 
		make_brick_all(global,
			       dent,
			       false,
			       _set_bio_params,
			       NULL,
			       10 * HZ,
			       src_path,
			       (const struct generic_brick_type*)&bio_brick_type,
			       (const struct generic_brick_type*[]){},
			       NULL,
			       0,
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
			       false,
			       _set_if_params,
			       NULL,
			       10 * HZ,
			       dent->d_argv[1],
			       (const struct generic_brick_type*)&if_brick_type,
			       (const struct generic_brick_type*[]){NULL},
			       NULL,
			       0,
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

	if (!global->global_power.button || !dent->d_parent || !dent->new_link) {
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

	status = __make_copy(global, dent, switch_path, copy_path, dent->d_parent->d_path, (const char**)dent->d_argv, -1, false, true, NULL);

done:
	MARS_DBG("status = %d\n", status);
	if (copy_path)
		brick_string_free(copy_path);
	if (switch_path)
		brick_string_free(switch_path);
	return status;
}

static int make_sync(void *buf, struct mars_dent *dent)
{
	struct mars_global *global = buf;
	struct mars_rotate *rot;
	loff_t start_pos = 0;
	loff_t end_pos = 0;
	struct mars_dent *size_dent;
	struct mars_dent *connect_dent;
	char *peer;
	struct copy_brick *copy = NULL;
	char *tmp = NULL;
	const char *switch_path = NULL;
	const char *copy_path = NULL;
	const char *src = NULL;
	const char *dst = NULL;
	bool do_start = true;
	int status;

	if (!global->global_power.button || !dent->d_parent || !dent->new_link) {
		return 0;
	}

	/* Analyze replay position
	 */
	status = sscanf(dent->new_link, "%lld", &start_pos);
	if (status != 1) {
		MARS_ERR("bad syncstatus symlink syntax '%s' (%s)\n", dent->new_link, dent->d_path);
		status = -EINVAL;
		goto done;
	}

	rot = dent->d_parent->d_private;
	if (rot) {
		rot->forbid_replay = false;
		rot->allow_update = true;
		rot->syncstatus_dent = dent;
	}

	/* Sync necessary?
	 */
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
	if (start_pos == end_pos) {
		MARS_DBG("no data sync necessary, size = %lld\n", start_pos);
		do_start = false;
	}
	brick_string_free(tmp);

	/* Determine peer
	 */
	tmp = path_make("%s/connect-%s", dent->d_parent->d_path, my_id());
	status = -ENOMEM;
	if (unlikely(!tmp))
		goto done;
	connect_dent = (void*)mars_find_dent(global, tmp);
	if (!connect_dent || !connect_dent->new_link) {
		MARS_WRN("cannot determine peer, symlink '%s' is missing => assuming that I am STANDALONE\n", tmp);
		status = 0;
		goto done;
	}
	peer = connect_dent->new_link;

	/* Disallow contemporary sync & logfile_apply
	 */
	if (do_start &&
	    rot->trans_brick &&
	    !rot->trans_brick->power.led_off) {
		MARS_INF("cannot start sync because logger is working\n");
		do_start = false;
	}

	/* Disallow overwrite of newer data
	 */
	if (do_start && compare_replaylinks(rot, peer, my_id()) < 0) {
		MARS_INF("cannot start sync because my data is newer than the remote one at '%s'!\n", peer);
		do_start = false;
		rot->forbid_replay = true;
	}

	/* Flip between replay and sync
	 */
	if (do_start && rot->replay_mode && rot->end_pos > rot->start_pos &&
	    mars_sync_flip_interval >= 8) {
		if (!rot->flip_start) {
			rot->flip_start = jiffies;
		} else if ((long long)jiffies - rot->flip_start > CONFIG_MARS_SYNC_FLIP_INTERVAL * HZ) {
			do_start = false;
			rot->flip_start = jiffies + mars_sync_flip_interval * HZ;
		}
	} else {
		rot->flip_start = 0;
	}

	/* Start copy
	 */
#ifdef CONFIG_MARS_SEPARATE_PORTS
	src = path_make("data-%s@%s:%d", peer, peer, mars_net_default_port + 2);
#else
	src = path_make("data-%s@%s", peer, peer);
#endif
	dst = path_make("data-%s", my_id());
	copy_path = backskip_replace(dent->d_path, '/', true, "/copy-");

	// check whether connection is allowed
	switch_path = path_make("%s/todo-%s/sync", dent->d_parent->d_path, my_id());

	status = -ENOMEM;
	if (unlikely(!src || !dst || !copy_path || !switch_path))
		goto done;

	MARS_DBG("initial sync '%s' => '%s' do_start = %d\n", src, dst, do_start);

	{
		const char *argv[2] = { src, dst };
		status = __make_copy(global, dent, do_start ? switch_path : "", copy_path, dent->d_parent->d_path, argv, start_pos, mars_fast_fullsync > 0, true, &copy);
		if (copy)
			copy->copy_limiter = &rot->sync_limiter;
		rot->sync_brick = copy;
	}

	/* Update syncstatus symlink
	 */
	if (status >= 0 && copy &&
	   ((copy->power.button && copy->power.led_on) ||
	    (copy->copy_last == copy->copy_end && copy->copy_end > 0))) {
		brick_string_free(src);
		brick_string_free(dst);
		src = path_make("%lld", copy->copy_last);
		dst = path_make("%s/syncstatus-%s", dent->d_parent->d_path, my_id());
		status = -ENOMEM;
		if (unlikely(!src || !dst))
			goto done;
		status = mars_symlink(src, dst, NULL, 0);
		brick_string_free(src);
		brick_string_free(dst);
		src = path_make("%lld,%lld", copy->verify_ok_count, copy->verify_error_count);
		dst = path_make("%s/verifystatus-%s", dent->d_parent->d_path, my_id());
		status = -ENOMEM;
		if (unlikely(!src || !dst))
			goto done;
		status = mars_symlink(src, dst, NULL, 0);
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

static int prepare_delete(void *buf, struct mars_dent *dent)
{
	struct mars_global *global = buf;
	struct mars_dent *target;
	struct mars_dent *response;
	const char *response_path = NULL;
	struct mars_brick *brick;
	int max_serial = 0;

	if (!global || !dent || !dent->new_link || !dent->d_path) {
		goto done;
	}

	brick = mars_find_brick(global, NULL, dent->new_link);
	if (brick && unlikely(brick->nr_outputs > 0 && brick->outputs[0] && brick->outputs[0]->nr_connected)) {
		MARS_WRN("target '%s' cannot be deleted, its brick '%s' in use\n", dent->new_link, SAFE_STR(brick->brick_name));
		goto done;
	}

	target = _mars_find_dent(global, dent->new_link);
	if (target) {
		mars_unlink(dent->new_link);
		target->d_killme = true;
		MARS_DBG("target '%s' deleted and marked for removal\n", dent->new_link);
	} else {
		MARS_DBG("target '%s' does no longer exist\n", dent->new_link);
		if (dent->d_serial < global->deleted_border) {
			MARS_DBG("removing deletion symlink '%s'\n", dent->d_path);
			dent->d_killme = true;
			mars_unlink(dent->d_path);
		}
	}
	
	response_path = path_make("/mars/todo-global/deleted-%s", my_id());
	if (!response_path) {
		MARS_ERR("cannot build response path for '%s'\n", dent->new_link);
		goto done;
	}
	response = _mars_find_dent(global, response_path);
	if (response && response->new_link) {
		sscanf(response->new_link, "%d", &max_serial);
	}
	if (dent->d_serial > max_serial) {
		char response_val[16];
		max_serial = dent->d_serial;
		snprintf(response_val, sizeof(response_val), "%09d", max_serial);
		mars_symlink(response_val, response_path, NULL, 0);
	}

 done:
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

	/* Compute the minimum of the deletion progress among
	 * the resource members.
	 */
	if (serial < global->deleted_min || !global->deleted_min)
		global->deleted_min = serial;

	
 done:
	return 0;
}

///////////////////////////////////////////////////////////////////////

// the order is important!
enum {
	// root element: this must have index 0
	CL_ROOT,
	// global userspace
	CL_GLOBAL_USERSPACE,
	CL_GLOBAL_USERSPACE_ITEMS,
	// global todos
	CL_GLOBAL_TODO,
	CL_GLOBAL_TODO_DELETE,
	CL_GLOBAL_TODO_DELETED,
	// replacement for DNS in kernelspace
	CL_IPS,
	CL_PEERS,
	CL_ALIVE,
	CL_TREE,
	CL_EMERGENCY,
	CL_REST_SPACE,
	// resource definitions
	CL_RESOURCE,
	CL_RESOURCE_USERSPACE,
	CL_RESOURCE_USERSPACE_ITEMS,
	CL_DEFAULTS0,
	CL_DEFAULTS,
	CL_DEFAULTS_ITEMS0,
	CL_DEFAULTS_ITEMS,
	CL_TODO,
	CL_TODO_ITEMS,
	CL_ACTUAL,
	CL_ACTUAL_ITEMS,
	CL_CONNECT,
	CL_DATA,
	CL_SIZE,
	CL_ACTSIZE,
	CL_PRIMARY,
	CL__FILE,
	CL_SYNC,
	CL_VERIF,
	CL__COPY,
	CL__DIRECT,
	CL_VERSION,
	CL_LOG,
	CL_REPLAYSTATUS,
	CL_DEVICE,
};

/* Please keep the order the same as in the enum.
 */
static const struct light_class light_classes[] = {
	/* Placeholder for root node /mars/
	 */
	[CL_ROOT] = {
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
		.cl_type = 'l',
		.cl_father = CL_GLOBAL_USERSPACE,
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
	/* Indicate aliveness of all cluster paritcipants
	 * by the timestamp of this link.
	 */
	[CL_ALIVE] = {
		.cl_name = "alive-",
		.cl_len = 6,
		.cl_type = 'l',
		.cl_father = CL_ROOT,
	},
	/* Show version indication for symlink tree.
	 */
	[CL_TREE] = {
		.cl_name = "tree-",
		.cl_len = 5,
		.cl_type = 'l',
		.cl_father = CL_ROOT,
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
		.cl_type = 'l',
		.cl_father = CL_RESOURCE_USERSPACE,
	},

	/* Subdirectory for defaults...
	 */
	[CL_DEFAULTS0] = {
		.cl_name = "defaults",
		.cl_len = 8,
		.cl_type = 'd',
		.cl_hostcontext = false,
		.cl_father = CL_RESOURCE,
	},
	[CL_DEFAULTS] = {
		.cl_name = "defaults-",
		.cl_len = 9,
		.cl_type = 'd',
		.cl_hostcontext = false,
		.cl_father = CL_RESOURCE,
	},
	/* ... and its contents
	 */
	[CL_DEFAULTS_ITEMS0] = {
		.cl_name = "",
		.cl_len = 0, // catch any
		.cl_type = 'l',
		.cl_father = CL_DEFAULTS0,
	},
	[CL_DEFAULTS_ITEMS] = {
		.cl_name = "",
		.cl_len = 0, // catch any
		.cl_type = 'l',
		.cl_father = CL_DEFAULTS,
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


	/* Symlink indicating the current peer
	 */
	[CL_CONNECT] = {
		.cl_name = "connect-",
		.cl_len = 8,
		.cl_type = 'l',
		.cl_hostcontext = false, // not used here
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
		.cl_hostcontext = true,
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
	/* Dito for each individual size
	 */
	[CL_ACTSIZE] = {
		.cl_name = "actsize-",
		.cl_len = 8,
		.cl_type = 'l',
		.cl_hostcontext = true,
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
	{}
};

/* Helper routine to pre-determine the relevance of a name from the filesystem.
 */
int light_checker(struct mars_dent *parent, const char *_name, int namlen, unsigned int d_type, int *prefix, int *serial, bool *use_channel)
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

	//MARS_DBG("trying '%s' '%s'\n", path, name);
	for (class = CL_ROOT + 1; ; class++) {
		const struct light_class *test = &light_classes[class];
		int len = test->cl_len;
		if (!test->cl_name) { // end of table
			break;
		}

		//MARS_DBG("   testing class '%s'\n", test->cl_name);

#ifdef MARS_DEBUGGING
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

		//MARS_DBG("path '%s/%s' matches class %d '%s'\n", path, name, class, test->cl_name);

		// check special contexts
		if (test->cl_serial) {
			int plus = 0;
			int count;
			count = sscanf(name+len, "%d%n", serial, &plus);
			if (count < 1) {
				//MARS_DBG("'%s' serial number mismatch at '%s'\n", name, name+len);
				continue;
			}
			//MARS_DBG("'%s' serial number = %d\n", name, *serial);
			len += plus;
			if (name[len] == '-')
				len++;
		}
		if (prefix)
			*prefix = len;
		if (test->cl_hostcontext) {
			if (memcmp(name+len, my_id(), namlen-len)) {
				//MARS_DBG("context mismatch '%s' at '%s'\n", name, name+len);
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
 * from the light_classes[] table.
 */
static int light_worker(struct mars_global *global, struct mars_dent *dent, bool prepare, bool direction)
{
	light_worker_fn worker;
	int class = dent->d_class;

	if (class < 0 || class >= sizeof(light_classes)/sizeof(struct light_class)) {
		MARS_ERR_ONCE(dent, "bad internal class %d of '%s'\n", class, dent->d_path);
		return -EINVAL;
	}
	switch (light_classes[class].cl_type) {
	case 'd':
		if (!S_ISDIR(dent->new_stat.mode)) {
			MARS_ERR_ONCE(dent, "'%s' should be a directory, but is something else\n", dent->d_path);
			return -EINVAL;
		}
		break;
	case 'f':
		if (!S_ISREG(dent->new_stat.mode)) {
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
	}
	if (likely(class > CL_ROOT)) {
		int father = light_classes[class].cl_father;
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
		worker = light_classes[class].cl_prepare;
	} else if (direction) {
		worker = light_classes[class].cl_backward;
	} else {
		worker = light_classes[class].cl_forward;
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

static struct mars_global _global = {
	.dent_anchor = LIST_HEAD_INIT(_global.dent_anchor),
	.brick_anchor = LIST_HEAD_INIT(_global.brick_anchor),
	.global_power = {
		.button = true,
	},
	.dent_mutex = __RWSEM_INITIALIZER(_global.dent_mutex),
	.brick_mutex = __RWSEM_INITIALIZER(_global.brick_mutex),
	.main_event = __WAIT_QUEUE_HEAD_INITIALIZER(_global.main_event),
};

static int light_thread(void *data)
{
	long long last_rollover = jiffies;
	char *id = my_id();
	int status = 0;
	mars_global = &_global;

	if (!id || strlen(id) < 2) {
		MARS_ERR("invalid hostname\n");
		status = -EFAULT;
		goto done;
	}	

	MARS_INF("-------- starting as host '%s' ----------\n", id);

        while (_global.global_power.button || !list_empty(&_global.brick_anchor)) {
		int status;

		MARS_DBG("-------- NEW ROUND %d ---------\n", atomic_read(&server_handler_count));

		if (mars_mem_percent < 0)
			mars_mem_percent = 0;
		if (mars_mem_percent > 70)
			mars_mem_percent = 70;
		brick_global_memlimit = (long long)brick_global_memavail * mars_mem_percent / 100;

		brick_msleep(100);

		if (brick_thread_should_stop()) {
			_global.global_power.button = false;
			mars_net_is_alive = false;
		}

		_make_alivelink("alive", _global.global_power.button ? 1 : 0);
		_make_alivelink_str("tree", SYMLINK_TREE_VERSION);

		compute_emergency_mode();

		MARS_DBG("-------- start worker ---------\n");
		_global.deleted_min = 0;
		status = mars_dent_work(&_global, "/mars", sizeof(struct mars_dent), light_checker, light_worker, &_global, 3);
		_global.deleted_border = _global.deleted_min;
		MARS_DBG("-------- worker deleted_min = %d status = %d\n", _global.deleted_min, status);

		if (!_global.global_power.button) {
			status = mars_kill_brick_when_possible(&_global, &_global.brick_anchor, false, (void*)&copy_brick_type, false);
			MARS_DBG("kill copy bricks (when possible) = %d\n", status);
		}
		status = mars_kill_brick_when_possible(&_global, &_global.brick_anchor, false, (void*)&client_brick_type, false);
		MARS_DBG("kill client bricks (when possible) = %d\n", status);
		status = mars_kill_brick_when_possible(&_global, &_global.brick_anchor, false, (void*)&aio_brick_type, false);
		MARS_DBG("kill aio    bricks (when possible) = %d\n", status);
		status = mars_kill_brick_when_possible(&_global, &_global.brick_anchor, false, (void*)&sio_brick_type, false);
		MARS_DBG("kill sio    bricks (when possible) = %d\n", status);

		if ((long long)jiffies + mars_rollover_interval * HZ >= last_rollover) {
			last_rollover = jiffies;
			rollover_all();
		}

		_show_status_all(&_global);
		show_statistics(&_global, "main");

		MARS_DBG("ban_count = %d ban_renew_count = %d\n", mars_global_ban.ban_count, mars_global_ban.ban_renew_count);

		brick_msleep(500);

		wait_event_interruptible_timeout(_global.main_event, _global.main_trigger, mars_scan_interval * HZ);

		_global.main_trigger = false;
	}

done:
	MARS_INF("-------- cleaning up ----------\n");
	mars_remote_trigger();
	brick_msleep(2000);

	mars_free_dent_all(&_global, &_global.dent_anchor);
	mars_kill_brick_all(&_global, &_global.brick_anchor, false);

	_show_status_all(&_global);
	show_statistics(&_global, "main");

	mars_global = NULL;

	MARS_INF("-------- done status = %d ----------\n", status);
	//cleanup_mm();
	return status;
}

static struct mem_reservation global_reserve = {
	.amount = {
		[5] = 64,
	},
};

#ifdef CONFIG_MARS_HAVE_BIGMODULE
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

#endif

void (*_mars_remote_trigger)(void);
EXPORT_SYMBOL_GPL(_mars_remote_trigger);

static void __exit exit_light(void)
{
	MARS_DBG("====================== stopping everything...\n");
	// TODO: make this thread-safe.
	if (main_thread) {
		MARS_DBG("=== stopping light thread...\n");
		mars_trigger();
		MARS_INF("stopping main thread...\n");
		brick_thread_stop(main_thread);
	}

	_mars_remote_trigger = NULL;
	brick_allow_freelist = false;

#ifdef CONFIG_MARS_HAVE_BIGMODULE
	while (exit_fn_nr > 0) {
		MARS_DBG("=== stopping module %s ...\n", exit_names[exit_fn_nr - 1]);
		exit_fn[--exit_fn_nr]();
	}
#endif
	MARS_DBG("====================== stopped everything.\n");
	exit_say();
	printk(KERN_INFO "stopped MARS\n");
}

static int __init init_light(void)
{
	extern int min_free_kbytes;
	int new_limit = 4096;
	int status = 0;

	// bump the min_free limit
	if (min_free_kbytes < new_limit)
		min_free_kbytes = new_limit;
	
	printk(KERN_INFO "loading MARS, BUILDTAG=%s BUILDHOST=%s BUILDDATE=%s\n", BUILDTAG, BUILDHOST, BUILDDATE);

	init_say(); // this must come first

#ifdef CONFIG_MARS_HAVE_BIGMODULE
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
	DO_INIT(log_format);
	DO_INIT(mars_net);
	DO_INIT(mars_server);
	DO_INIT(mars_client);
	DO_INIT(mars_aio);
	DO_INIT(mars_sio);
	DO_INIT(mars_bio);
	DO_INIT(mars_if);
	DO_INIT(mars_copy);
	DO_INIT(mars_trans_logger);

	DO_INIT(sy);
	DO_INIT(sy_net);
	DO_INIT(mars_proc);
#endif

	brick_mem_reserve(&global_reserve);

	status = compute_emergency_mode();
	if (unlikely(status < 0)) {
		MARS_ERR("Sorry, your /mars/ filesystem is too small!\n");
		goto done;
	}

	main_thread = brick_thread_create(light_thread, NULL, "mars_light");
	if (unlikely(!main_thread)) {
		status = -ENOENT;
		goto done;
	}

done:
	if (status < 0) {
		MARS_ERR("module init failed with status = %d, exiting.\n", status);
		exit_light();
	}
	_mars_remote_trigger = __mars_remote_trigger;
	return status;
}

// force module loading
const void *dummy1 = &client_brick_type;
const void *dummy2 = &server_brick_type;

MODULE_DESCRIPTION("MARS Light");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_VERSION(BUILDTAG " (" BUILDHOST " " BUILDDATE ")");
MODULE_LICENSE("GPL");

module_init(init_light);
module_exit(exit_light);
