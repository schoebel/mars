// (c) 2011 Thomas Schoebel-Theuer / 1&1 Internet AG

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING
//#define IO_DEBUGGING
//#define STAT_DEBUGGING // here means: display full statistics

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

#include <linux/kthread.h>
#include <linux/wait.h>

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

#if 0
#define inline __attribute__((__noinline__))
#endif

static struct task_struct *main_thread = NULL;

typedef int (*light_worker_fn)(void *buf, struct mars_dent *dent);

struct light_class {
	char *cl_name;
	int    cl_len;
	char   cl_type;
	bool   cl_hostcontext;
	bool   cl_serial;
	int    cl_father;
	light_worker_fn cl_prepare;
	light_worker_fn cl_forward;
	light_worker_fn cl_backward;
};

///////////////////////////////////////////////////////////////////////

// TUNING

#define CONF_TRANS_SHADOW_LIMIT (65536 * 1) // don't fill the hashtable too much
#define CONF_TRANS_CHUNKSIZE  (128 * 1024)
//#define CONF_TRANS_MAX_MREF_SIZE 0
#define CONF_TRANS_MAX_MREF_SIZE PAGE_SIZE
//#define CONF_TRANS_ALIGN      512
#define CONF_TRANS_ALIGN      0
//#define FLUSH_DELAY (HZ / 100 + 1)
#define FLUSH_DELAY 0

//#define TRANS_FAKE

#define CONF_TRANS_BATCHLEN 1024
//#define CONF_LOGST_FLYING 0
#define CONF_LOGST_FLYING 16
//#define CONF_TRANS_FLYING 16
#define CONF_TRANS_FLYING 0
#define CONF_TRANS_PRIO   MARS_PRIO_HIGH
#define CONF_TRANS_LOG_READS false
//#define CONF_TRANS_LOG_READS true
#define CONF_TRANS_MINIMIZE_LATENCY false
//#define CONF_TRANS_MINIMIZE_LATENCY true
//#define CONF_TRANS_COMPLETION_SEMANTICS 2
#define CONF_TRANS_COMPLETION_SEMANTICS 0

//#define CONF_ALL_BATCHLEN 2
#define CONF_ALL_BATCHLEN 1
#define CONF_ALL_FLYING 4
//#define CONF_ALL_FLYING 1
#define CONF_ALL_CONTENTION 0
#define CONF_ALL_PRESSURE 0
#define CONF_ALL_PRIO   MARS_PRIO_NORMAL

#define CONF_ALL_MAX_QUEUE 10000
#define CONF_ALL_MAX_JIFFIES (180 * HZ)

#define IF_SKIP_SYNC true

#define IF_MAX_PLUGGED 10000
#define IF_READAHEAD 0
//#define IF_READAHEAD 1

#define BIO_READAHEAD 0
//#define BIO_READAHEAD 1
#define BIO_NOIDLE true
#define BIO_SYNC true
#define BIO_UNPLUG true

#define AIO_READAHEAD 1
#define AIO_WAIT_DURING_FDSYNC false

#define COPY_APPEND_MODE 0
//#define COPY_APPEND_MODE 1 // FIXME: does not work yet
#define COPY_PRIO MARS_PRIO_LOW

#define MIN_SPACE (1024 * 1024 * 8) // 8 GB
#ifdef CONFIG_MARS_MIN_SPACE
#define EXHAUSTED(x) ((x) <= MIN_SPACE)
#else
#define EXHAUSTED(x) (false)
#endif

static
int _set_trans_params(struct mars_brick *_brick, void *private)
{
	struct trans_logger_brick *trans_brick = (void*)_brick;
	if (_brick->type != (void*)&trans_logger_brick_type) {
		MARS_ERR("bad brick type\n");
		return -EINVAL;
	}
	if (!trans_brick->q_phase2.q_ordering) {
		trans_brick->q_phase1.q_batchlen = CONF_TRANS_BATCHLEN;
		trans_brick->q_phase2.q_batchlen = CONF_ALL_BATCHLEN;
		trans_brick->q_phase3.q_batchlen = CONF_ALL_BATCHLEN;
		trans_brick->q_phase4.q_batchlen = CONF_ALL_BATCHLEN;

		trans_brick->q_phase1.q_max_flying = CONF_TRANS_FLYING;
		trans_brick->q_phase2.q_max_flying = CONF_ALL_FLYING;
		trans_brick->q_phase3.q_max_flying = CONF_ALL_FLYING;
		trans_brick->q_phase4.q_max_flying = CONF_ALL_FLYING;

		trans_brick->q_phase1.q_max_contention = CONF_ALL_CONTENTION;
		trans_brick->q_phase2.q_max_contention = CONF_ALL_CONTENTION;
		trans_brick->q_phase3.q_max_contention = CONF_ALL_CONTENTION;
		trans_brick->q_phase4.q_max_contention = CONF_ALL_CONTENTION;

		trans_brick->q_phase1.q_over_pressure = CONF_ALL_PRESSURE;
		trans_brick->q_phase2.q_over_pressure = CONF_ALL_PRESSURE;
		trans_brick->q_phase3.q_over_pressure = CONF_ALL_PRESSURE;
		trans_brick->q_phase4.q_over_pressure = CONF_ALL_PRESSURE;

		trans_brick->q_phase1.q_io_prio = CONF_TRANS_PRIO;
		trans_brick->q_phase2.q_io_prio = CONF_ALL_PRIO;
		trans_brick->q_phase3.q_io_prio = CONF_ALL_PRIO;
		trans_brick->q_phase4.q_io_prio = CONF_ALL_PRIO;

		trans_brick->q_phase2.q_max_queued = CONF_ALL_MAX_QUEUE;
		trans_brick->q_phase4.q_max_queued = CONF_ALL_MAX_QUEUE;

		trans_brick->q_phase2.q_max_jiffies = CONF_ALL_MAX_JIFFIES;
		trans_brick->q_phase4.q_max_jiffies = CONF_ALL_MAX_JIFFIES;

		trans_brick->q_phase2.q_ordering = true;
		trans_brick->q_phase4.q_ordering = true;

		trans_brick->shadow_mem_limit = CONF_TRANS_SHADOW_LIMIT;
		trans_brick->log_reads = CONF_TRANS_LOG_READS;
		trans_brick->completion_semantics = CONF_TRANS_COMPLETION_SEMANTICS;
		trans_brick->minimize_latency = CONF_TRANS_MINIMIZE_LATENCY;
#ifdef TRANS_FAKE
		trans_brick->debug_shortcut = true;
#endif

		trans_brick->max_mref_size = CONF_TRANS_MAX_MREF_SIZE;
		trans_brick->align_size = CONF_TRANS_ALIGN;
		trans_brick->chunk_size = CONF_TRANS_CHUNKSIZE;
		trans_brick->flush_delay = FLUSH_DELAY;
		trans_brick->max_flying = CONF_LOGST_FLYING;

		if (!trans_brick->log_reads) {
			trans_brick->q_phase2.q_max_queued = 0;
			trans_brick->q_phase4.q_max_queued *= 2;
		}
	}
	MARS_INF("name = '%s' path = '%s'\n", _brick->brick_name, _brick->brick_path);
	return 1;
}

static
int _set_client_params(struct mars_brick *_brick, void *private)
{
	struct client_brick *client_brick = (void*)_brick;
	client_brick->io_timeout = CONFIG_MARS_NETIO_TIMEOUT;
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
	MARS_INF("name = '%s' path = '%s'\n", _brick->brick_name, _brick->brick_path);
	return 1;
}

static
int _set_aio_params(struct mars_brick *_brick, void *private)
{
	struct aio_brick *aio_brick = (void*)_brick;
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
	aio_brick->readahead = AIO_READAHEAD;
	aio_brick->o_direct = false; // important!
	aio_brick->o_fdsync = true;
	aio_brick->wait_during_fdsync = AIO_WAIT_DURING_FDSYNC;
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
	MARS_INF("name = '%s' path = '%s'\n", _brick->brick_name, _brick->brick_path);
	return 1;
}


static
int _set_if_params(struct mars_brick *_brick, void *private)
{
	struct if_brick *if_brick = (void*)_brick;
	if (_brick->type != (void*)&if_brick_type) {
		MARS_ERR("bad brick type\n");
		return -EINVAL;
	}
	if_brick->max_plugged = IF_MAX_PLUGGED;
	if_brick->readahead = IF_READAHEAD;
	if_brick->skip_sync = IF_SKIP_SYNC;
	MARS_INF("name = '%s' path = '%s'\n", _brick->brick_name, _brick->brick_path);
	return 1;
}

struct copy_cookie {
	const char *argv[2];
	const char *copy_path;
	loff_t start_pos;

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

static
char *_parse_versionlink(const char *str, loff_t *start_pos, loff_t *end_pos)
{
	char *res = NULL;
	const char *tmp;
	int count;
	int status;

	*start_pos = 0;
	*end_pos = 0;

	while (*str && *str++ != MARS_DELIM) {
		// empty
	}

	tmp = str;
	count = 0;
	while (*tmp && *tmp != MARS_DELIM) {
		tmp++;
		count++;
	}
	res = brick_string_alloc(count + 1);
	if (unlikely(!res)) {
		MARS_DBG("bad alloc\n");
		goto done;
	}

	strncpy(res, str, count);
	res[count] = '\0';

	status = sscanf(tmp, ",%lld,%lld", start_pos, end_pos);
	if (unlikely(status != 2)) {
		MARS_DBG("status = %d\n", status);
		brick_string_free(res);
		res = NULL;
	}
done:
	return res;
}

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

	if (global->exhausted)
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

///////////////////////////////////////////////////////////////////////

// needed for logfile rotation

struct mars_rotate {
	struct mars_global *global;
	struct mars_dent *replay_link;
	struct mars_dent *aio_dent;
	struct aio_brick *aio_brick;
	struct mars_info aio_info;
	struct trans_logger_brick *trans_brick;
	struct mars_dent *relevant_log;
	struct mars_brick *relevant_brick;
	struct mars_dent *next_relevant_log;
	struct mars_brick *next_relevant_brick;
	struct mars_dent *prev_log;
	struct mars_dent *next_log;
	struct if_brick *if_brick;
	loff_t remaining_space;
	loff_t copy_end_pos;
	loff_t start_pos;
	loff_t end_pos;
	int max_sequence;
	bool has_error;
	bool try_sync;
	bool do_replay;
	bool todo_primary;
	bool is_primary;
	bool old_is_primary;
	bool copy_is_done;
};

///////////////////////////////////////////////////////////////////////

// status display

static
int _show_actual(const char *path, const char *name, bool val)
{
	char *src;
	char *dst = NULL;
	int status = -EINVAL;

	src = val ? "1" : "0";
	dst = path_make("%s/actual-%s/%s", path, my_id(), name);
	status = -ENOMEM;
	if (!dst)
		goto done;
	MARS_DBG("symlink '%s' -> '%s'\n", dst, src);
	status = mars_symlink(src, dst, NULL, 0);

done:
	brick_string_free(dst);
	return status;
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
		struct copy_brick **__copy)
{
	struct mars_brick *copy;
	struct copy_brick *_copy;
	struct copy_cookie cc = {};
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
				       NULL,
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
			       global->exhausted ? -1 : 0,
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
	//wait_queue_head_t event;
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
int _update_file(struct mars_global *global, const char *switch_path, const char *copy_path, const char *file, const char *peer, loff_t end_pos)
{
	const char *tmp = path_make("%s@%s", file, peer);
	const char *argv[2] = { tmp, file };
	struct copy_brick *copy = NULL;
	int status = -ENOMEM;

	if (unlikely(!tmp))
		goto done;

	MARS_DBG("src = '%s' dst = '%s'\n", tmp, file);
	status = __make_copy(global, NULL, switch_path, copy_path, NULL, argv, -1, &copy);
	if (status >= 0 && copy && (!copy->append_mode || copy->power.led_off)) {
		if (end_pos > copy->copy_end) {
			MARS_DBG("appending to '%s' %lld => %lld\n", copy_path, copy->copy_end, end_pos);
			copy->copy_end = end_pos;
		}
	}

done:
	brick_string_free(tmp);
	return status;
}

static
int check_logfile(struct mars_peerinfo *peer, struct mars_dent *remote_dent, struct mars_dent *local_dent, struct mars_dent *parent, loff_t dst_size)
{
	loff_t src_size = remote_dent->new_stat.size;
	struct mars_rotate *rot;
	const char *switch_path = NULL;
	const char *copy_path = NULL;
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

	// check whether (some/another) copy is already running
	copy_path = path_make("%s/logfile-update", parent->d_path);
	if (unlikely(!copy_path)) {
		status = -ENOMEM;
		goto done;
	}
	copy_brick = (struct copy_brick*)mars_find_brick(peer->global, &copy_brick_type, copy_path);
	MARS_DBG("copy_path = '%s' copy_brick = %p dent = '%s'\n", copy_path, copy_brick, remote_dent->d_path);
	if (copy_brick) {
		bool is_my_copy = (remote_dent->d_serial == parent->d_logfile_serial);
		bool copy_is_done = (is_my_copy && copy_brick->copy_last == copy_brick->copy_end && local_dent != NULL && copy_brick->copy_end == rot->copy_end_pos);
		bool is_next_copy = (remote_dent->d_serial == parent->d_logfile_serial + 1);

		MARS_DBG("current copy brick '%s' copy_last = %lld copy_end = %lld dent '%s' serial = %d/%d is_done = %d is_my_copy = %d is_next_copy = %d\n", copy_brick->brick_path, copy_brick->copy_last, copy_brick->copy_end, remote_dent->d_path, remote_dent->d_serial, parent->d_logfile_serial, copy_is_done, is_my_copy, is_next_copy);

		if (is_my_copy) {
			rot->copy_is_done = copy_is_done;
			goto treat;
		}
		if (peer->global->global_power.button && !rot->copy_is_done) {
			goto done;
		}
		MARS_DBG("killing old copy brick '%s'\n", copy_brick->brick_path);
		status = mars_kill_brick((void*)copy_brick);
		if (status < 0)
			goto done;
		rot->copy_is_done = false;
		// ensure consecutiveness of logfiles
		if (!is_next_copy) {
			goto done;
		}
		// fallthrough: take the next logfile
	}

treat:
	// (new) copy necessary?
	status = 0;
	if (!rot->try_sync) {
		MARS_DBG("logfiles are not for me.\n");
		goto done;
	}
	if (dst_size >= src_size && local_dent != NULL) { // nothing to do
		goto ok;
	}

	// check whether connection is allowed
	switch_path = path_make("%s/todo-%s/connect", parent->d_path, my_id());
	
	// start / treat copy brick instance
	rot->copy_end_pos = src_size;
	status = _update_file(peer->global, switch_path, copy_path, remote_dent->d_path, peer->peer, src_size);
	MARS_DBG("update '%s' from peer '%s' status = %d\n", remote_dent->d_path, peer->peer, status);
	if (status < 0) {
		goto done;
	}
ok:
	parent->d_logfile_serial = remote_dent->d_serial;

done:
	brick_string_free(copy_path);
	brick_string_free(switch_path);
	if (status < 0 && parent)
		parent->d_logfile_serial = status;
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

		MARS_DBG("timestamps '%s' remote = %ld.%09ld local = %ld.%09ld\n", remote_dent->d_path, remote_dent->new_stat.mtime.tv_sec, remote_dent->new_stat.mtime.tv_nsec, local_stat.mtime.tv_sec, local_stat.mtime.tv_nsec);

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

		if (remote_dent->new_stat.uid != local_stat.uid && update_ctime) {
			MARS_DBG("lchown '%s' %d -> %d\n", remote_dent->d_path, local_stat.uid, remote_dent->new_stat.uid);
			mars_lchown(remote_dent->d_path, remote_dent->new_stat.uid);
			run_trigger = true;
		}
	}

	if (S_ISDIR(remote_dent->new_stat.mode)) {
		if (!_is_usable_dir(remote_dent->d_name)) {
			MARS_DBG("ignoring directory '%s'\n", remote_dent->d_path);
			goto done;
		}
		if (!stat_ok) {
			status = mars_mkdir(remote_dent->d_path);
			MARS_DBG("create directory '%s' status = %d\n", remote_dent->d_path, status);
			if (status >= 0) {
				mars_chmod(remote_dent->d_path, remote_dent->new_stat.mode);
				mars_lchown(remote_dent->d_path, remote_dent->new_stat.uid);
			}
		}
	} else if (S_ISLNK(remote_dent->new_stat.mode) && remote_dent->new_link) {
		if (!stat_ok || update_mtime) {
			status = mars_symlink(remote_dent->new_link, remote_dent->d_path, &remote_dent->new_stat.mtime, remote_dent->new_stat.uid);
			MARS_DBG("create symlink '%s' -> '%s' status = %d\n", remote_dent->d_path, remote_dent->new_link, status);
			run_trigger = true;
		}
	} else if (S_ISREG(remote_dent->new_stat.mode) && _is_peer_logfile(remote_dent->d_name, my_id())) {
		const char *parent_path = backskip_replace(remote_dent->d_path, '/', false, "");
		if (likely(parent_path)) {
			struct mars_dent *parent = mars_find_dent(peer->global, parent_path);
			struct mars_dent *local_dent = mars_find_dent(peer->global, remote_dent->d_path);
			if (unlikely(!parent)) {
				MARS_DBG("ignoring non-existing local resource '%s'\n", parent_path);
			} else {
				status = check_logfile(peer, remote_dent, local_dent, parent, local_stat.size);
			}
			brick_string_free(parent_path);
		}
	} else {
		MARS_DBG("ignoring '%s'\n", remote_dent->d_path);
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

	for (tmp = tmp_list.next; tmp != &tmp_list; tmp = tmp->next) {
		struct mars_dent *remote_dent = container_of(tmp, struct mars_dent, dent_link);
		if (!remote_dent->d_path) {
			MARS_DBG("NULL\n");
			continue;
		}
		MARS_DBG("path = '%s'\n", remote_dent->d_path);
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
	if (peer->socket.s_socket) {
		MARS_DBG("really shutdown socket\n");
		mars_shutdown_socket(&peer->socket);
		mars_put_socket(&peer->socket);
	}

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

        while (!kthread_should_stop()) {
		LIST_HEAD(tmp_list);
		LIST_HEAD(old_list);
		unsigned long flags;
		struct mars_cmd cmd = {
			.cmd_code = CMD_GETENTS,
			.cmd_str1 = peer->path,
			.cmd_int1 = peer->maxdepth,
		};

		if (!mars_socket_is_alive(&peer->socket)) {
			if (peer->socket.s_socket) {
				_peer_cleanup(peer);
				msleep(5000);
				continue;
			}
			status = mars_create_socket(&peer->socket, &sockaddr, false);
			if (unlikely(status < 0)) {
				MARS_INF("no connection to '%s'\n", real_peer);
				msleep(5000);
				continue;
			}
			peer->socket.s_shutdown_on_err = true;
			MARS_DBG("successfully opened socket to '%s'\n", real_peer);
			msleep(100);
			continue;
		}

		/* This is not completely race-free, but does no harm.
		 * In worst case, network propagation will just take
		 * a litte longer (see CONFIG_MARS_PROPAGATE_INTERVAL).
		 */
		if (atomic_read(&remote_trigger_count) > 0) {
			atomic_dec(&remote_trigger_count);
			cmd.cmd_code = CMD_NOTIFY;
		}

		status = mars_send_struct(&peer->socket, &cmd, mars_cmd_meta);
		if (unlikely(status < 0)) {
			MARS_WRN("communication error on send, status = %d\n", status);
			_peer_cleanup(peer);
			msleep(2000);
			continue;
		}
		if (cmd.cmd_code == CMD_NOTIFY)
			continue;

		status = mars_recv_dent_list(&peer->socket, &tmp_list);
		if (unlikely(status < 0)) {
			MARS_WRN("communication error on receive, status = %d\n", status);
			_peer_cleanup(peer);
			msleep(5000);
			continue;
		}

		if (likely(!list_empty(&tmp_list))) {
			//MARS_DBG("AHA!!!!!!!!!!!!!!!!!!!!\n");

			traced_lock(&peer->lock, flags);

			list_replace_init(&peer->remote_dent_list, &old_list);
			list_replace_init(&tmp_list, &peer->remote_dent_list);

			traced_unlock(&peer->lock, flags);

			mars_free_dent_all(NULL, &old_list);
		}

		msleep(1000);
		if (!kthread_should_stop())
			wait_event_interruptible_timeout(remote_event, atomic_read(&peer_thread_count) > 0, CONFIG_MARS_PROPAGATE_INTERVAL * HZ);
	}

	MARS_INF("-------- peer thread terminating\n");

	_peer_cleanup(peer);

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
		kthread_stop(peer->peer_thread);
		put_task_struct(peer->peer_thread);
		peer->peer_thread = NULL;
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

static int _make_peer(struct mars_global *global, struct mars_dent *dent, char *mypeer, char *path)
{
	static int serial = 0;
	struct mars_peerinfo *peer;
	int status = 0;

	if (!global->global_power.button || !dent->new_link) {
		return 0;
	}
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
			return -1;
		}

		peer = dent->d_private;
		peer->global = global;
		peer->peer = brick_strdup(mypeer);
		peer->path = brick_strdup(path);
		peer->maxdepth = 2;
		spin_lock_init(&peer->lock);
		INIT_LIST_HEAD(&peer->remote_dent_list);
		//init_waitqueue_head(&peer->event);
	}

	peer = dent->d_private;
	if (!peer->peer_thread) {
		peer->peer_thread = kthread_create(peer_thread, peer, "mars_peer%d", serial++);
		if (unlikely(IS_ERR(peer->peer_thread))) {
			MARS_ERR("cannot start peer thread, status = %d\n", (int)PTR_ERR(peer->peer_thread));
			peer->peer_thread = NULL;
			return -1;
		}
		MARS_DBG("starting peer thread\n");
		get_task_struct(peer->peer_thread);
		wake_up_process(peer->peer_thread);
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
	return _make_peer(buf, dent, dent->d_rest, "/mars");
}


static
int kill_any(void *buf, struct mars_dent *dent)
{
	struct mars_global *global = buf;
	struct list_head *tmp;

	if (global->global_power.button) {
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
int _update_replaylink(const char *parent_path, const char *host, int sequence, loff_t start_pos, loff_t end_pos, bool check_exist)
{
	struct timespec now = {};
	char *old = NULL;
	char *new = NULL;
	char *test = NULL;
	int status = -ENOMEM;

	if (check_exist) {
		struct kstat kstat;
		char *test = path_make("%s/log-%09d-%s", parent_path, sequence, host);
		if (!test) {
			goto out;
		}
		status = mars_stat(test, &kstat, true);
		brick_string_free(test);
		if (status < 0) {
			MARS_DBG("could not update replay link to nonexisting logfile '%s'\n", test);
			goto out;
		}
		status = -ENOMEM;
	}

	old = path_make("log-%09d-%s,%lld,%lld", sequence, host, start_pos, end_pos - start_pos);
	if (!old) {
		goto out;
	}
	new = path_make("%s/replay-%s", parent_path, my_id());
	if (!new) {
		goto out;
	}

	get_lamport(&now);
	status = mars_symlink(old, new, &now, 0);
	if (status < 0) {
		MARS_ERR("cannot create symlink '%s' -> '%s' status = %d\n", old, new, status);
	} else {
		MARS_DBG("made replay symlink '%s' -> '%s' status = %d\n", old, new, status);
	}

out:
	brick_string_free(new);
	brick_string_free(old);
	brick_string_free(test);
	return status;
}

static
int _update_versionlink(struct mars_global *global, const char *parent_path, const char *host, int sequence, loff_t start_pos, loff_t end_pos)
{
	char *prev = NULL;
	struct mars_dent *prev_link = NULL;
	char *prev_digest = NULL;
	struct timespec now = {};
	int i;
	int status = -ENOMEM;
	int len = 0;
	int oldlen;

	char *new = NULL;
	char *data = brick_string_alloc(0);
	char *old = brick_string_alloc(0);
	unsigned char *digest = brick_string_alloc(0);

	if (unlikely(!data || !digest || !old)) {
		MARS_ERR("no MEM\n");
		goto out;
	}
	status = -EINVAL;
	if (sequence > 1) {
		prev = path_make("%s/version-%09d-%s", parent_path, sequence-1, my_id());
		if (unlikely(!prev)) {
			goto out;
		}
		prev_link = mars_find_dent(global, prev);
		if (unlikely(!prev_link)) {
			MARS_ERR("cannot find previous version symlink '%s'\n", prev);
			goto out;
		}
		prev_digest = prev_link->new_link;
	}

	len = sprintf(data, "%s,%d,%lld,%lld,%s", host, sequence, start_pos, end_pos, prev_digest ? prev_digest : "");

	MARS_DBG("data = '%s' len = %d\n", data, len);

	mars_digest(digest, data, len);

	oldlen = 0;
	for (i = 0; i < mars_digest_size; i++) {
		oldlen += sprintf(old + oldlen, "%02x", digest[i]);
	}
	oldlen += sprintf(old + oldlen, ",%s,%lld,%lld", host, start_pos, end_pos - start_pos);

	new = path_make("%s/version-%09d-%s", parent_path, sequence, my_id());
	if (!new) {
		goto out;
	}

	get_lamport(&now);
	status = mars_symlink(old, new, &now, 0);
	if (status < 0) {
		MARS_ERR("cannot create symlink '%s' -> '%s' status = %d\n", old, new, status);
	} else {
		MARS_DBG("make version symlink '%s' -> '%s' status = %d\n", old, new, status);
	}

out:
	brick_string_free(new);
	brick_string_free(prev);
	brick_string_free(data);
	brick_string_free(digest);
	brick_string_free(old);
	return status;
}

static
int __update_all_links(struct mars_global *global, const char *parent_path, struct trans_logger_brick *trans_brick, const char *override_host, int override_sequence, bool check_exist, bool force, int nr, bool both)
{
	struct trans_logger_input *trans_input;
	loff_t min_pos;
	loff_t max_pos;
	const char *host;
	int sequence;
	int status;

	if (nr < TL_INPUT_LOG1 || nr > TL_INPUT_LOG2) {
		MARS_ERR("bad nr = %d\n", nr);
		status = -EINVAL;
		goto done;
	}
	trans_input = trans_brick->inputs[nr];
	if (!trans_input) {
		MARS_ERR("bad trans_input = %p\n", trans_input);
		status = -EINVAL;
		goto done;
	}
	if (!force && (long long)jiffies < trans_input->last_jiffies + 3 * HZ) {
		status = 0;
		goto done;
	}

	min_pos = trans_input->replay_min_pos;
	max_pos = trans_input->replay_max_pos;
	host = trans_input->inf_host;
	sequence = trans_input->inf_sequence;
	if (override_host)
		host = override_host;
	if (override_sequence) {
		sequence = override_sequence;
		min_pos = max_pos = 0;
	}

	if (!host) {
		MARS_DBG("no host string\n");
		status = 0;
		goto done;
	}

	status = 0;
	if (both)
		status = _update_replaylink(parent_path, host, sequence, min_pos, max_pos, check_exist);
	status |= _update_versionlink(global, parent_path, host, sequence, max_pos, max_pos);
	if (!status)
		trans_input->last_jiffies = jiffies;
 done:
	return status;
}

static
int _update_all_links(struct mars_global *global, const char *parent_path, struct trans_logger_brick *trans_brick, const char *override_host, int override_sequence, bool check_exist, bool force)
{
	int old_nr = trans_brick->old_input_nr;
	int new_nr = trans_brick->new_input_nr;
	int status;

	if (old_nr == new_nr) {
		status = __update_all_links(global, parent_path, trans_brick, override_host, override_sequence, check_exist, force, new_nr, true);
	} else {
		status = __update_all_links(global, parent_path, trans_brick, override_host, override_sequence, check_exist, force, old_nr, false);
		status |= __update_all_links(global, parent_path, trans_brick, override_host, override_sequence, check_exist, force, new_nr, true);
	}
	return status;
}

static
int _check_versionlink(struct mars_global *global, const char *parent_path, int sequence, loff_t target_end_pos)
{
	char *my_version = NULL;
	char *other_version = NULL;
	struct mars_dent *my_version_dent;
	struct mars_dent *other_version_dent;
	const char *my_data;
	const char *other_data;
	char *from_host = NULL;
	loff_t start_pos;
	loff_t end_pos;
	int status = -ENOMEM;

	my_version = path_make("%s/version-%09d-%s", parent_path, sequence, my_id());
	if (!my_version) {
		MARS_WRN("out of memory");
		goto out;
	}

	status = -ENOENT;
	my_version_dent = mars_find_dent(global, my_version);
	if (!my_version_dent || !my_version_dent->new_link) {
		MARS_WRN("cannot find my own version symlink '%s'\n", my_version);
		goto out;
	}

	my_data = my_version_dent->new_link;
	from_host = _parse_versionlink(my_data, &start_pos, &end_pos);
	if (!from_host) {
		MARS_WRN("cannot parse '%s'\n", my_data);
		goto out;
	}

	if (!strcmp(from_host, my_id())) {
		MARS_DBG("found version stemming from myself, no check of other version necessary.\n");
		status = 1;
		if (unlikely(start_pos != target_end_pos || end_pos != 0)) {
			MARS_WRN("start_pos = %lld != target_end_pos = %lld || end_pos = %lld != 0\n", start_pos, target_end_pos, end_pos);
			status = 0;
		}
		goto out;
	}

	status = -ENOMEM;
	other_version = path_make("%s/version-%09d-%s", parent_path, sequence, from_host);
	if (!other_version) {
		MARS_WRN("out of memory");
		goto out;
	}

	status = -ENOENT;
	other_version_dent = mars_find_dent(global, other_version);
	if (!other_version_dent || !other_version_dent->new_link) {
		MARS_WRN("cannot find other version symlink '%s'\n", other_version);
		goto out;
	}

	other_data = other_version_dent->new_link;

	if (!strcmp(my_data, other_data)) {
		MARS_DBG("VERSION OK '%s'\n", my_data);
		status = 1;
	} else {
		MARS_DBG("VERSION MISMATCH '%s' != '%s'\n", my_data, other_data);
		status = 0;
	}

out:
	brick_string_free(my_version);
	brick_string_free(other_version);
	brick_string_free(from_host);
	return status;
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
		rot = brick_zmem_alloc(sizeof(struct mars_rotate));
		parent->d_private = rot;
		if (!rot) {
			MARS_ERR("cannot allocate rot structure\n");
			status = -ENOMEM;
			goto done;
		}
		rot->global = global;
	}

	rot->replay_link = NULL;
	rot->aio_dent = NULL;
	rot->aio_brick = NULL;
	rot->relevant_log = NULL;
	rot->relevant_brick = NULL;
	rot->next_relevant_log = NULL;
	rot->prev_log = NULL;
	rot->next_log = NULL;
	rot->max_sequence = 0;
	rot->has_error = false;

	rot->remaining_space = mars_remaining_space(parent_path);

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
		rot->try_sync = false;
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
	if (rot->trans_brick && rot->trans_brick->log_input_nr) {
		struct trans_logger_input *trans_input = rot->trans_brick->inputs[rot->trans_brick->log_input_nr];
		status = -EINVAL;
		CHECK_PTR(trans_input, done);
		if (trans_input->inf_host) {
			aio_path = path_make("%s/log-%09d-%s", parent_path, trans_input->inf_sequence, trans_input->inf_host);
			MARS_DBG("using logfile '%s' from trans_input %d (old=%d)\n", SAFE_STR(aio_path), rot->trans_brick->log_input_nr, rot->trans_brick->old_input_nr);
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
	/* For safety, default is to try an (unnecessary) replay in case
	 * something goes wrong later.
	 */
	rot->do_replay = true;

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
		MARS_ERR("transaction logs are not consecutive at '%s' (%d ~> %d)\n", dent->d_path, prev_log->d_serial, dent->d_serial);
		status = -EINVAL;
		goto done;
	}

	if (dent->d_serial > rot->max_sequence) {
		rot->max_sequence = dent->d_serial;
	}

	/* Skip any logfiles after the relevant one.
	 * This should happen only when replaying multiple logfiles
	 * in sequence, or when starting a new logfile for writing.
	 */
	status = 0;
	if (rot->relevant_log) {
		if (!rot->next_relevant_log) {
			rot->next_relevant_log = dent;
		}
		MARS_DBG("next_relevant_log = %p\n", rot->next_relevant_log);
		goto ok;
	}

	/* Preconditions
	 */
	if (!rot->replay_link || !rot->aio_dent || !rot->aio_brick) {
		//MARS_DBG("nothing to do on '%s'\n", dent->d_path);
		goto ok;
	}

	/* Remember the relevant log.
	 */
	if (rot->aio_dent->d_serial == dent->d_serial) {
		rot->relevant_log = dent;
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
int _check_logging_status(struct mars_rotate *rot, long long *oldpos_start, long long *oldpos_end, long long *newpos)
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

	if (sscanf(rot->replay_link->d_argv[1], "%lld", oldpos_start) != 1) {
		MARS_ERR("bad start position argument '%s'\n", rot->replay_link->d_argv[1]);
		goto done;
	}
	if (sscanf(rot->replay_link->d_argv[2], "%lld", oldpos_end) != 1) {
		MARS_ERR("bad end position argument '%s'\n", rot->replay_link->d_argv[2]);
		goto done;
	}
	*oldpos_end += *oldpos_start;
	if (unlikely(*oldpos_end < *oldpos_start)) {
		MARS_ERR("end_pos %lld < start_pos %lld\n", *oldpos_end, *oldpos_start);
	}

	if (unlikely(rot->aio_info.current_size < *oldpos_start)) {
		MARS_ERR("oops, bad replay position attempted at logfile '%s' (file length %lld should never be smaller than requested position %lld, is your filesystem corrupted?) => please repair this by hand\n", rot->aio_dent->d_path, rot->aio_info.current_size, *oldpos_start);
		status = -EBADF;
		goto done;
	}

	status = 0;
	if (rot->aio_info.current_size > *oldpos_start || rot->aio_info.current_size < *oldpos_end) {
		MARS_DBG("transaction log replay is necessary on '%s' from %lld to %lld (dirty region ends at %lld)\n", rot->aio_dent->d_path, *oldpos_start, rot->aio_info.current_size, *oldpos_end);
		*newpos = rot->aio_info.current_size;
		status = 2;
	} else if (rot->next_relevant_log) {
		MARS_DBG("transaction log '%s' is already applied, and the next one is available for switching\n", rot->aio_dent->d_path);
		*newpos = rot->aio_info.current_size;
		status = 1;
	} else if (rot->todo_primary) {
		if (rot->aio_info.current_size > 0 || strcmp(dent->d_rest, my_id()) != 0) {
			MARS_DBG("transaction log '%s' is already applied (would be usable for appending at position %lld, but a fresh logfile will be used for safety reasons)\n", rot->aio_dent->d_path, *oldpos_end);
			*newpos = rot->aio_info.current_size;
			status = 1;
		} else {
			MARS_DBG("empty transaction log '%s' is usable for me as a primary node\n", rot->aio_dent->d_path);
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
	status = _check_logging_status(rot, &start_pos, &dirty_pos, &end_pos);
	if (status < 0) {
		goto done;
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
			if (global->exhausted) {
				MARS_DBG("filesystem is exhausted, refraining from log rotation\n");
			} else if (rot->next_relevant_log) {
				MARS_DBG("check switchover from '%s' to '%s'\n", dent->d_path, rot->next_relevant_log->d_path);
				if (_check_versionlink(global, parent->d_path, dent->d_serial, end_pos) > 0) {
					MARS_DBG("switching over from '%s' to next relevant transaction log '%s'\n", dent->d_path, rot->next_relevant_log->d_path);
					_update_all_links(global, parent->d_path, trans_brick, rot->next_relevant_log->d_rest, dent->d_serial + 1, true, true);
#ifdef CONFIG_MARS_FAST_TRIGGER
					mars_trigger();
					mars_remote_trigger();
#endif
				}
			} else if (rot->todo_primary) {
				MARS_DBG("preparing new transaction log '%s' from version %d to %d\n", dent->d_path, dent->d_serial, dent->d_serial + 1);
				_update_all_links(global, parent->d_path, trans_brick, my_id(), dent->d_serial + 1, false, true);
#ifdef CONFIG_MARS_FAST_TRIGGER
				mars_trigger();
				mars_remote_trigger();
#endif
			} else {
				MARS_DBG("nothing to do on last transaction log '%s'\n", dent->d_path);
			}
		}
		status = -EAGAIN;
		goto done;
	case 2: // relevant for transaction replay
		MARS_DBG("replaying transaction log '%s' from %lld to %lld\n", dent->d_path, start_pos, end_pos);
		rot->do_replay = true;
		rot->start_pos = start_pos;
		rot->end_pos = end_pos;
		break;
	case 3: // relevant for appending
		MARS_DBG("appending to transaction log '%s'\n", dent->d_path);
		rot->do_replay = false;
		rot->start_pos = 0;
		rot->end_pos = 0;
		break;
	default:
		MARS_ERR("bad internal status %d\n", status);
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
void _init_trans_input(struct trans_logger_input *trans_input, struct mars_dent *log_dent)
{
	if (trans_input->is_prepared) {
		MARS_ERR("this should not happen\n");
		return;
	}
	brick_string_free(trans_input->inf_host);
	trans_input->inf_host = brick_strdup(log_dent->d_rest);
	trans_input->inf_sequence = log_dent->d_serial;
	trans_input->replay_min_pos = 0;
	trans_input->replay_max_pos = 0;
	trans_input->log_start_pos = 0;
	trans_input->is_prepared = true;
	MARS_DBG("initialized '%s' %d\n", trans_input->inf_host, trans_input->inf_sequence);
}

static
void __exit_trans_input(struct trans_logger_input *trans_input)
{
	MARS_DBG("cleaning '%s' %d\n", SAFE_STR(trans_input->inf_host), trans_input->inf_sequence);
	brick_string_free(trans_input->inf_host);
	trans_input->inf_host = NULL;
	trans_input->is_prepared = false;
}

static
void _exit_trans_input(struct trans_logger_input *trans_input)
{
	if (!trans_input->is_prepared) {
		MARS_ERR("this should not happen\n");
		return;
	}
	__exit_trans_input(trans_input);
}

#ifdef CONFIG_MARS_LOGROT
static
int _get_free_input(struct trans_logger_brick *trans_brick)
{
	int nr = (((trans_brick->log_input_nr - TL_INPUT_LOG1) + 1) % 2) + TL_INPUT_LOG1;
	struct trans_logger_input *candidate;
	MARS_DBG("nr = %d\n", nr);
	candidate = trans_brick->inputs[nr];
	MARS_DBG("candidate = %p\n", candidate);
	if (!candidate || candidate->is_operating || candidate->connect) {
		MARS_DBG("%d unusable!\n", nr);
		return -EEXIST;
	}
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
		if (!trans_input->connect) {
			MARS_DBG("ignoring unused input %d\n", old_nr);
		} else if (trans_input->replay_min_pos == trans_input->replay_max_pos && list_empty(&trans_input->pos_list)) {
			int status = generic_disconnect((void*)trans_input);
			if (status < 0) {
				MARS_ERR("disconnect failed\n");
			} else {
				MARS_INF("closed old transaction log (%d -> %d)\n", old_nr, log_nr);
				// we must not change the replaylink (races)
				if (likely(rot->replay_link && rot->replay_link->d_parent && rot->replay_link->d_parent->d_path)) {
					(void)_update_versionlink(rot->global, rot->replay_link->d_parent->d_path, trans_input->inf_host, trans_input->inf_sequence, trans_input->replay_min_pos, trans_input->replay_max_pos);
				} else {
					MARS_ERR("bad pointers\n");
				}
				_exit_trans_input(trans_input);
				mars_remote_trigger();
			}
		} else {
			MARS_DBG("old transaction replay not yet finished: %lld != %lld\n", trans_input->replay_min_pos, trans_input->replay_max_pos);
		}
	} 
	// try to setup new log
	else if (rot->next_relevant_log && (next_nr = _get_free_input(trans_brick)) >= 0 && trans_brick->inputs[next_nr] && !trans_brick->inputs[next_nr]->is_prepared) {
		struct trans_logger_input *trans_input;
		int status;

		MARS_DBG("start switchover %d -> %d\n", old_nr, next_nr);

		rot->next_relevant_brick =
			make_brick_all(rot->global,
				       rot->next_relevant_log,
				       false,
				       NULL,
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
			MARS_ERR("could not open next transaction log '%s'\n", rot->next_relevant_log->d_path);
			goto done;
		}
		trans_input = trans_brick->inputs[next_nr];
		if (unlikely(!trans_input)) {
			MARS_ERR("log input does not exist\n");
			goto done;
		}

		_init_trans_input(trans_input, rot->next_relevant_log);

		status = generic_connect((void*)trans_input, (void*)rot->next_relevant_brick->outputs[0]);
		if (unlikely(status < 0)) {
			MARS_ERR("connect failed\n");
			goto done;
		}
		trans_brick->new_input_nr = next_nr;
		MARS_INF("started switchover to '%s'\n", rot->next_relevant_log->d_path);
	}
done: ;
}
#endif

static
void _change_trans(struct mars_rotate *rot)
{
	struct trans_logger_brick *trans_brick = rot->trans_brick;
	
	MARS_DBG("do_replay = %d start_pos = %lld end_pos = %lld\n", trans_brick->do_replay, rot->start_pos, rot->end_pos);

	if (trans_brick->do_replay) {
		trans_brick->replay_start_pos = rot->start_pos;
		trans_brick->replay_end_pos = rot->end_pos;
	} else {
#ifdef CONFIG_MARS_LOGROT
		_rotate_trans(rot);
#endif
	}
}

static
int _start_trans(struct mars_rotate *rot)
{
	struct trans_logger_brick *trans_brick = rot->trans_brick;
	struct trans_logger_input *trans_input;
	int nr;
	int status;

	/* Internal safety checks
	 */
	status = -EINVAL;
	if (unlikely(!trans_brick)) {
		MARS_ERR("logger instance does not exist\n");
		goto done;
	}
	nr = trans_brick->new_input_nr;
	trans_input = trans_brick->inputs[nr];
	if (unlikely(!trans_input)) {
		MARS_ERR("log input %d does not exist\n", nr);
		goto done;
	}
	if (unlikely(!rot->aio_brick || !rot->relevant_log)) {
		MARS_ERR("something is missing, this should not happen\n");
		goto done;
	}

	/* Update status when already working
	 */
	if (trans_brick->power.button || !trans_brick->power.led_off) {
		_change_trans(rot);
		status = 0;
		goto done;
	}

	/* Really start transaction logging now.
	 * Check some preconditions.
	 */
	if (unlikely(rot->relevant_brick)) {
		MARS_ERR("log aio brick already present, this should not happen\n");
		goto done;
	}

	/* For safety, disconnect old connection first
	 */
	if (trans_input->connect) {
		(void)generic_disconnect((void*)trans_input);
	}

	/* Open new transaction log
	 */
	rot->relevant_brick =
		make_brick_all(rot->global,
			       rot->relevant_log,
			       false,
			       NULL,
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
	if (!rot->relevant_brick) {
		MARS_ERR("log aio brick not open\n");
		goto done;
	}

	/* Connect to new transaction log
	 */
	status = generic_connect((void*)trans_input, (void*)rot->relevant_brick->outputs[0]);
	if (status < 0) {
		goto done;
	}

	/* Supply all relevant parameters
	 */
	trans_brick->do_replay = rot->do_replay;
	_init_trans_input(trans_input, rot->relevant_log);
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
		(void)_update_all_links(rot->global, parent_path, trans_brick, NULL, 0, false, true);
		for (i = TL_INPUT_LOG1; i <= TL_INPUT_LOG2; i++) {
			struct trans_logger_input *trans_input;
			trans_input = trans_brick->inputs[i];
			if (trans_input) {
				if (trans_input->connect)
					(void)generic_disconnect((void*)trans_input);
				__exit_trans_input(trans_input);
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
	int status = -EINVAL;

	CHECK_PTR(parent, done);
	rot = parent->d_private;
	CHECK_PTR(rot, done);
	trans_brick = rot->trans_brick;
	status = 0;
	if (!trans_brick) {
		MARS_DBG("nothing to do\n");
		goto done;
	}

	/* Stopping is also possible in case of errors
	 */
	if (trans_brick->power.button && trans_brick->power.led_on && !trans_brick->power.led_off) {
		bool do_stop = true;
		if (trans_brick->do_replay) {
			do_stop = trans_brick->replay_code != 0 || !_check_allow(global, parent, "allow-replay");
		} else {
			do_stop = !rot->is_primary;
		}

		MARS_DBG("replay_code = %d do_stop = %d\n", trans_brick->replay_code, (int)do_stop);

		if (do_stop) {
			status = _stop_trans(rot, parent->d_path);
#ifdef CONFIG_MARS_LOGROT
		} else {
			_change_trans(rot);
#endif
			(void)_update_all_links(global, parent->d_path, trans_brick, NULL, 0, false, do_stop);
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

		do_start = (!rot->do_replay ||
			    (rot->start_pos != rot->end_pos && _check_allow(global, parent, "allow-replay")));
		MARS_DBG("do_start = %d\n", (int)do_start);

		if (do_start) {
			status = _start_trans(rot);
#if 0 // silly idea!
			if (status >= 0) {
				status = _update_all_links(global, parent->d_path, trans_brick, NULL, 0, true, true);
			}
#endif
		}
	} else {
		MARS_DBG("trans_brick %d %d %d\n", trans_brick->power.button, trans_brick->power.led_on, trans_brick->power.led_off);
	}

done:
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

	if (!global->global_power.button) {
		status = 0;
		goto done;
	}

	parent = dent->d_parent;
	CHECK_PTR(parent, done);
	rot = parent->d_private;
	CHECK_PTR(rot, done);

	rot->todo_primary =
		global->global_power.button && dent->new_link && !strcmp(dent->new_link, my_id());
	rot->is_primary =
		rot->if_brick && !rot->if_brick->power.led_off;
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
	if (mars_find_brick(global, NULL, dent->d_path)) {
		goto done;
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

	status = _parse_args(dent, dent->new_link, 1);
	if (status < 0) {
		MARS_DBG("fail\n");
		goto done;
	}

	switch_on =
		(rot->if_brick && atomic_read(&rot->if_brick->inputs[0]->open_count) > 0) ||
		(rot->todo_primary &&
		 !rot->trans_brick->do_replay &&
		 rot->trans_brick->power.led_on);
	if (!global->global_power.button || global->exhausted) {
		switch_on = false;
	}

	dev_brick =
		make_brick_all(global,
			       dent,
			       false,
			       _set_if_params,
			       NULL,
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

	status = __make_copy(global, dent, switch_path, copy_path, dent->d_parent->d_path, (const char**)dent->d_argv, -1, NULL);

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
		rot->try_sync = true;
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
		MARS_WRN("cannot determine peer, symlink '%s' is missing\n", tmp);
		status = -ENOENT;
		goto done;
	}
	peer = connect_dent->new_link;

	/* Start copy
	 */
	src = path_make("data-%s@%s", peer, peer);
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
		status = __make_copy(global, dent, do_start ? switch_path : "", copy_path, dent->d_parent->d_path, argv, start_pos, &copy);
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
	int max_serial = 0;

	if (!global || !dent || !dent->new_link) {
		goto done;
	}
	target = _mars_find_dent(global, dent->new_link);
	if (target) {
		mars_unlink(dent->new_link);
		target->d_killme = true;
		MARS_DBG("target '%s' deleted and marked for removal\n", dent->new_link);
	} else {
		MARS_DBG("target '%s' does no longer exist\n", dent->new_link);
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

///////////////////////////////////////////////////////////////////////

// the order is important!
enum {
	// root element: this must have index 0
	CL_ROOT,
	// global todos
	CL_GLOBAL_TODO,
	CL_GLOBAL_TODO_DELETE,
	CL_GLOBAL_TODO_ITEMS,
	// replacement for DNS in kernelspace
	CL_IPS,
	CL_PEERS,
	CL_ALIVE,
	// resource definitions
	CL_RESOURCE,
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
	CL_PRIMARY,
	CL__FILE,
	CL_SYNC,
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
	[CL_GLOBAL_TODO_ITEMS] = {
		.cl_name = "",
		.cl_len = 0, // catch any
		.cl_type = 'l',
		.cl_father = CL_GLOBAL_TODO,
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

	/* Directory containing all items of a resource
	 */
	[CL_RESOURCE] = {
		.cl_name = "resource-",
		.cl_len = 9,
		.cl_type = 'd',
		.cl_father = CL_ROOT,
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
static int light_checker(struct mars_dent *parent, const char *_name, int namlen, unsigned int d_type, int *prefix, int *serial)
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
				status = -1;
				goto done;
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
				status = -1;
				goto done;
			}
		}

		// all ok
		status = class;
		goto done;
	}

	//MARS_DBG("no match for '%s' '%s'\n", path, name);

done:
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
				MARS_ERR_ONCE(dent, "'%s' is not at the root of the hierarchy\n", dent->d_path);
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

#ifdef STAT_DEBUGGING
static
void _show_one(struct mars_brick *test, int *brick_count)
{
	int i;
	if (*brick_count) {
		MARS_STAT("---------\n");
	}
	MARS_STAT("BRICK type = %s path = '%s' name = '%s' button = %d off = %d on = %d\n", SAFE_STR(test->type->type_name), SAFE_STR(test->brick_path), SAFE_STR(test->brick_name), test->power.button, test->power.led_off, test->power.led_on);
	(*brick_count)++;
	if (test->ops && test->ops->brick_statistics) {
		char *info = test->ops->brick_statistics(test, 0);
		if (info) {
			MARS_STAT("  %s", info);
			brick_string_free(info);
		}
	}
	for (i = 0; i < test->type->max_inputs; i++) {
		struct mars_input *input = test->inputs[i];
		struct mars_output *output = input ? input->connect : NULL;
		if (output) {
			MARS_STAT("    input %d connected with %s path = '%s' name = '%s'\n", i, SAFE_STR(output->brick->type->type_name), SAFE_STR(output->brick->brick_path), SAFE_STR(output->brick->brick_name));
		} else {
			MARS_STAT("    input %d not connected\n", i);
		}
	}
	for (i = 0; i < test->type->max_outputs; i++) {
		struct mars_output *output = test->outputs[i];
		if (output) {
			MARS_STAT("    output %d nr_connected = %d\n", i, output->nr_connected);
		}
	}
}

static
void _show_statist(struct mars_global *global)
{
	struct list_head *tmp;
	int dent_count = 0;
	int brick_count = 0;

	brick_mem_statistics();

	down_read(&global->brick_mutex);
	MARS_STAT("================================== ordinary bricks:\n");
	for (tmp = global->brick_anchor.next; tmp != &global->brick_anchor; tmp = tmp->next) {
		struct mars_brick *test;
		test = container_of(tmp, struct mars_brick, global_brick_link);
		_show_one(test, &brick_count);
	}
	MARS_STAT("================================== server bricks:\n");
	for (tmp = global->server_anchor.next; tmp != &global->server_anchor; tmp = tmp->next) {
		struct mars_brick *test;
		test = container_of(tmp, struct mars_brick, global_brick_link);
		_show_one(test, &brick_count);
	}
	up_read(&global->brick_mutex);
	
	MARS_STAT("================================== dents:\n");
	down_read(&global->dent_mutex);
	for (tmp = global->dent_anchor.next; tmp != &global->dent_anchor; tmp = tmp->next) {
		struct mars_dent *dent;
		struct list_head *sub;
		dent = container_of(tmp, struct mars_dent, dent_link);
		MARS_STAT("dent %d '%s' '%s' stamp=%ld.%09ld\n", dent->d_class, SAFE_STR(dent->d_path), SAFE_STR(dent->new_link), dent->new_stat.mtime.tv_sec, dent->new_stat.mtime.tv_nsec);
		dent_count++;
		for (sub = dent->brick_list.next; sub != &dent->brick_list; sub = sub->next) {
			struct mars_brick *test;
			test = container_of(sub, struct mars_brick, dent_brick_link);
			MARS_STAT("  owner of brick '%s'\n", SAFE_STR(test->brick_path));
		}
	}
	up_read(&global->dent_mutex);

	MARS_INF("==================== STATISTICS: %d dents, %d bricks, %lld KB free\n", dent_count, brick_count, global->remaining_space);
}
#endif

static
void _make_alivelink(const char *name, bool alive)
{
	char *src = alive ? "1" : "0";
	char *dst = path_make("/mars/%s-%s", name, my_id());
	mars_symlink(src, dst, NULL, 0);
	brick_string_free(dst);
}

static struct mars_global _global = {
	.dent_anchor = LIST_HEAD_INIT(_global.dent_anchor),
	.brick_anchor = LIST_HEAD_INIT(_global.brick_anchor),
	.server_anchor = LIST_HEAD_INIT(_global.server_anchor),
	.global_power = {
		.button = true,
	},
	.dent_mutex = __RWSEM_INITIALIZER(_global.dent_mutex),
	.brick_mutex = __RWSEM_INITIALIZER(_global.brick_mutex),
	.main_event = __WAIT_QUEUE_HEAD_INITIALIZER(_global.main_event),
};

static int light_thread(void *data)
{
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
		bool exhausted;

		MARS_DBG("-------- NEW ROUND ---------\n");
		msleep(100);

		_global.global_power.button = !kthread_should_stop();
		_make_alivelink("alive", _global.global_power.button);

		_global.remaining_space = mars_remaining_space("/mars");
		exhausted = EXHAUSTED(_global.remaining_space);
		_global.exhausted = exhausted;
		_make_alivelink("exhausted", exhausted);
		if (exhausted)
			MARS_WRN("EXHAUSTED filesystem space = %lld, STOPPING IO\n", _global.remaining_space);


#if 1
		if (!_global.global_power.button) {
			mars_kill_brick_all(&_global, &_global.server_anchor, false);
		}
#endif

		MARS_DBG("-------- start worker ---------\n");
		status = mars_dent_work(&_global, "/mars", sizeof(struct mars_dent), light_checker, light_worker, &_global, 3);
		MARS_DBG("-------- worker status = %d\n", status);

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

		_show_status_all(&_global);
#ifdef STAT_DEBUGGING
		_show_statist(&_global);
#endif

		msleep(500);

		wait_event_interruptible_timeout(_global.main_event, _global.main_trigger, CONFIG_MARS_SCAN_INTERVAL * HZ);
		_global.main_trigger = false;
	}

done:
	MARS_INF("-------- cleaning up ----------\n");
	mars_remote_trigger();
	msleep(2000);

	mars_kill_brick_all(&_global, &_global.server_anchor, false);
	mars_free_dent_all(&_global, &_global.dent_anchor);
	mars_kill_brick_all(&_global, &_global.brick_anchor, false);

	_show_status_all(&_global);
#ifdef STAT_DEBUGGING
	_show_statist(&_global);
#endif

	mars_global = NULL;
	main_thread = NULL;

	MARS_INF("-------- done status = %d ----------\n", status);
	//cleanup_mm();
	return status;
}

static struct mem_reservation global_reserve = {
	.amount = {
		[1] = 32,
		[2] = 32,
		[3] = 32,
		[4] = 32,
		[5] = 32,
		[6] = 64,
		[7] = 2,
		[8] = 2,
		[9] = 1,
		[10] = 1,
		[11] = 0,
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
	struct task_struct *thread;

	MARS_DBG("====================== stopping everything...\n");
	// TODO: make this thread-safe.
	thread = main_thread;
	if (thread) {
		main_thread = NULL;
		MARS_DBG("=== stopping light thread...\n");
		MARS_INF("stopping thread...\n");
		mars_trigger();
		kthread_stop(thread);
		put_task_struct(thread);
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
}

static int __init init_light(void)
{
	int status = 0;
	struct task_struct *thread;

	init_say(); // this must come first

#ifdef CONFIG_MARS_HAVE_BIGMODULE
	/* be careful: order is important!
	 */
	DO_INIT(brick_mem);
	DO_INIT(brick);
	DO_INIT(mars);
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

	thread = kthread_create(light_thread, NULL, "mars_light");
	if (IS_ERR(thread)) {
		status = PTR_ERR(thread);
		goto done;
	}
	get_task_struct(thread);
	main_thread = thread;
	wake_up_process(thread);

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
