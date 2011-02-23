// (c) 2011 Thomas Schoebel-Theuer / 1&1 Internet AG

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING
//#define IO_DEBUGGING // here means: display full statistics

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/debug_locks.h>

#include <linux/major.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>

#define _STRATEGY
#include "mars.h"

#include <linux/kthread.h>
#include <linux/wait.h>

// used brick types
#include "mars_server.h"
#include "mars_client.h"
#include "mars_copy.h"
#include "mars_device_aio.h"
#include "mars_trans_logger.h"
#include "mars_if_device.h"

#define USE_TRANS_LOGGER // disable this ONLY FOR TESTING

static struct task_struct *main_thread = NULL;

struct light_dent {
	MARS_DENT(light_dent);
};

typedef int (*light_worker_fn)(void *buf, struct light_dent *dent);

struct light_class {
	char *cl_name;
	int    cl_len;
	char   cl_type;
	bool   cl_hostcontext;
	bool   cl_serial;
	int    cl_father;
	light_worker_fn cl_forward;
	light_worker_fn cl_backward;
};

static
struct mars_brick *make_brick(struct mars_global *global, const void *_brick_type, const char *path, const char *name)
{
	struct mars_brick *res;
	MARS_DBG("type = '%s' path = '%s' name = '%s'\n", ((struct generic_brick_type*)_brick_type)->type_name, path, name);
	res = mars_make_brick(global, _brick_type, path, name);
	MARS_DBG("brick = %p\n", res);
	if (res) {
		mars_trigger();
	}
	return res;
}

static
int kill_brick(struct mars_brick *brick, int max_level)
{
	int i;
	int status;

	if (!brick) {
		MARS_ERR("bad brick parameter\n");
		return -EINVAL;
	}

	// first check whether the brick is in use somewhere
	for (i = 0; i < brick->nr_outputs; i++) {
		if (brick->outputs[i]->nr_connected > 0) {
			MARS_DBG("brick '%s' not killable, output %i is used\n", brick->brick_name, i);
			return -EEXIST;
		}
	}

	MARS_DBG("===> killing brick name = '%s'\n", brick->brick_name);

	// start shutdown
	mars_power_button((void*)brick, false);
	status = brick->ops->brick_switch(brick);

	MARS_DBG("kill '%s' status = %d led_off = %d\n", brick->brick_name, status, brick->power.led_off);

	// wait until clean shutdown
	if (status >= 0 && brick->power.led_off) {
		int count = 0;
		struct mars_brick *prev[brick->nr_inputs];

		// remove from the global list => no longer visible
		down(&brick->global->mutex);
		list_del_init(&brick->brick_link);
		up(&brick->global->mutex);

		/* Disconnect all inputs.
		 * This must not start earlier, because during shutdown
		 * the inputs could be needed for cleanup operations etc.
		 */
		for (i = 0; i < brick->nr_inputs; i++) {
			if (brick->inputs[i]->connect) {
				prev[count++] = brick->inputs[i]->connect->brick;
				(void)generic_disconnect((void*)brick->inputs[i]);
			}
		}

#if 1
		/* recursively kill predecessors
		 */
		if (max_level > 0) {
			struct mars_brick *old = NULL;
			for (i = 0; i < count; i++) {
				if (!prev[i] || prev[i] == old || list_empty(&prev[i]->brick_link))
					continue;
				old = prev[i];
				status |= kill_brick(prev[i], max_level - 1);
#if 1
				msleep(500);
#endif
			}
		}
#endif

		/* This runs unchecked and may therefore leave memory remains,
		 * but we currently have no separate list for "zombies".
		 * TODO: do better.
		 */
#if 0 // TODO: debug locking crash
		(void)generic_brick_exit_full((void*)brick);
#endif
		mars_trigger();
	}
	return status;
}


///////////////////////////////////////////////////////////////////////

// internal helpers

static
void normalized_path(char *res, int len, struct light_dent *father, const char *prefix, const char *suffix)
{
	char *test;
	int prelen;

	test = strchr(prefix, '+');
	if (test) {
		test++;
		prelen = test - prefix;
		if (prelen >= len)
			goto done;
		memcpy(res, prefix, prelen);
		res += prelen;
		len -= prelen;
		prefix = test;
	}

	if (father && *prefix != '/') {
		prelen = strlen(father->d_path);
		if (prelen+1 >= len)
			goto done;
		memcpy(res, father->d_path, prelen);
		res += prelen;
		*res++ = '/';
		len -= prelen+1;
	}

	prelen = strlen(prefix);
	if (prelen >= len)
		goto done;
	memcpy(res, prefix, prelen);
	res += prelen;
	len -= prelen;

	prelen = strlen(suffix);
	if (prelen >= len)
		goto done;

	strncpy(res, suffix, len);
	res += prelen;
done:
	*res = '\0';
}

static
struct mars_brick *find_other(struct mars_global *global, const void *brick_type, struct light_dent *father, const char *prefix, const char *suffix)
{
	int len = (father ? father->d_pathlen : 0)
		+ strlen(prefix)
		+ strlen(suffix)
		+ 2;
	char fullpath[len];

	normalized_path(fullpath, len, father, prefix, suffix);
	MARS_DBG("searching for '%s'\n", fullpath);
	return mars_find_brick(global, brick_type, fullpath);
}

/* Create a new brick and connect its inputs to a set of predecessors.
 * Before starting that, check whether all predecessors exist and are healthy.
 */
static
struct mars_brick *make_all(struct mars_global *global,
			    const void *new_brick_type,
			    const char *new_path,
			    const char *new_name,
			    struct light_dent *father,
			    const void *brick_type[],
			    const char *prefix[],
			    const char *suffix[],
			    int count,
			    bool switch_on)
{
	struct mars_brick *brick;
	struct mars_brick *prev[count];
	int status = 0;
	int i;
	int len = (father ? father->d_pathlen : 0)
		+ strlen(new_path)
		+ 2;
	char fullpath[len];

	normalized_path(fullpath, len, father, new_path, "");

	// check whether all previous bricks exist and are healthy
	for (i = 0; i < count; i++) {
		prev[i] = find_other(global, brick_type[i], father, prefix[i], suffix[i]);
		if (!prev[i]) {
			MARS_DBG("previous brick '%s' '%s' '%s' does not exist\n", father ? father->d_path : "", prefix[i], suffix[i]);
			return NULL;
		}
		if (!prev[i]->power.led_on) {
			MARS_DBG("previous brick '%s' '%s' '%s' not healthy\n", father ? father->d_path : "", prefix[i], suffix[i]);
			return NULL;
		}
	}

	// special case for client brick: treat network indirection
	if (new_brick_type == &client_brick_type) {
		struct mars_dent *test;
		char path[256];
		snprintf(path, sizeof(path), "/mars/ips/ip-%s", new_name);
		test = mars_find_dent(global, path);
		if (test && test->new_link) {
			MARS_DBG("translation '%s' => '%s'\n", new_name, test->new_link);
			new_name = test->new_link;
		}
	}

	// create it...
	brick = make_brick(global, new_brick_type, fullpath, new_name);
	if (unlikely(!brick)) {
		MARS_DBG("creation failed '%s' '%s'\n", fullpath, new_name);
		return NULL;
	}

	// special case for aio: file name is treated different IMPROVEME!
	if (new_brick_type == &device_aio_brick_type) {
		brick->outputs[0]->output_name = brick->brick_name;
	}

	// connect the wires
	for (i = 0; i < count; i++) {
		status = generic_connect((void*)brick->inputs[i], (void*)prev[i]->outputs[0]);
		if (unlikely(status < 0)) {
			MARS_ERR("'%s' '%s' cannot connect input %d\n", fullpath, new_name, i);
			goto err;
		}
	}
	if (!brick->ops) {
		MARS_ERR("cannot start '%s' '%s'\n", fullpath, new_name);
		goto err;
	}

	// switch on (may fail silently, but responsibility is at the workers)
	if (switch_on) {
		mars_power_button((void*)brick, true);
		status = brick->ops->brick_switch(brick);
		MARS_DBG("switch on status = %d\n", status);
	}
	return brick;

err:
	status = kill_brick(brick, 0);
	if (status >= 0) {
		brick = NULL;
	}
	return brick;
}

#define MARS_DELIM ','

static int _parse_args(struct light_dent *dent, char *str, int count)
{
	int i;
	int status = -EINVAL;
	if (!str)
		goto done;
	if (!dent->d_args) {
		dent->d_args = kstrdup(str, GFP_MARS);
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
		tmp = kzalloc(len+1, GFP_MARS);
		if (!tmp) {
			status = -ENOMEM;
			goto done;
		}
		if (dent->d_argv[i]) {
			kfree(dent->d_argv[i]);
		}
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


///////////////////////////////////////////////////////////////////////

// remote workers

struct mars_peerinfo {
	char *peer;
	char *path;
	struct socket *socket;
	struct task_struct *thread;
	wait_queue_head_t event;
	light_worker_fn worker;
	int maxdepth;
};

static int run_bones(void *buf, struct light_dent *dent)
{
	int status = 0;
	//struct mars_peerinfo *peer = buf;

	if (S_ISDIR(dent->new_stat.mode)) {
		if (strncmp(dent->d_name, "resource-", 9)) {
			MARS_DBG("ignoring directory '%s'\n", dent->d_path);
			return 0;
		}
		status = mars_mkdir(dent->d_path);
		MARS_DBG("create directory '%s' status = %d\n", dent->d_path, status);
	} else if (S_ISLNK(dent->new_stat.mode) && dent->new_link) {
		status = mars_symlink(dent->new_link, dent->d_path, &dent->new_stat.mtime);
		MARS_DBG("create symlink '%s' -> '%s' status = %d\n", dent->d_path, dent->new_link, status);
	} else {
		MARS_DBG("ignoring '%s'\n", dent->d_path);
	}
	return status;
}

///////////////////////////////////////////////////////////////////////

// remote working infrastructure

static void _peer_cleanup(struct mars_peerinfo *peer)
{
	if (peer->socket) {
		kernel_sock_shutdown(peer->socket, SHUT_WR);
		peer->socket = NULL;
	}
	//...
}

static int remote_thread(void *data)
{
	struct mars_peerinfo *peer = data;
	struct sockaddr_storage sockaddr = {};
	int status;

	if (!peer)
		return -1;

	MARS_INF("-------- remote thread starting on peer '%s'\n", peer->peer);

	//fake_mm();

	status = mars_create_sockaddr(&sockaddr, peer->peer);
	if (unlikely(status < 0)) {
		MARS_ERR("unusable remote address '%s'\n", peer->peer);
		goto done;
	}

        while (!kthread_should_stop()) {
		LIST_HEAD(tmp_list);
		struct mars_cmd cmd = {
			.cmd_code = CMD_GETENTS,
			.cmd_str1 = peer->path,
			.cmd_int1 = peer->maxdepth,
		};

		if (!peer->socket) {
			status = mars_create_socket(&peer->socket, &sockaddr, false);
			if (unlikely(status < 0)) {
				peer->socket = NULL;
				MARS_INF("no connection to '%s'\n", peer->peer);
				msleep(5000);
				continue;
			}
			MARS_DBG("successfully opened socket to '%s'\n", peer->peer);
			continue;
		}

		status = mars_send_struct(&peer->socket, &cmd, mars_cmd_meta);
		if (unlikely(status < 0)) {
			MARS_ERR("communication error on send, status = %d\n", status);
			_peer_cleanup(peer);
			msleep(5000);
			continue;
		}

		status = mars_recv_dent_list(&peer->socket, &tmp_list);
		if (unlikely(status < 0)) {
			MARS_ERR("communication error on receive, status = %d\n", status);
			_peer_cleanup(peer);
			msleep(5000);
			continue;
		}

		MARS_DBG("AHA!!!!!!!!!!!!!!!!!!!!\n");

		{
			struct list_head *tmp;
			for (tmp = tmp_list.next; tmp != &tmp_list; tmp = tmp->next) {
				struct light_dent *dent = container_of(tmp, struct light_dent, sub_link);
				if (!dent->d_path) {
					MARS_DBG("NULL\n");
					continue;
				}
				MARS_DBG("path = '%s'\n", dent->d_path);
				if (!peer->worker)
					continue;
				status = peer->worker(peer, dent);
			}
		}

		//...

		mars_dent_free_all(&tmp_list);

		if (!kthread_should_stop())
			msleep(10 * 1000);
	}

	MARS_INF("-------- remote thread terminating\n");

	_peer_cleanup(peer);

done:
	//cleanup_mm();
	return 0;
}

///////////////////////////////////////////////////////////////////////

// helpers for worker functions

static int _kill_peer(void *buf, struct light_dent *dent)
{
	struct mars_global *global = buf;
	struct mars_peerinfo *peer = dent->d_private;

	if (global->global_power.button) {
		return 0;
	}
	if (!peer) {
		return 0;
	}
	if (!peer->thread) {
		MARS_ERR("oops, remote thread is not running - doing cleanup myself\n");
		_peer_cleanup(peer);
		dent->d_private = NULL;
		return -1;

	}
	kthread_stop(peer->thread);
	dent->d_private = NULL;
	return 0;
}

static int _make_peer(void *buf, struct light_dent *dent, char *mypeer, char *path, light_worker_fn worker)
{
	static int serial = 0;
	struct mars_global *global = buf;
	struct mars_peerinfo *peer;
	int status = 0;

	if (!global->global_power.button || !dent->d_parent || !dent->new_link) {
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
		dent->d_private = kzalloc(sizeof(struct mars_peerinfo), GFP_MARS);
		if (!dent->d_private) {
			MARS_ERR("no memory for peer structure\n");
			return -1;
		}

		peer = dent->d_private;
		peer->peer = mypeer;
		peer->path = path;
		peer->worker = worker;
		peer->maxdepth = 2;
		init_waitqueue_head(&peer->event);
	}
	peer = dent->d_private;
	if (!peer->thread) {
		peer->thread = kthread_create(remote_thread, peer, "mars_remote%d", serial++);
		if (unlikely(IS_ERR(peer->thread))) {
			MARS_ERR("cannot start peer thread, status = %d\n", (int)PTR_ERR(peer->thread));
			peer->thread = NULL;
			return -1;
		}
		wake_up_process(peer->thread);
	}

done:
	return status;
}

static int _kill_remote(void *buf, struct light_dent *dent)
{
	return _kill_peer(buf, dent);
}

static int _make_remote(void *buf, struct light_dent *dent)
{
	return _make_peer(buf, dent, NULL, "/mars", NULL);
}

static int kill_scan(void *buf, struct light_dent *dent)
{
	return _kill_peer(buf, dent);
}

static int make_scan(void *buf, struct light_dent *dent)
{
	return _make_peer(buf, dent, "/mars/ips", "/mars", run_bones);
}


static
int _kill_default(void *buf, struct light_dent *dent, int maxlevel)
{
	struct mars_global *global = buf;
	struct mars_brick *brick;

	if (global->global_power.button) {
		return 0;
	}
	brick = mars_find_brick(global, NULL, dent->d_path);
	if (!brick) {
		return 0;
	}
	return kill_brick(brick, maxlevel);
}


static
int kill_default(void *buf, struct light_dent *dent)
{
	return _kill_default(buf, dent, 0);
}

static
int kill_all(void *buf, struct light_dent *dent)
{
	return _kill_default(buf, dent, 999);
}


///////////////////////////////////////////////////////////////////////

// handlers / helpers for logfile rotation

struct mars_rotate {
	struct light_dent *replay_link;
	struct light_dent *aio_dent;
	struct device_aio_brick *aio_brick;
	struct mars_info aio_info;
	struct trans_logger_brick *trans_brick;
	struct light_dent *relevant_log;
	struct light_dent *current_log;
	struct light_dent *prev_log;
	struct light_dent *next_log;
	long long last_jiffies;
	loff_t start_pos;
	loff_t end_pos;
	int max_sequence;
	bool has_error;
	bool do_replay;
	bool is_primary;
	bool create_once;
};

static
void _create_new_logfile(char *path)
{
	struct file *f;
	const int flags = O_RDWR | O_CREAT | O_EXCL;
	const int prot = 0600;
	mm_segment_t oldfs;

	oldfs = get_fs();
	set_fs(get_ds());
	f = filp_open(path, flags, prot);
	set_fs(oldfs);
	if (f) {
		filp_close(f, NULL);
		MARS_DBG("created empty logfile '%s'\n", path);
		mars_trigger();
	}
}

static
int _update_link(struct mars_rotate *rot, struct light_dent *parent, int sequence, loff_t pos)
{
	struct timespec now = {};
	char old[128] = {};
	char new[128] = {};
	int status = 0;
		

	snprintf(old, sizeof(old), "log-%09d-%s,%lld", sequence, my_id(), pos);
	snprintf(new, sizeof(new), "%s/replay-%s", parent->d_path, my_id());

	get_lamport(&now);
	status = mars_symlink(old, new, &now);
	if (status < 0) {
		MARS_ERR("cannot create symlink '%s' -> '%s' status = %d\n", old, new, status);
	} else {
		MARS_DBG("make symlink '%s' -> '%s' status = %d\n", old, new, status);
	}
	if (status >= 0) {
		rot->last_jiffies = jiffies;
	}
	return status;
}

/* This must be called once at every round of logfile checking.
 */
static
int make_log_init(void *buf, struct light_dent *parent)
{
	struct mars_global *global = buf;
	struct mars_brick *aio_brick;
	struct mars_brick *trans_brick;
	struct mars_rotate *rot = parent->d_private;
	struct light_dent *replay_link;
	struct light_dent *aio_dent;
	struct mars_output *output;
	char tmp[128] = {};
	int status;

	if (!rot) {
		rot = kzalloc(sizeof(struct mars_rotate), GFP_MARS);
		parent->d_private = rot;
		if (!rot) {
			MARS_ERR("cannot allocate rot structure\n");
			status = -ENOMEM;
			goto done;
		}
	}

	rot->replay_link = NULL;
	rot->aio_dent = NULL;
	rot->aio_brick = NULL;
	rot->relevant_log = NULL;
	rot->prev_log = NULL;
	rot->next_log = NULL;
	rot->max_sequence = 0;
	rot->has_error = false;

	/* Fetch the replay status symlink.
	 * It must exist, and its value will control everything.
	 */
	normalized_path(tmp, sizeof(tmp), parent, "replay-", my_id());

	replay_link = (void*)mars_find_dent(global, tmp);
	if (!replay_link || !replay_link->new_link) {
		MARS_ERR("replay status symlink '%s' does not exist (%p)\n", tmp, replay_link);
		status = -ENOENT;
		goto done;
	}

	status = _parse_args(replay_link, replay_link->new_link, 2);
	if (status < 0) {
		goto done;
	}
	rot->replay_link = replay_link;

	/* Fetch the referenced AIO dentry.
	 */
	normalized_path(tmp, sizeof(tmp), parent, replay_link->d_argv[0], "");

	aio_dent = (void*)mars_find_dent(global, tmp);
	if (unlikely(!aio_dent)) {
		MARS_ERR("logfile '%s' does not exist\n", tmp);
		status = -ENOENT;
		if (rot->is_primary) { // try to create an empty logfile
			_create_new_logfile(tmp);
		}
		goto done;
	}
	rot->aio_dent = aio_dent;

	/* Fetch / make the AIO brick instance
	 */
	aio_brick = mars_find_brick(global, &device_aio_brick_type, tmp);
	MARS_DBG("search for '%s' -> found %p\n", tmp, aio_brick);
	if (!aio_brick) {
		aio_brick =
			make_all(global,
				 &device_aio_brick_type,
				 tmp,
				 tmp,
				 parent,
				 (const void *[]){},
				 (const char *[]){},
				 (const char *[]){},
				 0,
				 true);
		if (!aio_brick) {
			MARS_ERR("cannot access '%s'\n", tmp);
			status = -EIO;
			goto done;
		}
	}
	rot->aio_brick = (void*)aio_brick;

	/* Fetch the actual logfile size
	 */
	output = aio_brick->outputs[0];
	status = output->ops->mars_get_info(output, &rot->aio_info);
	if (status < 0) {
		MARS_ERR("cannot get info on '%s'\n", tmp);
		goto done;
	}
	MARS_DBG("logfile '%s' size = %lld\n", tmp, rot->aio_info.current_size);

	/* Fetch / make the transaction logger
	 */
	trans_brick = mars_find_brick(global, &trans_logger_brick_type, parent->d_path);
	MARS_DBG("search for transaction logger '%s' -> found %p\n", parent->d_path, trans_brick);
	if (!trans_brick) {
		/* We deliberately "forget" to connect the log input here.
		 * Will be carried out later in make_log().
		 * The final switch-on will be started in make_log_finalize().
		 */
		trans_brick =
			make_all(global,
				 &trans_logger_brick_type,
				 parent->d_path,
				 parent->d_path,
				 parent,
				 (const void *[]){&device_aio_brick_type},
				 (const char *[]){"data-"},
				 (const char *[]){my_id()},
				 1,
				 false);
		status = -ENOENT;
		if (!trans_brick)
			goto done;
	}
	rot->trans_brick = (void*)trans_brick;
	/* For safety, default is to try an (unnecessary) replay in case
	 * something goes wrong later.
	 */
	rot->do_replay = true;

	status = 0;

done:
	return status;
}


/* Internal helper. Return codes:
 * ret < 0 : error
 * ret == 0 : not relevant
 * ret == 1 : relevant, no transaction replay
 * ret == 2 : relevant for transaction replay
 * ret == 3 : relevant for appending
 */
static
int _check_logging_status(struct mars_global *global, struct light_dent *dent, long long *oldpos, long long *newpos)
{
	struct light_dent *parent = dent->d_parent;
	struct mars_rotate *rot = parent->d_private;
	int status = -EINVAL;

	CHECK_PTR(rot, done);

	status = 0;
	if (!rot->replay_link || !rot->aio_dent || !rot->aio_brick) {
		//MARS_DBG("nothing to do on '%s'\n", dent->d_path);
		goto done;
	}

	if (rot->aio_dent->d_serial != dent->d_serial) {
		//MARS_DBG("serial number %d not relevant\n", dent->d_serial);
		goto done;
	}

	if (sscanf(rot->replay_link->d_argv[1], "%lld", oldpos) != 1) {
		MARS_ERR("bad position argument '%s'\n", rot->replay_link->d_argv[1]);
		status = -EINVAL;
		goto done;
	}

	if (unlikely(rot->aio_info.current_size < *oldpos)) {
		MARS_ERR("oops, bad replay position attempted in logfile '%s' (file length %lld should never be smaller than requested position %lld, is your filesystem corrupted?) => please repair this by hand\n", rot->aio_dent->d_path, rot->aio_info.current_size, *oldpos);
		status = -EINVAL;
		goto done;
	}

	if (rot->aio_info.current_size > *oldpos) {
		MARS_INF("transaction log replay is necessary on '%s' from %lld to %lld\n", rot->aio_dent->d_path, *oldpos, rot->aio_info.current_size);
		*newpos = rot->aio_info.current_size;
		status = 2;
	} else if (rot->aio_info.current_size > 0) {
		MARS_INF("transaction log '%s' is already applied (would be usable for appending at position %lld, but a fresh log is needed for safety reasons)\n", rot->aio_dent->d_path, *oldpos);
		*newpos = rot->aio_info.current_size;
		status = 1;
	} else if (!rot->is_primary) {
		MARS_INF("empty transaction log '%s' would be usable, but I am not primary\n", rot->aio_dent->d_path);
		status = 0;
	} else {
		MARS_INF("empty transaction log '%s' is usable for me as a primary node\n", rot->aio_dent->d_path);
		status = 3;
	}

done:
	return status;
}


/* Note: this is strictly called in d_serial order.
 * This is important!
 */
static
int make_log(void *buf, struct light_dent *dent)
{
	struct mars_global *global = buf;
	struct light_dent *parent = dent->d_parent;
	struct mars_rotate *rot = parent->d_private;
	struct trans_logger_brick *trans_brick;
	struct light_dent *prev_log;
	loff_t start_pos = 0;
	loff_t end_pos = 0;
	int status = -EINVAL;

	CHECK_PTR(rot, err);

	status = 0;
	trans_brick = rot->trans_brick;
	if (!global->global_power.button || !dent->d_parent || !trans_brick || rot->has_error) {
		goto done;
	}

	if (dent->d_serial > rot->max_sequence) {
		rot->max_sequence = dent->d_serial;
	}

	/* Check for consecutiveness of logfiles
	 */
	prev_log = rot->next_log;
	if (prev_log && prev_log->d_serial + 1 != dent->d_serial) {
		MARS_ERR("transaction logs are not consecutive at '%s' (%d ~> %d)\n", dent->d_path, prev_log->d_serial, dent->d_serial);
		status = -EINVAL;
		goto done;
	}

	/* Skip any logfiles after the relevant one.
	 * This should happen only when replaying multiple logfiles
	 * in sequence, or when starting a new logfile for writing.
	 */
	if (rot->relevant_log) {
		if (rot->do_replay) {
			status = 0;
			goto ok;
		}
		if (rot->aio_dent->new_stat.size > 0) {
			MARS_ERR("oops, the new logfile '%s' is not empty -- for safety, I will not use it -- log rotation is disabled now\n", dent->d_path);
			status = -EINVAL;
			goto done;
		}
		MARS_DBG("considering next logfile '%s' for rotation\n", dent->d_path);
	}

	/* Find current logging status.
	 */
	status = _check_logging_status(global, dent, &start_pos, &end_pos);
	if (status < 0) {
		goto done;
	}
	/* Relevant or not?
	 */
	switch (status) {
	case 0: // not relevant
		goto ok;
	case 1: // relevant, but transaction replay already finished
		if (!trans_brick->power.button && !trans_brick->power.led_on && trans_brick->power.led_off) {
			_update_link(rot, dent->d_parent, dent->d_serial + 1, 0);
			mars_trigger();
		}
		status = -EAGAIN;
		goto done;
	case 2: // relevant for transaction replay
		MARS_DBG("replaying transaction log '%s' from %lld to %lld\n", dent->d_path, start_pos, end_pos);
		rot->do_replay = true;
		rot->start_pos = start_pos;
		rot->end_pos = end_pos;
		rot->relevant_log = dent;
		break;
	case 3: // relevant for appending
		MARS_DBG("appending to transaction log '%s'\n", dent->d_path);
		rot->do_replay = false;
		rot->start_pos = 0;
		rot->end_pos = 0;
		rot->relevant_log = dent;
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
		rot->has_error = true;
	}
err:
	return status;
}

static
int _start_trans(struct mars_rotate *rot)
{
	struct trans_logger_brick *trans_brick = rot->trans_brick;
	int status = 0;

	if (trans_brick->power.button) {
		goto done;
	}

	/* Internal safety checks
	 */
	status = -EINVAL;
	if (unlikely(!rot->aio_brick || !rot->relevant_log)) {
		MARS_ERR("something is missing, this should not happen\n");
		goto done;
	}

	/* For safety, disconnect old connection first
	 */
	if (trans_brick->inputs[1]->connect) {
		(void)generic_disconnect((void*)trans_brick->inputs[1]);
	}

	/* Connect to new transaction log
	 */
	status = generic_connect((void*)trans_brick->inputs[1], (void*)rot->aio_brick->outputs[0]);
	if (status < 0) {
		goto done;
	}

	/* Supply all relevant parameters
	 */
	trans_brick->sequence = rot->relevant_log->d_serial;
	trans_brick->do_replay = rot->do_replay;
	trans_brick->current_pos = rot->start_pos;
	trans_brick->start_pos = rot->start_pos;
	trans_brick->end_pos = rot->end_pos;

	/* Switch on....
	 */
	mars_power_button((void*)trans_brick, true);
	status = trans_brick->ops->brick_switch(trans_brick);
	MARS_DBG("status = %d\n", status);

done:
	return status;
}

static
int _stop_trans(struct mars_rotate *rot)
{
	struct trans_logger_brick *trans_brick = rot->trans_brick;
	int status = 0;

	if (!trans_brick->power.button) {
		goto done;
	}

	/* Switch off....
	 */
	mars_power_button((void*)trans_brick, false);
	status = trans_brick->ops->brick_switch(trans_brick);
	MARS_DBG("status = %d\n", status);
	if (status < 0) {
		goto done;
	}

	/* Disconnect old connection
	 */
	if (trans_brick->inputs[1]->connect && trans_brick->power.led_off) {
		(void)generic_disconnect((void*)trans_brick->inputs[1]);
	}

done:
	return status;
}

static
int make_log_finalize(struct mars_global *global, struct light_dent *parent)
{
	struct mars_rotate *rot = parent->d_private;
	struct trans_logger_brick *trans_brick;
	int status = -EINVAL;

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
		bool do_stop =
			(rot->do_replay || trans_brick->do_replay)
			? (trans_brick->current_pos == trans_brick->end_pos)
			: (rot->relevant_log && rot->relevant_log != rot->current_log);
		MARS_DBG("do_stop = %d\n", (int)do_stop);

		if (do_stop || (long long)jiffies > rot->last_jiffies + 5 * HZ) {
			status = _update_link(rot, parent, trans_brick->sequence, trans_brick->current_pos);
		}
		if (do_stop) {
			status = _stop_trans(rot);
		}
		goto done;
	}
	/* Special case: after a fresh start, when no logfile exists,
	 * create one. This is a thin exception from the rule that
	 * normally userspace should control what happens in MARS.
	 */
	if (!rot->relevant_log && rot->is_primary && !rot->has_error && rot->max_sequence > 0 && !rot->create_once) { // try to create an empty logfile
		char tmp[128] = {};
		snprintf(tmp, sizeof(tmp), "%s/log-%09d-%s", parent->d_path, rot->max_sequence + 1, my_id());
		_create_new_logfile(tmp);
		rot->create_once = true;
		msleep(1000);
		goto done;
	}
	/* Starting is only possible when no error ocurred.
	 */
	if (!rot->relevant_log || rot->has_error) {
		MARS_DBG("nothing to do\n");
		goto done;
	}

	/* Start when necessary
	 */
	if (!trans_brick->power.button && !trans_brick->power.led_on && trans_brick->power.led_off) {
		bool do_start = (!rot->do_replay || rot->start_pos != rot->end_pos);
		MARS_DBG("do_start = %d\n", (int)do_start);

		if (do_start) {
			status = _start_trans(rot);
			rot->current_log = rot->relevant_log;
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
int make_primary(void *buf, struct light_dent *dent)
{
	struct light_dent *parent = dent->d_parent;
	struct mars_rotate *rot = parent->d_private;
	int status = -EINVAL;

	CHECK_PTR(rot, done);

	rot->is_primary = (dent->new_link && !strcmp(dent->new_link, my_id()));
	status = 0;

done:
	return status;
}

static
int make_aio(void *buf, struct light_dent *dent)
{
	struct mars_global *global = buf;
	struct mars_brick *brick;
	struct device_aio_brick *_brick;
	int status;

	if (!global->global_power.button) {
		return 0;
	}
	if (mars_find_brick(global, &device_aio_brick_type, dent->d_path)) {
		return 0;
	}
	brick = make_brick(global, &device_aio_brick_type, dent->d_path, dent->d_path);
	if (!brick)
		return -1;
	brick->outputs[0]->output_name = dent->d_path;
	mars_power_button((void*)brick, true);
	_brick = (void*)brick;
	_brick->outputs[0]->o_fdsync = true;
	status = brick->ops->brick_switch(brick);
	if (status < 0) {
		kill_default(buf, dent);
	}
	return status;
}

static int make_dev(void *buf, struct light_dent *dent)
{
	struct mars_global *global = buf;
	struct light_dent *parent = dent->d_parent;
	struct mars_rotate *rot = parent->d_private;
	struct mars_brick *dev_brick;
	int status = 0;

	if (!global->global_power.button || !dent->d_parent || !dent->new_link) {
		MARS_DBG("nothing to do\n");
		goto done;
	}

#ifdef USE_TRANS_LOGGER
	status = make_log_finalize(global, dent->d_parent);
	if (status < 0) {
		MARS_DBG("logger not initialized\n");
		goto done;
	}
	if (!rot || !rot->is_primary) {
		MARS_DBG("I am not primary, don't show the device\n");
		goto done;
	}
	if (!rot->trans_brick || rot->trans_brick->do_replay || !rot->trans_brick->power.led_on || rot->trans_brick->power.led_off) {
		MARS_DBG("transaction logger not ready for writing\n");
		goto done;
	}
#endif

	status = _parse_args(dent, dent->new_link, 1);
	if (status < 0) {
		goto done;
	}
	dev_brick = mars_find_brick(global, &if_device_brick_type, dent->d_path);
	MARS_DBG("search for '%s' -> found %p\n", dent->d_path, dev_brick);
	if (!dev_brick) {
		dev_brick =
			make_all(global,
				 &if_device_brick_type,
				 dent->d_path,
				 dent->d_argv[0],
				 dent->d_parent,
#ifdef USE_TRANS_LOGGER
				 (const void *[]){&trans_logger_brick_type},
				 (const char *[]){dent->d_parent->d_path},
				 (const char *[]){""},
#else // direct connection, ONLY FOR TESTING!!!
				 (const void *[]){&device_aio_brick_type},
				 (const char *[]){"data-"},
				 (const char *[]){my_id()},
#endif
				 1,
				 true);
		if (!dev_brick)
			return -1;
	}

done:
	return status;
}

static int _make_direct(void *buf, struct light_dent *dent)
{
	struct mars_global *global = buf;
	struct mars_brick *brick;
	int status;

	if (!global->global_power.button || !dent->d_parent || !dent->new_link) {
		return 0;
	}
	status = _parse_args(dent, dent->new_link, 2);
	if (status < 0) {
		goto done;
	}
	brick = mars_find_brick(global, &client_brick_type, dent->d_argv[0]);
	MARS_DBG("search for '%s' -> found %p\n", dent->d_argv[0], brick);
	if (!brick) {
		brick = make_all(global,
				 &client_brick_type,
				 dent->d_argv[0],
				 dent->d_argv[0],
				 dent->d_parent,
				 (const void *[]){},
				 (const char *[]){},
				 (const char *[]){},
				 0,
				 true);
		status = -1;
		if (!brick)
			goto done;
	}
	brick = mars_find_brick(global, &if_device_brick_type, dent->d_path);
	MARS_DBG("search for '%s' -> found %p\n", dent->d_path, brick);
	if (!brick) {
		brick = make_all(global,
				 &if_device_brick_type,
				 dent->d_path,
				 dent->d_argv[1],
				 dent->d_parent,
				 (const void *[]){&client_brick_type},
				 (const char *[]){dent->d_argv[0]},
				 (const char *[]){""},
				 1,
				 true);
		status = -1;
		if (!brick)
			goto done;
	}
	status = 0;
done:
	MARS_DBG("status = %d\n", status);
	return status;
}

static
int __make_copy(struct mars_global *global, struct light_dent *parent, char *path, char *argv[])
{
	char tmp[128];
	char *new_argv[4];
	struct mars_brick *copy;
	struct copy_brick *_copy;
	struct mars_output *output[2] = {};
	struct mars_info info[2] = {};
	int i;
	int status = -1;

	for (i = 0; i < 2; i++) {
		char *target = argv[i];
		struct mars_brick *new = NULL;

		new_argv[i * 2] = target;
		new_argv[i * 2 + 1] = target;
		if (*target == '/') { // local
			new = mars_find_brick(global, &device_aio_brick_type, target);
			MARS_DBG("search for local '%s' -> found %p\n", target, new);
		} else { // remote
			new = mars_find_brick(global, &client_brick_type, target);
			MARS_DBG("search for remote '%s' -> found %p\n", target, new);
			if (!new) {
				snprintf(tmp, sizeof(tmp), "%s_copy", target);
				new_argv[i * 2 + 1] = tmp;
				/* 1st client instance is for data IO
				 */
				new = make_all(global,
					       &client_brick_type,
					       target,
					       target,
					       parent,
					       (const void *[]){},
					       (const char *[]){},
					       (const char *[]){},
					       0,
					       true);
				if (!new) {
					MARS_DBG("cannot instantiate\n");
					goto done;
				}
				/* 2nd client instance is for background copy IO
				 */
				new = make_all(global,
					       &client_brick_type,
					       tmp,
					       target,
					       parent,
					       (const void *[]){},
					       (const char *[]){},
					       (const char *[]){},
					       0,
					       true);
			}
		}
		if (!new) {
			MARS_DBG("cannot instantiate\n");
			goto done;
		}
		output[i] = new->outputs[0];
	}

	copy = mars_find_brick(global, &copy_brick_type, path);
	MARS_DBG("search for copy brick '%s' -> found %p\n", path, copy);
	if (!copy) {
		copy = make_all(global,
				&copy_brick_type,
				path,
				path,
				parent,
				(const void *[]){NULL,NULL,NULL,NULL},
				(const char *[]){new_argv[0],new_argv[1],new_argv[2],new_argv[3]},
				(const char *[]){"","","",""},
				4, false);
		MARS_DBG("copy brick = %p\n", copy);
		if (!copy)
			goto done;

	}

	/* Determine the copy area
	 */
	for (i = 0; i < 2; i++) {
		status = output[i]->ops->mars_get_info(output[i], &info[i]);
		if (status < 0) {
			MARS_ERR("cannot determine current size of\n");
			goto done;
		}
	}
	_copy = (void*)copy;
	_copy->copy_start = info[1].current_size;
	MARS_DBG("copy_start = %lld\n", _copy->copy_start);
	_copy->copy_end = info[0].current_size;
	MARS_DBG("copy_end = %lld\n", _copy->copy_end);
	mars_power_button((void*)copy, true);
	status = copy->ops->brick_switch(copy);
	MARS_DBG("copy switch status = %d\n", status);
	status = 0;

done:
	MARS_DBG("status = %d\n", status);
	return status;
}

static int _make_copy(void *buf, struct light_dent *dent)
{
	struct mars_global *global = buf;
	int status;

	if (!global->global_power.button || !dent->d_parent || !dent->new_link) {
		return 0;
	}
	status = _parse_args(dent, dent->new_link, 2);
	if (status < 0) {
		goto done;
	}

	status = __make_copy(global, dent->d_parent, dent->d_path, dent->d_argv);

done:
	MARS_DBG("status = %d\n", status);
	return status;
}

///////////////////////////////////////////////////////////////////////

// the order is important!
enum {
	CL_ROOT, // root element: this must have index 0
	CL_IPS,
	CL_PEERS,
	CL_RESOURCE,
	CL_DATA,
	CL_PRIMARY,
	CL__FILE,
	CL_SYNC,
	CL__COPY,
	CL__REMOTE,
	CL__DIRECT,
	CL_REPLAYSTATUS,
	CL_LOG,
	CL_DEVICE,
	CL_CONNECT,
};

/* Please keep the order the same as in the enum.
 */
static const struct light_class light_classes[] = {
	/* Placeholder for root node /mars/
	 */
	[CL_ROOT] = {
	},

	/* Directory containing the addresses of all peers
	 */
	[CL_IPS] = {
		.cl_name = "ips",
		.cl_len = 3,
		.cl_type = 'd',
		.cl_father = CL_ROOT,
#if 1
		.cl_forward = make_scan,
		.cl_backward = kill_scan,
#endif
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
		.cl_forward = NULL,
		.cl_backward = NULL,
	},

	/* Directory containing all items of a resource
	 */
	[CL_RESOURCE] = {
		.cl_name = "resource-",
		.cl_len = 9,
		.cl_type = 'd',
		.cl_father = CL_ROOT,
		.cl_forward = make_log_init,
		.cl_backward = NULL,
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
		.cl_forward = make_aio,
		.cl_backward = kill_default,
	},
	/* Symlink pointing to the name of the primary node
	 */
	[CL_PRIMARY] = {
		.cl_name = "primary",
		.cl_len = 7,
		.cl_type = 'l',
		.cl_hostcontext = false,
		.cl_father = CL_RESOURCE,
		.cl_forward = make_primary,
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
		.cl_forward = make_aio,
		.cl_backward = kill_default,
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
#if 0
		.cl_forward = make_sync,
		.cl_backward = kill_sync,
#endif
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
		.cl_backward = kill_all,
	},
	/* Only for testing: access remote data directly
	 */
	[CL__REMOTE] = {
		.cl_name = "_remote-",
		.cl_len = 8,
		.cl_type = 'l',
		.cl_serial = true,
		.cl_hostcontext = true,
		.cl_father = CL_RESOURCE,
		.cl_forward = _make_remote,
		.cl_backward = _kill_remote,
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
		.cl_backward = kill_all,
	},

	/* Passive symlink indicating the last state of
	 * transaction log replay.
	 */
	[CL_REPLAYSTATUS] = {
		.cl_name = "replay-",
		.cl_len = 7,
		.cl_type = 'l',
		.cl_hostcontext = true,
		.cl_father = CL_RESOURCE,
		.cl_forward = NULL,
		.cl_backward = NULL,
	},
	/* Logfiles for transaction logger
	 */
	[CL_LOG] = {
		.cl_name = "log-",
		.cl_len = 4,
		.cl_type = 'F',
		.cl_serial = true,
		.cl_hostcontext = true,
		.cl_father = CL_RESOURCE,
#if 1
		.cl_forward = make_log,
		.cl_backward = kill_all,
#endif
	},

	/* Name of the device appearing at the primary
	 */
	[CL_DEVICE] = {
		.cl_name = "device-",
		.cl_len = 7,
		.cl_type = 'l',
		.cl_hostcontext = true,
		.cl_father = CL_RESOURCE,
		.cl_forward = make_dev,
		.cl_backward = kill_default,
	},
	/* Symlink indicating the current peer
	 */
	[CL_CONNECT] = {
		.cl_name = "connect-",
		.cl_len = 8,
		.cl_type = 'l',
		.cl_hostcontext = true,
		.cl_father = CL_RESOURCE,
#if 0
		.cl_forward = make_connect,
		.cl_backward = kill_connect,
#endif
	},
	{}
};

/* Helper routine to pre-determine the relevance of a name from the filesystem.
 */
static int light_checker(const char *path, const char *_name, int namlen, unsigned int d_type, int *prefix, int *serial)
{
	char name[namlen+1];
	int class;
	memcpy(name, _name, namlen);
	name[namlen] = '\0';

	//MARS_DBG("trying '%s' '%s'\n", path, name);
	for (class = CL_ROOT + 1; ; class++) {
		const struct light_class *test = &light_classes[class];
		int len = test->cl_len;
		if (!len || !test->cl_name)
			break;
		//MARS_DBG("   testing class '%s'\n", test->cl_name);
#if 0
		if (len != strlen(test->cl_name)) {
			MARS_ERR("internal table '%s': %d != %d\n", test->cl_name, len, (int)strlen(test->cl_name));
			len = strlen(test->cl_name);
		}
#endif
		if (namlen >= len && !memcmp(name, test->cl_name, len)) {
			//MARS_DBG("path '%s/%s' matches class %d '%s'\n", path, name, class, test->cl_name);
			// special contexts
			if (test->cl_serial) {
				int plus = 0;
				int count;
				count = sscanf(name+len, "%d%n", serial, &plus);
				if (count < 1) {
					//MARS_DBG("'%s' serial number mismatch at '%s'\n", name, name+len);
					return -1;
				}
				len += plus;
				if (name[len] == '-')
					len++;
			}
			*prefix = len;
			if (test->cl_hostcontext) {
				if (memcmp(name+len, my_id(), namlen-len)) {
					//MARS_DBG("context mismatch '%s' at '%s'\n", name, name+len);
					return -1;
				}
			}
			return class;
		}
	}
	//MARS_DBG("no match for '%s' '%s'\n", path, name);
	return -2;
}

/* Do some syntactic checks, then delegate work to the real worker functions
 * from the light_classes[] table.
 */
static int light_worker(struct mars_global *global, struct mars_dent *dent, bool direction)
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
	if (direction) {
		worker = light_classes[class].cl_backward;
	} else {
		worker = light_classes[class].cl_forward;
	}
	if (worker) {
		int status;
		//MARS_DBG("working %s on '%s' rest='%s'\n", direction ? "backward" : "forward", dent->d_path, dent->d_rest);
		status = worker(global, (void*)dent);
		MARS_DBG("worked %s on '%s', status = %d\n", direction ? "backward" : "forward", dent->d_path, status);
		return status;
	}
	return 0;
}

static int light_thread(void *data)
{
	char *id = my_id();
	int status = 0;
	struct mars_global global = {
		.dent_anchor = LIST_HEAD_INIT(global.dent_anchor),
		.brick_anchor = LIST_HEAD_INIT(global.brick_anchor),
		.global_power = {
			.button = true,
		},
		.mutex = __SEMAPHORE_INITIALIZER(global.mutex, 1),
		.main_event = __WAIT_QUEUE_HEAD_INITIALIZER(global.main_event),
	};
	mars_global = &global; // TODO: cleanup, avoid stack

	if (!id || strlen(id) < 2) {
		MARS_ERR("invalid hostname\n");
		status = -EFAULT;
		goto done;
	}	

	fake_mm();

	MARS_INF("-------- starting as host '%s' ----------\n", id);

        while (global.global_power.button || !list_empty(&global.brick_anchor)) {
		int status;
		global.global_power.button = !kthread_should_stop();

		status = mars_dent_work(&global, "/mars", sizeof(struct light_dent), light_checker, light_worker, &global, 3);
		MARS_DBG("worker status = %d\n", status);

		wait_event_interruptible_timeout(global.main_event, global.main_trigger, 30 * HZ);
		global.main_trigger = false;

#ifdef MARS_DEBUGGING
		{
			struct list_head *tmp;
			int dent_count = 0;
			int brick_count = 0;

			down(&global.mutex);
			MARS_IO("----------- lists:\n");
			for (tmp = global.dent_anchor.next; tmp != &global.dent_anchor; tmp = tmp->next) {
				struct mars_dent *dent;
				dent = container_of(tmp, struct mars_dent, sub_link);
				MARS_IO("dent '%s'\n", dent->d_path);
				dent_count++;
			}
			for (tmp = global.brick_anchor.next; tmp != &global.brick_anchor; tmp = tmp->next) {
				struct mars_brick *test;
				test = container_of(tmp, struct mars_brick, brick_link);
				MARS_IO("brick path = '%s' name = '%s' button = %d on = %d off = %d\n", test->brick_path, test->brick_name, test->power.button, test->power.led_on, test->power.led_off);
				brick_count++;
			}
			up(&global.mutex);

			MARS_INF("----------- STATISTICS: %d dents, %d bricks\n", dent_count, brick_count);
		}
		msleep(500);
#endif
	}

done:
	MARS_INF("-------- cleaning up ----------\n");

	mars_dent_free_all(&global.dent_anchor);

	cleanup_mm();

	mars_global = NULL;
	main_thread = NULL;

	MARS_INF("-------- done status = %d ----------\n", status);
	return status;
}

static void __exit exit_light(void)
{
	// TODO: make this thread-safe.
	struct task_struct *thread = main_thread;
	if (thread) {
		main_thread = NULL;
		MARS_DBG("====================== stopping everything...\n");
		kthread_stop_nowait(thread);
		mars_trigger();
		kthread_stop(thread);
		put_task_struct(thread);
		MARS_DBG("====================== stopped everything.\n");
	}
}

static int __init init_light(void)
{
	struct task_struct *thread;
	thread = kthread_create(light_thread, NULL, "mars_light");
	if (IS_ERR(thread)) {
		return PTR_ERR(thread);
	}
	get_task_struct(thread);
	main_thread = thread;
	wake_up_process(thread);
	return 0;
}

MODULE_DESCRIPTION("MARS Light");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_light);
module_exit(exit_light);
