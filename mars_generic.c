// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/utsname.h>

#include "mars.h"
#include "mars_client.h"

//////////////////////////////////////////////////////////////

// infrastructure

static char *id = NULL;

/* TODO: better use MAC addresses (or motherboard IDs where available).
 * Or, at least, some checks for MAC addresses should be recorded / added.
 * When the nodename is misconfigured, data might be scrambled.
 * MAC addresses should be more secure.
 * In ideal case, further checks should be added to prohibit accidental
 * name clashes.
 */
char *my_id(void)
{
	struct new_utsname *u;
	if (id)
		return id;

	//down_read(&uts_sem); // FIXME: this is currenty not EXPORTed from the kernel!
	u = utsname();
	if (u) {
		id = kstrdup(u->nodename, GFP_MARS);
	}
	//up_read(&uts_sem);
	
	return id;
}
EXPORT_SYMBOL_GPL(my_id);

/////////////////////////////////////////////////////////////////////////

// MARS-specific memory allocation

#define USE_KERNEL_PAGES
#define MARS_MAX_ORDER 8
//#define USE_OFFSET
//#define USE_INTERNAL_FREELIST

#ifdef USE_INTERNAL_FREELIST
void *mars_freelist[MARS_MAX_ORDER+1] = {};
atomic_t freelist_count[MARS_MAX_ORDER+1] = {};
#endif

void *mars_alloc(loff_t pos, int len)
{
	int offset = 0;
	void *data;
#ifdef USE_KERNEL_PAGES
	int order = MARS_MAX_ORDER;
	if (unlikely(len > (PAGE_SIZE << order) || len <=0)) {
		MARS_ERR("trying to allocate %d bytes (max = %d)\n", len, (PAGE_SIZE << order));
		return NULL;
	}
#endif
#ifdef USE_OFFSET
	offset = pos & (PAGE_SIZE-1);
#endif
#ifdef USE_KERNEL_PAGES
	len += offset;
	while (order > 0 && (PAGE_SIZE << (order-1)) >= len) {
		order--;
	}
#ifdef USE_INTERNAL_FREELIST
	data = mars_freelist[order];
	if (data) {
		mars_freelist[order] = *(void**)data;
		atomic_dec(&freelist_count[order]);
	} else
#endif
	data = (void*)__get_free_pages(GFP_MARS, order);
#else
	data = __vmalloc(len + offset, GFP_MARS, PAGE_KERNEL_IO);
#endif
	if (likely(data)) {
		data += offset;
	}
	return data;
}
EXPORT_SYMBOL_GPL(mars_alloc);

void mars_free(void *data, int len)
{
	int offset = 0;
#ifdef USE_KERNEL_PAGES
	int order = MARS_MAX_ORDER;
#endif
	if (!data) {
		return;
	}
#ifdef USE_OFFSET
	offset = ((unsigned long)data) & (PAGE_SIZE-1);
#endif
	data -= offset;
#ifdef USE_KERNEL_PAGES
	len += offset;
	while (order > 0 && (PAGE_SIZE << (order-1)) >= len) {
		order--;
	}
#ifdef USE_INTERNAL_FREELIST
	if (order > 0 && atomic_read(&freelist_count[order]) < 500) {
		static int max[MARS_MAX_ORDER+1] = {};
		int now;
		*(void**)data = mars_freelist[order];
		mars_freelist[order] = data;
		atomic_inc(&freelist_count[order]);
		now = atomic_read(&freelist_count[order]);
		if (now > max[order] + 50) {
			int i;
			max[order] = now;
			MARS_INF("now %d freelist members at order %d (len = %d)\n", now, order, len);
			for (i = 0; i <= MARS_MAX_ORDER; i++) {
				MARS_INF("  %d : %4d\n", i, atomic_read(&freelist_count[i]));
			}
		}
	} else
#endif
	__free_pages(virt_to_page((unsigned long)data), order);
#else
	vfree(data);
#endif
}
EXPORT_SYMBOL_GPL(mars_free);

struct page *mars_iomap(void *data, int *offset, int *len)
{
	int _offset = ((unsigned long)data) & (PAGE_SIZE-1);
	struct page *page;
	*offset = _offset;
	if (*len > PAGE_SIZE - _offset) {
		*len = PAGE_SIZE - _offset;
	}
	if (is_vmalloc_addr(data)) {
		page = vmalloc_to_page(data);
	} else {
		page = virt_to_page(data);
	}
	return page;
}
EXPORT_SYMBOL_GPL(mars_iomap);


//////////////////////////////////////////////////////////////

// object stuff

const struct generic_object_type mref_type = {
        .object_type_name = "mref",
        .default_size = sizeof(struct mref_object),
        .brick_obj_nr = BRICK_OBJ_MREF,
};
EXPORT_SYMBOL_GPL(mref_type);

//////////////////////////////////////////////////////////////

// brick stuff

/////////////////////////////////////////////////////////////////////

// meta descriptions

const struct meta mars_info_meta[] = {
	META_INI(current_size,    struct mars_info, FIELD_INT),
	META_INI(transfer_order,  struct mars_info, FIELD_INT),
	META_INI(transfer_size,   struct mars_info, FIELD_INT),
	{}
};
EXPORT_SYMBOL_GPL(mars_info_meta);

const struct meta mars_mref_meta[] = {
	META_INI(ref_pos,          struct mref_object, FIELD_INT),
	META_INI(ref_len,          struct mref_object, FIELD_INT),
	META_INI(ref_may_write,    struct mref_object, FIELD_INT),
	META_INI(ref_prio,         struct mref_object, FIELD_INT),
	META_INI(ref_timeout,      struct mref_object, FIELD_INT),
	META_INI(ref_total_size,   struct mref_object, FIELD_INT),
	META_INI(ref_flags,        struct mref_object, FIELD_INT),
	META_INI(ref_rw,           struct mref_object, FIELD_INT),
	META_INI(ref_id,           struct mref_object, FIELD_INT),
	META_INI(ref_skip_sync,    struct mref_object, FIELD_INT),
	META_INI(_ref_cb.cb_error, struct mref_object, FIELD_INT),
	{}
};
EXPORT_SYMBOL_GPL(mars_mref_meta);

const struct meta mars_timespec_meta[] = {
	META_INI(tv_sec, struct timespec, FIELD_INT),
	META_INI(tv_nsec, struct timespec, FIELD_INT),
	{}
};
EXPORT_SYMBOL_GPL(mars_timespec_meta);


/////////////////////////////////////////////////////////////////////

// tracing

#ifdef MARS_TRACING

unsigned long long start_trace_clock = 0;
EXPORT_SYMBOL_GPL(start_trace_clock);

struct file *mars_log_file = NULL;
loff_t mars_log_pos = 0;

void _mars_log(char *buf, int len)
{
	static DECLARE_MUTEX(trace_lock);
	mm_segment_t oldfs;
	

	oldfs = get_fs();
	set_fs(get_ds());
	down(&trace_lock);

	vfs_write(mars_log_file, buf, len, &mars_log_pos);

	up(&trace_lock);
	set_fs(oldfs);
}
EXPORT_SYMBOL_GPL(_mars_log);

void mars_log(const char *fmt, ...)
{
	char *buf = kmalloc(PAGE_SIZE, GFP_MARS);
	va_list args;
	int len;
	if (!buf)
		return;

	va_start(args, fmt);
	len = vsnprintf(buf, PAGE_SIZE, fmt, args);
	va_end(args);

	_mars_log(buf, len);

	kfree(buf);
}
EXPORT_SYMBOL_GPL(mars_log);

void mars_trace(struct mref_object *mref, const char *info)
{
	int index = mref->ref_traces;
	if (likely(index < MAX_TRACES)) {
		mref->ref_trace_stamp[index] = cpu_clock(raw_smp_processor_id());
		mref->ref_trace_info[index] = info;
		mref->ref_traces++;
	}
}
EXPORT_SYMBOL_GPL(mars_trace);

void mars_log_trace(struct mref_object *mref)
{
	char *buf = kmalloc(PAGE_SIZE, GFP_MARS);
	unsigned long long old;
	unsigned long long diff;
	int i;
	int len;

	if (!buf) {
		return;
	}
	if (!mars_log_file || !mref->ref_traces) {
		goto done;
	}
	if (!start_trace_clock) {
		start_trace_clock = mref->ref_trace_stamp[0];
	}

	diff = mref->ref_trace_stamp[mref->ref_traces-1] - mref->ref_trace_stamp[0];

	len = snprintf(buf, PAGE_SIZE, "%c ;%12lld ;%6d;%10llu", mref->ref_rw ? 'W' : 'R', mref->ref_pos, mref->ref_len, diff / 1000);

	old = start_trace_clock;
	for (i = 0; i < mref->ref_traces; i++) {
		diff = mref->ref_trace_stamp[i] - old;
		
		len += snprintf(buf + len, PAGE_SIZE - len, " ; %s ;%10llu", mref->ref_trace_info[i], diff / 1000);
		old = mref->ref_trace_stamp[i];
	}
	len +=snprintf(buf + len, PAGE_SIZE - len, "\n");

	_mars_log(buf, len);

 done:
	kfree(buf);
	mref->ref_traces = 0;
}
EXPORT_SYMBOL_GPL(mars_log_trace);

#endif // MARS_TRACING

/////////////////////////////////////////////////////////////////////

// power led handling

void mars_power_led_on(struct generic_brick *brick, bool val)
{
	bool oldval = brick->power.led_on;
	if (val != oldval) {
		//MARS_DBG("brick '%s' type '%s' led_on %d -> %d\n", brick->brick_path, brick->type->type_name, oldval, val);
		set_led_on(&brick->power, val);
		mars_trigger();
	}
}
EXPORT_SYMBOL_GPL(mars_power_led_on);

void mars_power_led_off(struct generic_brick *brick, bool val)
{
	bool oldval = brick->power.led_off;
	if (val != oldval) {
		//MARS_DBG("brick '%s' type '%s' led_off %d -> %d\n", brick->brick_path, brick->type->type_name, oldval, val);
		set_led_off(&brick->power, val);
		mars_trigger();
	}
}
EXPORT_SYMBOL_GPL(mars_power_led_off);


/////////////////////////////////////////////////////////////////////

// init stuff

void (*_mars_trigger)(void) = NULL;
EXPORT_SYMBOL_GPL(_mars_trigger);

#define LIMIT_MEM
#ifdef LIMIT_MEM
#include <linux/swap.h>
#include <linux/mm.h>
#endif
long long mars_global_memlimit = 0;
EXPORT_SYMBOL_GPL(mars_global_memlimit);


struct mm_struct *mm_fake = NULL;
EXPORT_SYMBOL_GPL(mm_fake);

static int __init init_mars(void)
{
	MARS_INF("init_mars()\n");

#ifdef LIMIT_MEM // provisionary
	mars_global_memlimit = total_swapcache_pages * (PAGE_SIZE / 4);
	MARS_INF("mars_global_memlimit = %lld\n", mars_global_memlimit);
#endif

	set_fake();

#ifdef MARS_TRACING
	{
		int flags = O_CREAT | O_TRUNC | O_RDWR | O_LARGEFILE;
		int prot = 0600;
		mm_segment_t oldfs;
		oldfs = get_fs();
		set_fs(get_ds());
		mars_log_file = filp_open("/mars/trace.csv", flags, prot);
		set_fs(oldfs);
		if (IS_ERR(mars_log_file)) {
			MARS_ERR("cannot create trace logfile, status = %ld\n", PTR_ERR(mars_log_file));
			mars_log_file = NULL;
		}
	}
#endif
	return 0;
}

static void __exit exit_mars(void)
{
	MARS_INF("exit_mars()\n");
	put_fake();
#ifdef MARS_TRACING
	if (mars_log_file) {
		filp_close(mars_log_file, NULL);
		mars_log_file = NULL;
	}
#endif
	if (id) {
		kfree(id);
		id = NULL;
	}
}

MODULE_DESCRIPTION("MARS block storage");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_mars);
module_exit(exit_mars);
