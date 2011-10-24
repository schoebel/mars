// (c) 2011 Thomas Schoebel-Theuer / 1&1 Internet AG

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/fs.h>

#include <asm/atomic.h>

#include "brick_mem.h"
#include "brick_locks.h"

#define BRICK_DEBUG_MEM 10000

#define MAGIC_MEM  (int)0x8B395D7D
#define MAGIC_END  (int)0x8B395D7E
#define MAGIC_STR  (int)0x8B395D7F

#define INT_ACCESS(ptr,offset) (*(int*)(((char*)(ptr)) + (offset)))

#define _BRICK_FMT(_fmt) __BASE_FILE__ " %d %s(): " _fmt, __LINE__, __FUNCTION__
#define _BRICK_MSG(_dump, PREFIX, _fmt, _args...) do { printk(PREFIX _BRICK_FMT(_fmt), ##_args); if (_dump) dump_stack(); } while (0)
#define BRICK_ERROR   "MEM_ERROR "
#define BRICK_WARNING "MEM_WARN  "
#define BRICK_INFO    "MEM_INFO  "
#define BRICK_ERR(_fmt, _args...) _BRICK_MSG(true,  BRICK_ERROR,   _fmt, ##_args)
#define BRICK_WRN(_fmt, _args...) _BRICK_MSG(false, BRICK_WARNING, _fmt, ##_args)
#define BRICK_INF(_fmt, _args...) _BRICK_MSG(false, BRICK_INFO,    _fmt, ##_args)

/////////////////////////////////////////////////////////////////////////

// limit handling

#define LIMIT_MEM
#ifdef LIMIT_MEM
#include <linux/swap.h>
#include <linux/mm.h>
#endif
long long brick_global_memlimit = 0;
EXPORT_SYMBOL_GPL(brick_global_memlimit);

/////////////////////////////////////////////////////////////////////////

// small memory allocation (use this only for len < PAGE_SIZE)

#ifdef BRICK_DEBUG_MEM
static atomic_t mem_count[BRICK_DEBUG_MEM] = {};
static atomic_t mem_free[BRICK_DEBUG_MEM] = {};
static int  mem_len[BRICK_DEBUG_MEM] = {};
#define PLUS_SIZE (2 * sizeof(int))
#else
#define PLUS_SIZE 0
#endif

void *_brick_mem_alloc(int len, int line)
{
	void *res;
#ifdef CONFIG_DEBUG_KERNEL
	might_sleep();
#endif
	res = kmalloc(len + PLUS_SIZE + sizeof(int), GFP_BRICK);
#ifdef BRICK_DEBUG_MEM
	if (likely(res)) {
		if (unlikely(line < 0))
			line = 0;
		else if (unlikely(line >= BRICK_DEBUG_MEM))
			line = BRICK_DEBUG_MEM - 1;
		INT_ACCESS(res, 0) = MAGIC_MEM;
		INT_ACCESS(res, sizeof(int)) = line;
		res += PLUS_SIZE;
		INT_ACCESS(res, len) = MAGIC_END;
		atomic_inc(&mem_count[line]);
		mem_len[line] = len;
	}
#endif
	return res;
}
EXPORT_SYMBOL_GPL(_brick_mem_alloc);

void _brick_mem_free(void *data, int cline)
{
	if (data) {
#ifdef BRICK_DEBUG_MEM
		void *test = data - PLUS_SIZE;
		int magic = INT_ACCESS(test, 0);
		int line = INT_ACCESS(test, sizeof(int));
		if (unlikely(magic != MAGIC_MEM)) {
			BRICK_ERR("line %d memory corruption: magix %08x != %08x\n", cline, magic, MAGIC_STR);
			return;
		}
		if (unlikely(line < 0 || line >= BRICK_DEBUG_MEM)) {
			BRICK_ERR("line %d memory corruption: alloc line = %d\n", cline, line);
			return;
		}
		INT_ACCESS(test, 0) = 0xffffffff;
		atomic_dec(&mem_count[line]);
		atomic_inc(&mem_free[line]);
		data = test;
#endif
		kfree(data);
	}
}
EXPORT_SYMBOL_GPL(_brick_mem_free);

/////////////////////////////////////////////////////////////////////////

// string memory allocation

#ifdef BRICK_DEBUG_MEM
static atomic_t string_count[BRICK_DEBUG_MEM] = {};
static atomic_t string_free[BRICK_DEBUG_MEM] = {};
#endif

char *_brick_string_alloc(int len, int line)
{
	char *res;

#ifdef CONFIG_DEBUG_KERNEL
	might_sleep();
#endif

	if (len <= 0) {
		len = BRICK_STRING_LEN;
	}

#ifdef BRICK_DEBUG_MEM
	len += sizeof(int) * 4;
#endif

#ifdef CONFIG_DEBUG_KERNEL
	res = kzalloc(len + 1024, GFP_BRICK);
#else
	res = kzalloc(len, GFP_BRICK);
#endif

#ifdef BRICK_DEBUG_MEM
	if (likely(res)) {
		if (unlikely(line < 0))
			line = 0;
		else if (unlikely(line >= BRICK_DEBUG_MEM))
			line = BRICK_DEBUG_MEM - 1;
		INT_ACCESS(res, 0) = MAGIC_STR;
		INT_ACCESS(res, sizeof(int)) = len;
		INT_ACCESS(res, sizeof(int) * 2) = line;
		INT_ACCESS(res, len - sizeof(int)) = MAGIC_END;
		atomic_inc(&string_count[line]);
		res += sizeof(int) * 3;
	}
#endif
	return res;
}
EXPORT_SYMBOL_GPL(_brick_string_alloc);

void _brick_string_free(const char *data, int cline)
{
	if (data) {
#ifdef BRICK_DEBUG_MEM
		int magic;
		int len;
		int line;

		data -= sizeof(int) * 3;
		magic = INT_ACCESS(data, 0);
		if (unlikely(magic != MAGIC_STR)) {
			BRICK_ERR("cline %d stringmem corruption: magix %08x != %08x\n", cline, magic, MAGIC_STR);
			return;
		}
		len =  INT_ACCESS(data, sizeof(int));
		line = INT_ACCESS(data, sizeof(int) * 2);
		if (unlikely(line < 0 || line >= BRICK_DEBUG_MEM)) {
			BRICK_ERR("cline %d stringmem corruption: line = %d (len = %d)\n", cline, line, len);
			return;
		}
		magic = INT_ACCESS(data, len - sizeof(int));
		if (unlikely(magic != MAGIC_END)) {
			BRICK_ERR("cline %d stringmem corruption: end_magix %08x != %08x, line = %d len = %d\n", cline, magic, MAGIC_END, len, line);
			return;
		}
		INT_ACCESS(data, len - sizeof(int)) = 0xffffffff;
		atomic_dec(&string_count[line]);
		atomic_inc(&string_free[line]);
#endif
		kfree(data);
	}
}
EXPORT_SYMBOL_GPL(_brick_string_free);

/////////////////////////////////////////////////////////////////////////

// block memory allocation

#define USE_KERNEL_PAGES

int len2order(int len)
{
	int order = BRICK_MAX_ORDER;
	if (unlikely(len > (PAGE_SIZE << order) || len <= 0)) {
		BRICK_ERR("trying to allocate %d bytes (max = %d)\n", len, (int)(PAGE_SIZE << order));
		return -1;
	}
	while (order > 0 && (PAGE_SIZE << (order-1)) >= len) {
		order--;
	}
	return order;
}

#ifdef BRICK_DEBUG_MEM
static atomic_t op_count[BRICK_MAX_ORDER+1] = {};
static atomic_t raw_count[BRICK_MAX_ORDER+1] = {};
static atomic_t alloc_count[BRICK_MAX_ORDER+1] = {};
static int alloc_max[BRICK_MAX_ORDER+1] = {};
#endif

static inline
void *__brick_block_alloc(int order)
{
#ifdef BRICK_DEBUG_MEM
	atomic_inc(&raw_count[order]);
#endif
#ifdef USE_KERNEL_PAGES
	return (void*)__get_free_pages(GFP_BRICK, order);
#else
	return __vmalloc(PAGE_SIZE << order, GFP_BRICK, PAGE_KERNEL_IO);
#endif
}

static inline
void __brick_block_free(void *data, int order)
{
#ifdef USE_KERNEL_PAGES
	__free_pages(virt_to_page((unsigned long)data), order);
#else
	vfree(data);
#endif
#ifdef BRICK_DEBUG_MEM
	atomic_dec(&raw_count[order]);
#endif
}

bool brick_allow_freelist = true;
EXPORT_SYMBOL_GPL(brick_allow_freelist);

#ifdef CONFIG_MARS_MEM_PREALLOC
/* Note: we have no separate lists per CPU.
 * This should not hurt because the freelists are only used
 * for higher-order pages which should be rather low-frequency.
 */
static spinlock_t freelist_lock[BRICK_MAX_ORDER+1];
static void *brick_freelist[BRICK_MAX_ORDER+1] = {};
static atomic_t freelist_count[BRICK_MAX_ORDER+1] = {};

static
void *_get_free(int order)
{
	void *data;
	unsigned long flags;

	traced_lock(&freelist_lock[order], flags);
	data = brick_freelist[order];
	if (likely(data)) {
		void *next = *(void**)data;
#ifdef BRICK_DEBUG_MEM // check for corruptions
		void *copy = *(((void**)data)+1);
		if (unlikely(next != copy)) { // found a corruption
			// prevent further trouble by leaving a memleak
			brick_freelist[order] = NULL;
			traced_unlock(&freelist_lock[order], flags);
			BRICK_ERR("freelist corruption at %p (next %p != %p, murdered = %d), order = %d\n", data, next, copy, atomic_read(&freelist_count[order]), order);
			return NULL;
		}
#endif
		brick_freelist[order] = next;
		atomic_dec(&freelist_count[order]);
	}
	traced_unlock(&freelist_lock[order], flags);
	return data;
}

static
void _put_free(void *data, int order)
{
	void *next;
	unsigned long flags;

	traced_lock(&freelist_lock[order], flags);
	next = brick_freelist[order];
	*(void**)data = next;
#ifdef BRICK_DEBUG_MEM // insert redundant copy for checking
	*(((void**)data)+1) = next;
#endif
	brick_freelist[order] = data;
	traced_unlock(&freelist_lock[order], flags);
	atomic_inc(&freelist_count[order]);
}

static
void _free_all(void)
{
	int order;
	for (order = BRICK_MAX_ORDER; order > 0; order--) {
		for (;;) {
			void *data = _get_free(order);
			if (!data)
				break;
			__brick_block_free(data, order);
		}
	}
}

int brick_mem_reserve(struct mem_reservation *r)
{
	int order;
	int status = 0;
	for (order = BRICK_MAX_ORDER; order > 0; order--) {
		int max = r->amount[order];
		int i;
		BRICK_INF("preallocating %d at order %d\n", max, order);
		if (max >= 0) {
			for (i = 0; i < max; i++) {
				void *data = __brick_block_alloc(order);
				if (likely(data)) {
					_put_free(data, order);
				} else {
					status = -ENOMEM;
				}
			}
		} else {
			for (i = 0; i < -max; i++) {
				void *data = _get_free(order);
				if (likely(data)) {
					__brick_block_free(data, order);
				}
			}
		}
	}
	return status;
}
#else
int brick_mem_reserve(struct mem_reservation *r)
{
	BRICK_INF("preallocation is not compiled in\n");
	return 0;
}
#endif
EXPORT_SYMBOL_GPL(brick_mem_reserve);

void *_brick_block_alloc(loff_t pos, int len, int line)
{
	void *data;
	int order = len2order(len);
#ifdef BRICK_DEBUG_MEM
	int count;
#endif

	if (unlikely(order < 0)) {
		BRICK_ERR("trying to allocate %d bytes (max = %d)\n", len, (int)(PAGE_SIZE << order));
		return NULL;
	}

#ifdef CONFIG_DEBUG_KERNEL
	might_sleep();
#endif

#ifdef BRICK_DEBUG_MEM
	atomic_inc(&op_count[order]);
	atomic_inc(&alloc_count[order]);
	count = atomic_read(&alloc_count[order]);
	if (count > alloc_max[order])
		alloc_max[order] = count;
#endif

#ifdef CONFIG_MARS_MEM_PREALLOC
	data = NULL;
	if (order > 0)
		data = _get_free(order);
	if (!data)
#endif
		data = __brick_block_alloc(order);
	return data;
}
EXPORT_SYMBOL_GPL(_brick_block_alloc);

void brick_block_free(void *data, int len)
{
	int order;
	if (!data) {
		return;
	}
	order = len2order(len);
#ifdef CONFIG_MARS_MEM_PREALLOC
	if (order > 0 && brick_allow_freelist) {
		_put_free(data, order);
	} else
#endif
		__brick_block_free(data, order);

#ifdef BRICK_DEBUG_MEM
	atomic_dec(&alloc_count[order]);
#endif
}
EXPORT_SYMBOL_GPL(brick_block_free);

struct page *brick_iomap(void *data, int *offset, int *len)
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
EXPORT_SYMBOL_GPL(brick_iomap);

/////////////////////////////////////////////////////////////////////////

// module

void brick_mem_statistics(void)
{
#ifdef BRICK_DEBUG_MEM
	int i;
	int count = 0;
	int places = 0;

#ifdef CONFIG_MARS_MEM_PREALLOC
	BRICK_INF("======== page allocation:\n");
	for (i = 0; i <= BRICK_MAX_ORDER; i++) {
		BRICK_INF("pages order = %d operations = %9d freelist_count = %3d raw_count = %5d alloc_count = %5d max_count = %5d\n", i, atomic_read(&op_count[i]), atomic_read(&freelist_count[i]), atomic_read(&raw_count[i]), atomic_read(&alloc_count[i]), alloc_max[i]);
	}
#endif
	BRICK_INF("======== brick_mem allocation:\n");
	for (i = 0; i < BRICK_DEBUG_MEM; i++) {
		int val = atomic_read(&mem_count[i]);
		if (val) {
			count += val;
			places++;
			BRICK_INF("line %4d: %6d allocated (last size = %4d, freed = %6d)\n", i, val, mem_len[i], atomic_read(&mem_free[i]));
		}
	}
	BRICK_INF("======== %d memory allocations in %d places\n", count, places);
	count = places = 0;
	for (i = 0; i < BRICK_DEBUG_MEM; i++) {
		int val = atomic_read(&string_count[i]);
		if (val) {
			count += val;
			places++;
			BRICK_INF("line %4d: %6d allocated (freed = %6d)\n", i, val, atomic_read(&string_free[i]));
		}
	}
	BRICK_INF("======== %d string allocations in %d places\n", count, places);
#endif
}
EXPORT_SYMBOL_GPL(brick_mem_statistics);

// module init stuff

int __init init_brick_mem(void)
{
#ifdef CONFIG_MARS_MEM_PREALLOC
	int i;
	for (i = BRICK_MAX_ORDER; i >= 0; i--) {
		spin_lock_init(&freelist_lock[i]);
	}
#endif
#ifdef LIMIT_MEM // provisionary
	brick_global_memlimit = total_swapcache_pages * (PAGE_SIZE / 4);
	BRICK_INF("brick_global_memlimit = %lld\n", brick_global_memlimit);
#endif

	return 0;
}

void __exit exit_brick_mem(void)
{
#ifdef CONFIG_MARS_MEM_PREALLOC
	_free_all();
#endif
	brick_mem_statistics();
}

#ifndef CONFIG_MARS_HAVE_BIGMODULE
MODULE_DESCRIPTION("generic brick infrastructure");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_brick_mem);
module_exit(exit_brick_mem);
#endif
