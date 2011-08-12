// (c) 2011 Thomas Schoebel-Theuer / 1&1 Internet AG

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>

#include <asm/atomic.h>

#include "brick_mem.h"

#define BRICK_DEBUG_MEM 10000
#define STRING_SIZE 1024

#define MAGIC_MEM (int)0x8B395D7D
#define MAGIC_END (int)0x8B395D7E
#define MAGIC_STR (int)0x8B395D7F

#define INT_ACCESS(ptr,offset) (*(int*)(((char*)(ptr)) + (offset)))

#define _BRICK_FMT(_fmt) __BASE_FILE__ " %d %s(): " _fmt, __LINE__, __FUNCTION__
#define _BRICK_MSG(_dump, PREFIX, _fmt, _args...) do { printk(PREFIX _BRICK_FMT(_fmt), ##_args); } while (0)
#define BRICK_ERROR   "MEM_ERROR "
#define BRICK_WARNING "MEM_WARN  "
#define BRICK_INFO    "MEM_INFO  "
#define BRICK_ERR(_fmt, _args...) _BRICK_MSG(true,  BRICK_ERROR,   _fmt, ##_args)
#define BRICK_WRN(_fmt, _args...) _BRICK_MSG(false, BRICK_WARNING, _fmt, ##_args)
#define BRICK_INF(_fmt, _args...) _BRICK_MSG(false, BRICK_INFO,    _fmt, ##_args)

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
	void *res = kmalloc(len + PLUS_SIZE + sizeof(int), GFP_BRICK);
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

char *_brick_string_alloc(int line)
{
	char *res = kmalloc(STRING_SIZE, GFP_BRICK);
#ifdef BRICK_DEBUG_MEM
	if (likely(res)) {
		if (unlikely(line < 0))
			line = 0;
		else if (unlikely(line >= BRICK_DEBUG_MEM))
			line = BRICK_DEBUG_MEM - 1;
		INT_ACCESS(res, STRING_SIZE - PLUS_SIZE) = MAGIC_STR;
		INT_ACCESS(res, STRING_SIZE - PLUS_SIZE + sizeof(int)) = line;
		atomic_inc(&string_count[line]);
	}
#endif
	return res;
}
EXPORT_SYMBOL_GPL(_brick_string_alloc);

void _brick_string_free(const char *data, int cline)
{
	if (data) {
#ifdef BRICK_DEBUG_MEM
		int magic = INT_ACCESS(data, STRING_SIZE - PLUS_SIZE);
		int line = INT_ACCESS(data, STRING_SIZE - PLUS_SIZE + sizeof(int));
		if (unlikely(magic != MAGIC_STR)) {
			BRICK_ERR("line %d stringmem corruption: magix %08x != %08x\n", cline, magic, MAGIC_STR);
			return;
		}
		if (unlikely(line < 0 || line >= BRICK_DEBUG_MEM)) {
			BRICK_ERR("line %d stringmem corruption: line = %d\n", cline, line);
			return;
		}
		INT_ACCESS(data, STRING_SIZE - PLUS_SIZE) = 0xffffffff;
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
#define BRICK_MAX_ORDER 8
//#define USE_OFFSET
//#define USE_INTERNAL_FREELIST

#ifdef USE_INTERNAL_FREELIST
void *brick_freelist[BRICK_MAX_ORDER+1] = {};
atomic_t freelist_count[BRICK_MAX_ORDER+1] = {};
#endif

void *_brick_block_alloc(loff_t pos, int len, int line)
{
	int offset = 0;
	void *data;
#ifdef USE_KERNEL_PAGES
	int order = BRICK_MAX_ORDER;
	if (unlikely(len > (PAGE_SIZE << order) || len <=0)) {
		BRICK_ERR("trying to allocate %d bytes (max = %d)\n", len, (int)(PAGE_SIZE << order));
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
	data = brick_freelist[order];
	if (data) {
		brick_freelist[order] = *(void**)data;
		atomic_dec(&freelist_count[order]);
	} else
#endif
	data = (void*)__get_free_pages(GFP_BRICK, order);
#else
	data = __vmalloc(len + offset, GFP_BRICK, PAGE_KERNEL_IO);
#endif
	if (likely(data)) {
		data += offset;
	}
	return data;
}
EXPORT_SYMBOL_GPL(_brick_block_alloc);

void brick_block_free(void *data, int len)
{
	int offset = 0;
#ifdef USE_KERNEL_PAGES
	int order = BRICK_MAX_ORDER;
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
		static int max[BRICK_MAX_ORDER+1] = {};
		int now;
		*(void**)data = brick_freelist[order];
		brick_freelist[order] = data;
		atomic_inc(&freelist_count[order]);
		now = atomic_read(&freelist_count[order]);
		if (now > max[order] + 50) {
			int i;
			max[order] = now;
			BRICK_INF("now %d freelist members at order %d (len = %d)\n", now, order, len);
			for (i = 0; i <= BRICK_MAX_ORDER; i++) {
				BRICK_INF("  %d : %4d\n", i, atomic_read(&freelist_count[i]));
			}
		}
	} else
#endif
	__free_pages(virt_to_page((unsigned long)data), order);
#else
	vfree(data);
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

	for (i = 0; i < BRICK_DEBUG_MEM; i++) {
		int val = atomic_read(&mem_count[i]);
		if (val) {
			count += val;
			places++;
			BRICK_INF("line %d: %d allocated (last size = %d, freed = %d)\n", i, val, mem_len[i], atomic_read(&mem_free[i]));
		}
	}
	BRICK_INF("======== %d memory allocations in %d places\n", count, places);
	count = places = 0;
	for (i = 0; i < BRICK_DEBUG_MEM; i++) {
		int val = atomic_read(&string_count[i]);
		if (val) {
			count += val;
			places++;
			BRICK_INF("line %d: %d allocated (freed = %d)\n", i, val, atomic_read(&string_free[i]));
		}
	}
	BRICK_INF("======== %d string allocations in %d places\n", count, places);
#endif
}
EXPORT_SYMBOL_GPL(brick_mem_statistics);

// module init stuff

static int __init init_brick_mem(void)
{
	return 0;
}

static void __exit exit_brick_mem(void)
{
}


MODULE_DESCRIPTION("generic brick infrastructure");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_brick_mem);
module_exit(exit_brick_mem);
