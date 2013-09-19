// (c) 2011 Thomas Schoebel-Theuer / 1&1 Internet AG

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/delay.h>

#include <asm/atomic.h>

#include "brick_mem.h"
#include "brick_say.h"
#include "brick_locks.h"
#include "lamport.h"

#define USE_KERNEL_PAGES // currently mandatory (vmalloc does not work)

#define MAGIC_BLOCK  (int)0x8B395D7B
#define MAGIC_BEND   (int)0x8B395D7C
#define MAGIC_MEM1   (int)0x8B395D7D
#define MAGIC_MEM2   (int)0x9B395D8D
#define MAGIC_MEND1  (int)0x8B395D7E
#define MAGIC_MEND2  (int)0x9B395D8E
#define MAGIC_STR    (int)0x8B395D7F
#define MAGIC_SEND   (int)0x9B395D8F

#define INT_ACCESS(ptr,offset) (*(int*)(((char*)(ptr)) + (offset)))

#define _BRICK_FMT(_fmt)						\
	"%ld.%09ld %ld.%09ld MEM %s %d %s(): "				\
	_fmt,								\
		_s_now.tv_sec, _s_now.tv_nsec,				\
		_l_now.tv_sec, _l_now.tv_nsec,				\
		__BASE_FILE__,						\
		__LINE__,						\
		__FUNCTION__

#define _BRICK_MSG(_class, _dump, _fmt, _args...)			\
	do {								\
		struct timespec _s_now = CURRENT_TIME;			\
		struct timespec _l_now;					\
		get_lamport(&_l_now);					\
		say(_class, _BRICK_FMT(_fmt), ##_args); if (_dump) dump_stack(); \
	} while (0)

#define BRICK_ERR(_fmt, _args...) _BRICK_MSG(SAY_ERROR, true,  _fmt, ##_args)
#define BRICK_WRN(_fmt, _args...) _BRICK_MSG(SAY_WARN,  false, _fmt, ##_args)
#define BRICK_INF(_fmt, _args...) _BRICK_MSG(SAY_INFO,  false, _fmt, ##_args)

/////////////////////////////////////////////////////////////////////////

// limit handling

#include <linux/swap.h>

long long brick_global_memavail = 0;
EXPORT_SYMBOL_GPL(brick_global_memavail);
long long brick_global_memlimit = 0;
EXPORT_SYMBOL_GPL(brick_global_memlimit);
atomic64_t brick_global_block_used = ATOMIC64_INIT(0);
EXPORT_SYMBOL_GPL(brick_global_block_used);

void get_total_ram(void)
{
	struct sysinfo i = {};
	si_meminfo(&i);
	//si_swapinfo(&i);
	brick_global_memavail = (long long)i.totalram * (PAGE_SIZE / 1024);
	BRICK_INF("total RAM = %lld [KiB]\n", brick_global_memavail);
}

/////////////////////////////////////////////////////////////////////////

// small memory allocation (use this only for len < PAGE_SIZE)

#ifdef BRICK_DEBUG_MEM
static atomic_t phys_mem_alloc = ATOMIC_INIT(0);
static atomic_t mem_redirect_alloc = ATOMIC_INIT(0);
static atomic_t mem_count[BRICK_DEBUG_MEM] = {};
static atomic_t mem_free[BRICK_DEBUG_MEM] = {};
static int  mem_len[BRICK_DEBUG_MEM] = {};
#define PLUS_SIZE (6 * sizeof(int))
#else
#define PLUS_SIZE (2 * sizeof(int))
#endif

static inline
void *__brick_mem_alloc(int len)
{
	void *res;
	if (len >= PAGE_SIZE) {
#ifdef BRICK_DEBUG_MEM
		atomic_inc(&mem_redirect_alloc);
#endif
		res = _brick_block_alloc(0, len, 0);
	} else {
#ifdef CONFIG_MARS_MEM_RETRY
		for (;;) {
			res = kmalloc(len, GFP_BRICK);
			if (likely(res))
				break;
			msleep(1000);
		}
#ifdef BRICK_DEBUG_MEM
		atomic_inc(&phys_mem_alloc);
#endif
#else
		res = kmalloc(len, GFP_BRICK);
#ifdef BRICK_DEBUG_MEM
		if (res)
			atomic_inc(&phys_mem_alloc);
#endif
#endif
	}
	return res;
}

static inline
void __brick_mem_free(void *data, int len)
{
	if (len >= PAGE_SIZE) {
		_brick_block_free(data, len, 0);
#ifdef BRICK_DEBUG_MEM
		atomic_dec(&mem_redirect_alloc);
#endif
	} else {
		kfree(data);
#ifdef BRICK_DEBUG_MEM
		atomic_dec(&phys_mem_alloc);
#endif
	}
}

void *_brick_mem_alloc(int len, int line)
{
	void *res;
#ifdef CONFIG_MARS_DEBUG
	might_sleep();
#endif

	res = __brick_mem_alloc(len + PLUS_SIZE);

	if (likely(res)) {
#ifdef BRICK_DEBUG_MEM
		if (unlikely(line < 0))
			line = 0;
		else if (unlikely(line >= BRICK_DEBUG_MEM))
			line = BRICK_DEBUG_MEM - 1;
		INT_ACCESS(res, 0 * sizeof(int)) = MAGIC_MEM1;
		INT_ACCESS(res, 1 * sizeof(int)) = len;
		INT_ACCESS(res, 2 * sizeof(int)) = line;
		INT_ACCESS(res, 3 * sizeof(int)) = MAGIC_MEM2;
		res += 4 * sizeof(int);
		INT_ACCESS(res, len + 0 * sizeof(int)) = MAGIC_MEND1;
		INT_ACCESS(res, len + 1 * sizeof(int)) = MAGIC_MEND2;
		atomic_inc(&mem_count[line]);
		mem_len[line] = len;
#else
		INT_ACCESS(res, 0 * sizeof(int)) = len;
		res += PLUS_SIZE;
#endif
	}
	return res;
}
EXPORT_SYMBOL_GPL(_brick_mem_alloc);

void _brick_mem_free(void *data, int cline)
{
#ifdef BRICK_DEBUG_MEM
	void *test = data - 4 * sizeof(int);
	int magic1= INT_ACCESS(test, 0 * sizeof(int));
	int len   = INT_ACCESS(test, 1 * sizeof(int));
	int line  = INT_ACCESS(test, 2 * sizeof(int));
	int magic2= INT_ACCESS(test, 3 * sizeof(int));
	if (unlikely(magic1 != MAGIC_MEM1)) {
		BRICK_ERR("line %d memory corruption: magix1 %08x != %08x, len = %d\n", cline, magic1, MAGIC_MEM1, len);
		return;
	}
	if (unlikely(magic2 != MAGIC_MEM2)) {
		BRICK_ERR("line %d memory corruption: magix2 %08x != %08x, len = %d\n", cline, magic2, MAGIC_MEM2, len);
		return;
	}
	if (unlikely(line < 0 || line >= BRICK_DEBUG_MEM)) {
		BRICK_ERR("line %d memory corruption: alloc line = %d, len = %d\n", cline, line, len);
		return;
	}
	INT_ACCESS(test, 0) = 0xffffffff;
	magic1 = INT_ACCESS(data, len + 0 * sizeof(int));
	if (unlikely(magic1 != MAGIC_MEND1)) {
		BRICK_ERR("line %d memory corruption: magix1 %08x != %08x, len = %d\n", cline, magic1, MAGIC_MEND1, len);
		return;
	}
	magic2 = INT_ACCESS(data, len + 1 * sizeof(int));
	if (unlikely(magic2 != MAGIC_MEND2)) {
		BRICK_ERR("line %d memory corruption: magix2 %08x != %08x, len = %d\n", cline, magic2, MAGIC_MEND2, len);
		return;
	}
	INT_ACCESS(data, len) = 0xffffffff;
	atomic_dec(&mem_count[line]);
	atomic_inc(&mem_free[line]);
#else
	void *test = data - PLUS_SIZE;
	int len   = INT_ACCESS(test, 0 * sizeof(int));
#endif
	data = test;
	__brick_mem_free(data, len + PLUS_SIZE);
}
EXPORT_SYMBOL_GPL(_brick_mem_free);

/////////////////////////////////////////////////////////////////////////

// string memory allocation

#ifdef BRICK_DEBUG_MEM
static atomic_t phys_string_alloc = ATOMIC_INIT(0);
static atomic_t string_count[BRICK_DEBUG_MEM] = {};
static atomic_t string_free[BRICK_DEBUG_MEM] = {};
#endif

char *_brick_string_alloc(int len, int line)
{
	char *res;

#ifdef CONFIG_MARS_DEBUG
	might_sleep();
#endif

	if (len <= 0) {
		len = BRICK_STRING_LEN;
	}

#ifdef BRICK_DEBUG_MEM
	len += sizeof(int) * 4;
#endif

#ifdef CONFIG_MARS_MEM_RETRY
	for (;;) {
#endif
#ifdef CONFIG_MARS_DEBUG
		res = kzalloc(len + 1024, GFP_BRICK);
#else
		res = kzalloc(len + 1, GFP_BRICK);
#endif
#ifdef CONFIG_MARS_MEM_RETRY
		if (likely(res))
			break;
		msleep(1000);
	}
#endif

#ifdef BRICK_DEBUG_MEM
	if (likely(res)) {
		atomic_inc(&phys_string_alloc);
		if (unlikely(line < 0))
			line = 0;
		else if (unlikely(line >= BRICK_DEBUG_MEM))
			line = BRICK_DEBUG_MEM - 1;
		INT_ACCESS(res, 0) = MAGIC_STR;
		INT_ACCESS(res, sizeof(int)) = len;
		INT_ACCESS(res, sizeof(int) * 2) = line;
		INT_ACCESS(res, len - sizeof(int)) = MAGIC_SEND;
		atomic_inc(&string_count[line]);
		res += sizeof(int) * 3;
	}
#endif
	return res;
}
EXPORT_SYMBOL_GPL(_brick_string_alloc);

void _brick_string_free(const char *data, int cline)
{
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
	if (unlikely(magic != MAGIC_SEND)) {
		BRICK_ERR("cline %d stringmem corruption: end_magix %08x != %08x, line = %d len = %d\n", cline, magic, MAGIC_SEND, len, line);
		return;
	}
	INT_ACCESS(data, len - sizeof(int)) = 0xffffffff;
	atomic_dec(&string_count[line]);
	atomic_inc(&string_free[line]);
	atomic_dec(&phys_string_alloc);
#endif
	kfree(data);
}
EXPORT_SYMBOL_GPL(_brick_string_free);

/////////////////////////////////////////////////////////////////////////

// block memory allocation

static
int len2order(int len)
{
	int order = 0;

	while ((PAGE_SIZE << order) < len)
		order++;

	if (unlikely(order > BRICK_MAX_ORDER || len <= 0)) {
		BRICK_ERR("trying to allocate %d bytes (max = %d)\n", len, (int)(PAGE_SIZE << order));
		return -1;
	}
	return order;
}

#ifdef CONFIG_MARS_MEM_PREALLOC
static atomic_t _alloc_count[BRICK_MAX_ORDER+1] = {};
int brick_mem_alloc_count[BRICK_MAX_ORDER+1] = {};
EXPORT_SYMBOL_GPL(brick_mem_alloc_count);
int brick_mem_alloc_max[BRICK_MAX_ORDER+1] = {};
EXPORT_SYMBOL_GPL(brick_mem_alloc_max);
int brick_mem_freelist_max[BRICK_MAX_ORDER+1] = {};
EXPORT_SYMBOL_GPL(brick_mem_freelist_max);
#endif

#ifdef BRICK_DEBUG_MEM
static atomic_t phys_block_alloc = ATOMIC_INIT(0);
// indexed by line
static atomic_t block_count[BRICK_DEBUG_MEM] = {};
static atomic_t block_free[BRICK_DEBUG_MEM] = {};
static int  block_len[BRICK_DEBUG_MEM] = {};
// indexed by order
static atomic_t op_count[BRICK_MAX_ORDER+1] = {};
static atomic_t raw_count[BRICK_MAX_ORDER+1] = {};
static int alloc_line[BRICK_MAX_ORDER+1] = {};
static int alloc_len[BRICK_MAX_ORDER+1] = {};
#endif

static inline
void *__brick_block_alloc(gfp_t gfp, int order)
{
	void *res;
#ifdef CONFIG_MARS_MEM_RETRY
	for (;;) {
#endif
#ifdef USE_KERNEL_PAGES
		res = (void*)__get_free_pages(gfp, order);
#else
		res = __vmalloc(PAGE_SIZE << order, gfp, PAGE_KERNEL_IO);
#endif
#ifdef CONFIG_MARS_MEM_RETRY
		if (likely(res))
			break;
		msleep(1000);
	}
#endif

	if (likely(res)) {
#ifdef BRICK_DEBUG_MEM
		atomic_inc(&phys_block_alloc);
		atomic_inc(&raw_count[order]);
#endif
		atomic64_add((PAGE_SIZE/1024) << order, &brick_global_block_used);
	}

	return res;
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
	atomic_dec(&phys_block_alloc);
	atomic_dec(&raw_count[order]);
#endif
	atomic64_sub((PAGE_SIZE/1024) << order, &brick_global_block_used);
}

#ifdef CONFIG_MARS_MEM_PREALLOC
int brick_allow_freelist = 1;
EXPORT_SYMBOL_GPL(brick_allow_freelist);

int brick_pre_reserve[BRICK_MAX_ORDER+1] = {};
EXPORT_SYMBOL_GPL(brick_pre_reserve);

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
		long pattern = *(((long*)data)+1);
		void *copy = *(((void**)data)+2);
		if (unlikely(pattern != 0xf0f0f0f0f0f0f0f0 || next != copy)) { // found a corruption
			// prevent further trouble by leaving a memleak
			brick_freelist[order] = NULL;
			traced_unlock(&freelist_lock[order], flags);
			BRICK_ERR("freelist corruption at %p (pattern = %lx next %p != %p, murdered = %d), order = %d\n",
				  data, pattern, next, copy, atomic_read(&freelist_count[order]), order);
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

#ifdef BRICK_DEBUG_MEM // fill with pattern
	memset(data, 0xf0, PAGE_SIZE << order);
#endif

	traced_lock(&freelist_lock[order], flags);
	next = brick_freelist[order];
	*(void**)data = next;
#ifdef BRICK_DEBUG_MEM // insert redundant copy for checking
	*(((void**)data)+2) = next;
#endif
	brick_freelist[order] = data;
	traced_unlock(&freelist_lock[order], flags);
	atomic_inc(&freelist_count[order]);
}

static
void _free_all(void)
{
	int order;
	for (order = BRICK_MAX_ORDER; order >= 0; order--) {
		for (;;) {
			void *data = _get_free(order);
			if (!data)
				break;
			__brick_block_free(data, order);
		}
	}
}

int brick_mem_reserve(void)
{
	int order;
	int status = 0;
	for (order = BRICK_MAX_ORDER; order >= 0; order--) {
		int max = brick_pre_reserve[order];
		int i;

		brick_mem_freelist_max[order] += max;
		BRICK_INF("preallocating %d at order %d (new maxlevel = %d)\n", max, order, brick_mem_freelist_max[order]);

		max = brick_mem_freelist_max[order] - atomic_read(&freelist_count[order]);
		if (max >= 0) {
			for (i = 0; i < max; i++) {
				void *data = __brick_block_alloc(GFP_KERNEL, order);
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
	int count;
#ifdef BRICK_DEBUG_MEM
#ifdef BRICK_DEBUG_ORDER0
	const int plus0 = PAGE_SIZE;
#else
	const int plus0 = 0;
#endif
	const int plus = len <= PAGE_SIZE ? plus0 : PAGE_SIZE * 2;
#else
	const int plus = 0;
#endif
	int order = len2order(len + plus);

	if (unlikely(order < 0)) {
		BRICK_ERR("trying to allocate %d bytes (max = %d)\n", len, (int)(PAGE_SIZE << order));
		return NULL;
	}

#ifdef CONFIG_MARS_DEBUG
	might_sleep();
#endif

#ifdef CONFIG_MARS_MEM_PREALLOC
	count = atomic_add_return(1, &_alloc_count[order]);
	brick_mem_alloc_count[order] = count;
	if (count > brick_mem_alloc_max[order])
		brick_mem_alloc_max[order] = count;
#endif

#ifdef BRICK_DEBUG_MEM
	atomic_inc(&op_count[order]);
	// statistics
	alloc_line[order] = line;
	alloc_len[order] = len;
#endif

#ifdef CONFIG_MARS_MEM_PREALLOC
	/* Dynamic increase of limits, in order to reduce
	 * fragmentation on higher-order pages.
	 * This comes on cost of higher memory usage.
	 */
	if (order > 0 && count > brick_mem_freelist_max[order])
		brick_mem_freelist_max[order] = count;
#endif

#ifdef CONFIG_MARS_MEM_PREALLOC
	data = _get_free(order);
	if (!data)
#endif
		data = __brick_block_alloc(GFP_BRICK, order);

#ifdef BRICK_DEBUG_MEM
	if (likely(data) && order > 0) {
		if (unlikely(line < 0))
			line = 0;
		else if (unlikely(line >= BRICK_DEBUG_MEM))
			line = BRICK_DEBUG_MEM - 1;
		atomic_inc(&block_count[line]);
		block_len[line] = len;
		if (order > 1) {
			INT_ACCESS(data, 0 * sizeof(int)) = MAGIC_BLOCK;
			INT_ACCESS(data, 1 * sizeof(int)) = line;
			INT_ACCESS(data, 2 * sizeof(int)) = len;
			data += PAGE_SIZE;
			INT_ACCESS(data, -1 * sizeof(int)) = MAGIC_BLOCK;
			INT_ACCESS(data, len) = MAGIC_BEND;
		} else if (order == 1) {
			INT_ACCESS(data, PAGE_SIZE + 0 * sizeof(int)) = MAGIC_BLOCK;
			INT_ACCESS(data, PAGE_SIZE + 1 * sizeof(int)) = line;
			INT_ACCESS(data, PAGE_SIZE + 2 * sizeof(int)) = len;
		}
	}
#endif
	return data;
}
EXPORT_SYMBOL_GPL(_brick_block_alloc);

void _brick_block_free(void *data, int len, int cline)
{
	int order;
#ifdef BRICK_DEBUG_MEM
#ifdef BRICK_DEBUG_ORDER0
	const int plus0 = PAGE_SIZE;
#else
	const int plus0 = 0;
#endif
	const int plus = len <= PAGE_SIZE ? plus0 : PAGE_SIZE * 2;
#else
	const int plus = 0;
#endif

	order = len2order(len + plus);
#ifdef BRICK_DEBUG_MEM
	if (order > 1) {
		void *test = data - PAGE_SIZE;
		int magic = INT_ACCESS(test, 0);
		int line = INT_ACCESS(test, sizeof(int));
		int oldlen = INT_ACCESS(test, sizeof(int)*2);
		int magic1 = INT_ACCESS(data, -1 * sizeof(int));
		int magic2;

		if (unlikely(magic1 != MAGIC_BLOCK)) {
			BRICK_ERR("line %d memory corruption: magix1 %08x != %08x\n", cline, magic1, MAGIC_BLOCK);
			return;
		}
		if (unlikely(magic != MAGIC_BLOCK)) {
			BRICK_ERR("line %d memory corruption: magix %08x != %08x\n", cline, magic, MAGIC_BLOCK);
			return;
		}
		if (unlikely(line < 0 || line >= BRICK_DEBUG_MEM)) {
			BRICK_ERR("line %d memory corruption: alloc line = %d\n", cline, line);
			return;
		}
		if (unlikely(oldlen != len)) {
			BRICK_ERR("line %d memory corruption: len != oldlen (%d != %d)\n", cline, len, oldlen);
			return;
		}
		magic2 = INT_ACCESS(data, len);
		if (unlikely(magic2 != MAGIC_BEND)) {
			BRICK_ERR("line %d memory corruption: magix %08x != %08x\n", cline, magic, MAGIC_BEND);
			return;
		}
		INT_ACCESS(test, 0) = 0xffffffff;
		INT_ACCESS(data, len) = 0xffffffff;
		data = test;
		atomic_dec(&block_count[line]);
		atomic_inc(&block_free[line]);
	} else if (order == 1) {
		void *test = data + PAGE_SIZE;
		int magic  = INT_ACCESS(test, 0 * sizeof(int));
		int line   = INT_ACCESS(test, 1 * sizeof(int));
		int oldlen = INT_ACCESS(test, 2 * sizeof(int));

		if (unlikely(magic != MAGIC_BLOCK)) {
			BRICK_ERR("line %d memory corruption: magix %08x != %08x\n", cline, magic, MAGIC_BLOCK);
			return;
		}
		if (unlikely(line < 0 || line >= BRICK_DEBUG_MEM)) {
			BRICK_ERR("line %d memory corruption: alloc line = %d\n", cline, line);
			return;
		}
		if (unlikely(oldlen != len)) {
			BRICK_ERR("line %d memory corruption: len != oldlen (%d != %d)\n", cline, len, oldlen);
			return;
		}
		atomic_dec(&block_count[line]);
		atomic_inc(&block_free[line]);
	}
#endif
#ifdef CONFIG_MARS_MEM_PREALLOC
	if (order > 0 && brick_allow_freelist && atomic_read(&freelist_count[order]) <= brick_mem_freelist_max[order]) {
		_put_free(data, order);
	} else
#endif
		__brick_block_free(data, order);

#ifdef CONFIG_MARS_MEM_PREALLOC
	brick_mem_alloc_count[order] = atomic_dec_return(&_alloc_count[order]);
#endif
}
EXPORT_SYMBOL_GPL(_brick_block_free);

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

	BRICK_INF("======== page allocation:\n");
#ifdef CONFIG_MARS_MEM_PREALLOC
	for (i = 0; i <= BRICK_MAX_ORDER; i++) {
		BRICK_INF("pages order = %2d "
			  "operations = %9d "
			  "freelist_count = %4d / %3d "
			  "raw_count = %5d "
			  "alloc_count = %5d "
			  "alloc_len = %5d "
			  "line = %5d "
			  "max_count = %5d\n",
			  i,
			  atomic_read(&op_count[i]),
			  atomic_read(&freelist_count[i]),
			  brick_mem_freelist_max[i],
			  atomic_read(&raw_count[i]),
			  brick_mem_alloc_count[i],
			  alloc_len[i],
			  alloc_line[i],
			  brick_mem_alloc_max[i]);
	}
#endif
	for (i = 0; i < BRICK_DEBUG_MEM; i++) {
		int val = atomic_read(&block_count[i]);
		if (val) {
			count += val;
			places++;
			BRICK_INF("line %4d: "
				  "%6d allocated "
				  "(last size = %4d, freed = %6d)\n",
				  i,
				  val,
				  block_len[i],
				  atomic_read(&block_free[i]));
		}
	}
	BRICK_INF("======== %d block allocations in %d places (phys=%d)\n", count, places, atomic_read(&phys_block_alloc));
	count = places = 0;
	for (i = 0; i < BRICK_DEBUG_MEM; i++) {
		int val = atomic_read(&mem_count[i]);
		if (val) {
			count += val;
			places++;
			BRICK_INF("line %4d: "
				  "%6d allocated "
				  "(last size = %4d, freed = %6d)\n",
				  i,
				  val,
				  mem_len[i],
				  atomic_read(&mem_free[i]));
		}
	}
	BRICK_INF("======== %d memory allocations in %d places (phys=%d,redirect=%d)\n",
		  count, places, atomic_read(&phys_mem_alloc), atomic_read(&mem_redirect_alloc));
	count = places = 0;
	for (i = 0; i < BRICK_DEBUG_MEM; i++) {
		int val = atomic_read(&string_count[i]);
		if (val) {
			count += val;
			places++;
			BRICK_INF("line %4d: "
				  "%6d allocated "
				  "(freed = %6d)\n",
				  i,
				  val,
				  atomic_read(&string_free[i]));
		}
	}
	BRICK_INF("======== %d string allocations in %d places (phys=%d)\n", count, places, atomic_read(&phys_string_alloc));
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

	get_total_ram();

	return 0;
}

void __exit exit_brick_mem(void)
{
	BRICK_INF("deallocating memory...\n");
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
