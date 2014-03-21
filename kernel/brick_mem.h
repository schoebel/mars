// (c) 2011 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef BRICK_MEM_H
#define BRICK_MEM_H

#include <linux/mm_types.h>

#define BRICK_DEBUG_MEM 4096

#ifndef CONFIG_MARS_DEBUG_MEM
#undef BRICK_DEBUG_MEM
#endif
#ifdef CONFIG_MARS_DEBUG_ORDER0
#define BRICK_DEBUG_ORDER0
#endif

#define GFP_BRICK GFP_NOIO
//#define GFP_BRICK GFP_KERNEL // can lead to deadlocks!

extern long long brick_global_memavail;
extern long long brick_global_memlimit;
extern atomic64_t brick_global_block_used;

/////////////////////////////////////////////////////////////////////////

// compiler tweaking

/* Some functions are known to return non-null pointer values,
 * at least under some Kconfig conditions.
 *
 * In code like...
 *
 * void *ptr = myfunction();
 * if (unlikely(!ptr)) {
 *         printk("ERROR: this should not happen\n");
 *         goto fail;
 * }
 *
 * ... the dead code elimination of gcc will not remove the if clause
 * because the function might return a NULL value, even if a human
 * would know that myfunction() does not return a NULL value.
 *
 * Unfortunately, the __attribute__((nonnull)) can only be applied
 * to input parameters, but not to the return value.
 *
 * More unfortunately, a small inline wrapper does not help,
 * because it seems that together with the elimination of the wrapper,
 * its nonnull attribute seems to be eliminated alltogether.
 * I don't know whether this is a bug or a feature (or just a weakness).
 *
 * Following is a small hack which solves the problem at least for gcc 4.7.
 *
 * In order to be useful, the -fdelete-null-pointer-checks must be set.
 * Since MARS is superuser-only anyway, enabling this for MARS should not
 * be a security risk
 * (c.f. upstream kernel commit a3ca86aea507904148870946d599e07a340b39bf)
 */
extern inline
void *__mark_ptr_nonnull(void *_ptr)
{
	char *ptr = _ptr;
	// fool gcc to believe that the pointer were dereferenced...
	asm("" : : "X" (*ptr));
	return ptr;
}

/* All the brick memory allocations are guaranteed to succeed when
 * CONFIG_MARS_MEM_RETRY is set. In case of low memory, they will just
 * retry (forever).
 *
 * Allow checking code to be written which works for both cases:
 * CONFIG_MARS_MEM_RETRY is selected, or not.
 */
#ifdef CONFIG_MARS_MEM_RETRY
#define brick_mark_nonnull __mark_ptr_nonnull
#else
#define brick_mark_nonnull(p) (p)
#endif

/////////////////////////////////////////////////////////////////////////

// small memory allocation (use this only for len < PAGE_SIZE)

#define brick_mem_alloc(_len_)						\
	({								\
		void *_res_ = _brick_mem_alloc(_len_, __LINE__);	\
		brick_mark_nonnull(_res_);				\
	})

#define brick_zmem_alloc(_len_)						\
	({								\
		void *_res_ = _brick_mem_alloc(_len_, __LINE__);	\
		_res_ = brick_mark_nonnull(_res_);			\
		if (_res_) {						\
			memset(_res_, 0, _len_);			\
		}							\
		_res_;							\
	})

#define brick_mem_free(_data_)						\
	do {								\
		if (_data_) {						\
			_brick_mem_free(_data_, __LINE__);		\
		}							\
	} while(0)


// don't use the following directly
extern void *_brick_mem_alloc(int len, int line) __attribute__((malloc)) __attribute__((alloc_size(1)));
extern void _brick_mem_free(void *data, int line);

/////////////////////////////////////////////////////////////////////////

// string memory allocation

#define BRICK_STRING_LEN 1024 /* default value when len == 0 */

#define brick_string_alloc(_len_)					\
	({								\
		char *_res_ = _brick_string_alloc((_len_), __LINE__);	\
		(char*)brick_mark_nonnull(_res_);			\
	})

#define brick_strndup(_orig_,_len_)					\
	({								\
		char *_res_ = _brick_string_alloc((_len_) + 1, __LINE__); \
		_res_ = brick_mark_nonnull(_res_);			\
		if (_res_) {						\
			strncpy(_res_, (_orig_), (_len_) + 1);		\
			/* always null-terminate for safety */		\
			_res_[_len_] = '\0';				\
		}							\
		(char*)brick_mark_nonnull(_res_);			\
	})

#define brick_strdup(_orig_)						\
	({								\
		int _len_ = strlen(_orig_);				\
		char *_res_ = _brick_string_alloc((_len_) + 1, __LINE__); \
		_res_ = brick_mark_nonnull(_res_);			\
		if (_res_) {						\
			strncpy(_res_, (_orig_), (_len_) + 1);		\
		}							\
		(char*)brick_mark_nonnull(_res_);			\
	})

#define brick_string_free(_data_)					\
	do {								\
		if (_data_) {						\
			_brick_string_free(_data_, __LINE__);		\
		}							\
	} while(0)

// don't use the following directly
extern char *_brick_string_alloc(int len, int line) __attribute__((malloc));
extern void _brick_string_free(const char *data, int line);

/////////////////////////////////////////////////////////////////////////

// block memory allocation (for aligned multiples of 512 resp PAGE_SIZE)

#define brick_block_alloc(_pos_,_len_)					\
	({								\
		void *_res_ = _brick_block_alloc((_pos_), (_len_), __LINE__); \
		brick_mark_nonnull(_res_);				\
	})

#define brick_block_free(_data_,_len_)\
	do {								\
		if (_data_) {						\
			_brick_block_free((_data_), (_len_), __LINE__);	\
		}							\
	} while(0)

extern struct page *brick_iomap(void *data, int *offset, int *len);

// don't use the following directly
extern void *_brick_block_alloc(loff_t pos, int len, int line) __attribute__((malloc)) __attribute__((alloc_size(2)));
extern void _brick_block_free(void *data, int len, int cline);

/////////////////////////////////////////////////////////////////////////

// reservations / preallocation

#define BRICK_MAX_ORDER 11

#ifdef CONFIG_MARS_MEM_PREALLOC
extern int brick_allow_freelist;

extern int brick_pre_reserve[BRICK_MAX_ORDER+1];
extern int brick_mem_freelist_max[BRICK_MAX_ORDER+1];
extern int brick_mem_alloc_count[BRICK_MAX_ORDER+1];
extern int brick_mem_alloc_max[BRICK_MAX_ORDER+1];

extern int brick_mem_reserve(void);

#endif

extern void brick_mem_statistics(bool final);

/////////////////////////////////////////////////////////////////////////

// init

#ifdef CONFIG_MARS_HAVE_BIGMODULE
#undef __exit
#define __exit /*empty*/
#endif

extern int init_brick_mem(void);
extern void exit_brick_mem(void);

#endif
