// (c) 2011 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef BRICK_MEM_H
#define BRICK_MEM_H

#include <linux/mm_types.h>

#define GFP_BRICK GFP_NOIO
//#define GFP_BRICK GFP_KERNEL // can lead to deadlocks!

extern long long brick_global_memlimit;

/////////////////////////////////////////////////////////////////////////

// small memory allocation (use this only for len < PAGE_SIZE)

#define brick_mem_alloc(_len_) _brick_mem_alloc(_len_, __LINE__)
#define brick_zmem_alloc(_len_) ({ void *_res_ = _brick_mem_alloc(_len_, __LINE__); if (_res_) { memset(_res_, 0, _len_); } _res_; })
extern void *_brick_mem_alloc(int len, int line);
#define brick_mem_free(_data_) _brick_mem_free(_data_, __LINE__)
extern void _brick_mem_free(void *data, int line);

/////////////////////////////////////////////////////////////////////////

// string memory allocation

#define BRICK_STRING_LEN 1024 /* default value when len == 0 */

#define brick_string_alloc(_len_) _brick_string_alloc(_len_, __LINE__)
#define brick_strndup(_orig_,_len_) ({ char *_res_ = _brick_string_alloc((_len_) + 1, __LINE__); if (_res_) { strncpy(_res_, _orig_, (_len_)); _res_[_len_] = '\0';} _res_; })
#define brick_strdup(_orig_) ({ int _len_ = strlen(_orig_); char *_res_ = _brick_string_alloc(_len_ + 1, __LINE__); if (_res_) { strncpy(_res_, _orig_, _len_ + 1); } _res_; })
extern char *_brick_string_alloc(int len, int line);
#define brick_string_free(_data_) _brick_string_free(_data_, __LINE__)
extern void _brick_string_free(const char *data, int line);

extern void brick_mem_statistics(void);

/////////////////////////////////////////////////////////////////////////

// block memory allocation (for aligned multiples of 512 resp PAGE_SIZE)

#define brick_block_alloc(_pos_,_len_) _brick_block_alloc(_pos_, _len_, __LINE__)
extern void *_brick_block_alloc(loff_t pos, int len, int line);
extern void _brick_block_free(void *data, int len, int cline);
#define brick_block_free(_data_,_len_) _brick_block_free(_data_, _len_, __LINE__)
extern struct page *brick_iomap(void *data, int *offset, int *len);


/////////////////////////////////////////////////////////////////////////

// reservations / preallocation

#define BRICK_MAX_ORDER 11

extern bool brick_allow_freelist;

struct mem_reservation {
	int amount[BRICK_MAX_ORDER+1];
};

extern int brick_mem_reserve(struct mem_reservation *r);

/////////////////////////////////////////////////////////////////////////

// init

extern int init_brick_mem(void);
extern void exit_brick_mem(void);

#endif
