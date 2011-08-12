// (c) 2011 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef BRICK_MEM_H
#define BRICK_MEM_H

#include <linux/mm_types.h>

#define GFP_BRICK GFP_NOIO
//#define GFP_BRICK GFP_KERNEL // can lead to deadlocks!

/////////////////////////////////////////////////////////////////////////

// small memory allocation (use this only for len < PAGE_SIZE)

#define brick_mem_alloc(len) _brick_mem_alloc(len, __LINE__)
#define brick_zmem_alloc(len) ({ void *_res_ = _brick_mem_alloc(len, __LINE__); if (_res_) { memset(_res_, 0, len); } _res_; })
extern void *_brick_mem_alloc(int len, int line);
#define brick_mem_free(data) _brick_mem_free(data, __LINE__)
extern void _brick_mem_free(void *data, int line);

/////////////////////////////////////////////////////////////////////////

// string memory allocation

#define brick_string_alloc() _brick_string_alloc(__LINE__)
#define brick_strdup(orig) ({ char *_res_ = _brick_string_alloc(__LINE__); if (_res_) { strcpy(_res_, orig); } _res_; })
extern char *_brick_string_alloc(int line);
#define brick_string_free(data) _brick_string_free(data, __LINE__)
extern void _brick_string_free(const char *data, int line);

extern void brick_mem_statistics(void);

/////////////////////////////////////////////////////////////////////////

// block memory allocation (for aligned multiples of 512 resp PAGE_SIZE)

#define brick_block_alloc(pos,len) _brick_block_alloc(pos, len, __LINE__)
extern void *_brick_block_alloc(loff_t pos, int len, int line);
extern void brick_block_free(void *data, int len);
extern struct page *brick_iomap(void *data, int *offset, int *len);


#endif
