/*
 * MARS Long Distance Replication Software
 *
 * This file is part of MARS project: http://schoebel.github.io/mars/
 *
 * Copyright (C) 2010-2014 Thomas Schoebel-Theuer
 * Copyright (C) 2011-2014 1&1 Internet AG
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING
//#define IO_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/moduleparam.h>

#include "mars.h"
#include "mars_net.h"

#define MAX_FIELD_LEN   (32 + 16)

////////////////////////////////////////////////////////////////////

// Compatibility to old network data format: to be removed for kernel upstream

int use_old_format = 0;

struct mars_desc_cache_old {
	u64   cache_sender_cookie;
	u64   cache_recver_cookie;
	s32   cache_items;
};

struct mars_desc_item_old {
	char  field_name[32];
	s32   field_type;
	s32   field_size;
	s32   field_sender_offset;
	s32   field_recver_offset;
};

static
int _add_fields_old(struct mars_desc_item_old *mi, const struct meta *meta, int offset, const char *prefix, int maxlen)
{
	int count = 0;
	for (; meta->field_name != NULL; meta++) {
		const char *new_prefix;
		int new_offset;
		int len;

		new_prefix = mi->field_name;
		new_offset = offset + meta->field_offset;

		if (unlikely(maxlen < sizeof(struct mars_desc_item_old))) {
			MARS_ERR("desc cache item overflow\n");
			count = -1;
			goto done;
		}
		
		len = scnprintf(mi->field_name, MAX_FIELD_LEN, "%s.%s", prefix, meta->field_name);
		if (unlikely(len >= MAX_FIELD_LEN)) {
			MARS_ERR("field len overflow on '%s.%s'\n", prefix, meta->field_name);
			count = -1;
			goto done;
		}
		mi->field_type = meta->field_type;
		// the old model used no FIELD_RAW or FIELD_UINT
		if (mi->field_type >= FIELD_RAW)
			mi->field_type = FIELD_INT;
		mi->field_size = meta->field_data_size;
		mi->field_sender_offset = new_offset;
		mi->field_recver_offset = -1;

		mi++;
		maxlen -= sizeof(struct mars_desc_item_old);
		count++;

		if (meta->field_type == FIELD_SUB) {
			int sub_count;
			sub_count = _add_fields_old(mi, meta->field_ref, new_offset, new_prefix, maxlen);
			if (sub_count < 0)
				return sub_count;

			mi += sub_count;
			count += sub_count;
			maxlen -= sub_count * sizeof(struct mars_desc_item_old);
		}
	}
done:
	return count;
}

static
struct mars_desc_cache_old *make_sender_cache_old(struct mars_socket *msock, const struct meta *meta, int *cache_index)
{
	int orig_len = PAGE_SIZE;
	int maxlen = orig_len;
	struct mars_desc_cache_old *mc;
	struct mars_desc_item_old *mi;
	int i;
	int status;

	for (i = 0; i < MAX_DESC_CACHE; i++) {
		mc = (void *)msock->s_desc_send[i];
		if (!mc)
			break;
		if (mc->cache_sender_cookie == (u64)meta)
			goto done;
	}

	if (unlikely(i >= MAX_DESC_CACHE - 1)) {
		MARS_ERR("#%d desc cache overflow\n", msock->s_debug_nr);
		return NULL;
	}

	mc = brick_block_alloc(0, maxlen);
	if (unlikely(!mc)) {
		MARS_ERR("#%d desc cache alloc error\n", msock->s_debug_nr);
		goto done;
	}

	memset(mc, 0, maxlen);
	mc->cache_sender_cookie = (u64)meta;

	maxlen -= sizeof(struct mars_desc_cache_old);
	mi = (void*)(mc + 1);

	status = _add_fields_old(mi, meta, 0, "", maxlen);

	if (likely(status > 0)) {
		mc->cache_items = status;
		msock->s_desc_send[i] = (void *)mc;
		*cache_index = i;
	} else {
		brick_block_free(mc, orig_len);
		mc = NULL;
	}

done:
	return mc;
}

static
int _make_recver_cache_old(struct mars_desc_cache_old *mc, const struct meta *meta, int offset, const char *prefix)
{
	char *tmp = brick_string_alloc(MAX_FIELD_LEN);
	int count = 0;
	int i;

	for (; meta->field_name != NULL; meta++, count++) {
		snprintf(tmp, MAX_FIELD_LEN, "%s.%s", prefix, meta->field_name);
		for (i = 0; i < mc->cache_items; i++) {
			struct mars_desc_item_old *mi = ((struct mars_desc_item_old *)(mc + 1)) + i;
			if (!strcmp(tmp, mi->field_name)) {
				mi->field_recver_offset = offset + meta->field_offset;
				if (meta->field_type == FIELD_SUB) {
					int sub_count = _make_recver_cache_old(mc, meta->field_ref, mi->field_recver_offset, tmp);
					if (unlikely(sub_count <= 0)) {
						count = 0;
						goto done;
					}
				}
				goto found;
			}
		}
		if (unlikely(!count)) {
			MARS_ERR("field '%s' is missing\n", meta->field_name);
			goto done;
		}
		MARS_WRN("field %2d '%s' is missing\n", count, meta->field_name);
	found:;
	}
 done:
	brick_string_free(tmp);
	return count;
}

static
int make_recver_cache_old(struct mars_desc_cache_old *mc, const struct meta *meta)
{
	int count;
	int i;

	mc->cache_recver_cookie = (u64)meta;
	count = _make_recver_cache_old(mc, meta, 0, "");

	for (i = 0; i < mc->cache_items; i++) {
		struct mars_desc_item_old *mi = ((struct mars_desc_item_old *)(mc + 1)) + i;
		if (unlikely(mi->field_recver_offset < 0)) {
			MARS_WRN("field '%s' is not transferred\n", mi->field_name);
		}
	}
	return count;
}

static
int _desc_send_item_old(struct mars_socket *msock, const void *data, const struct mars_desc_cache_old *mc, int index, bool cork)
{
	struct mars_desc_item_old *mi = ((struct mars_desc_item_old *)(mc + 1)) + index;
	const void *item = data + mi->field_sender_offset;
	int len = mi->field_size;
	int status;
	int res = -1;

	switch (mi->field_type) {
	case FIELD_REF:
		MARS_ERR("NYI\n");
		goto done;
	case FIELD_SUB:
		/* skip this */
		res = 0;
		break;
	case FIELD_STRING:
		item = *(void**)item;
		len = 0;
		if (item)
			len = strlen(item) + 1;

		status = mars_send_raw(msock, &len, sizeof(len), cork || len > 0);
		if (unlikely(status < 0))
			goto done;
		/* fallthrough */
	default:
		if (likely(len > 0)) {
			status = mars_send_raw(msock, item, len, cork);
			if (unlikely(status < 0))
				goto done;
		}
		res = len;
	}
done:
	return res;
}

static
int _desc_recv_item_old(struct mars_socket *msock, void *data, const struct mars_desc_cache_old *mc, int index, int line)
{
	struct mars_desc_item_old *mi = ((struct mars_desc_item_old *)(mc + 1)) + index;
	void *item = NULL;
	int len = mi->field_size;
	int status;
	int res = -1;

	if (likely(data && mi->field_recver_offset >= 0)) {
		item = data + mi->field_recver_offset;
	}

	switch (mi->field_type) {
	case FIELD_REF:
		MARS_ERR("NYI\n");
		goto done;
	case FIELD_SUB:
		/* skip this */
		res = 0;
		break;
	case FIELD_STRING:
		len = 0;
		status = mars_recv_raw(msock, &len, sizeof(len), sizeof(len));
		if (unlikely(status < 0))
			goto done;

		if (len > 0 && item) {
			char *str = _brick_string_alloc(len, line);
			if (unlikely(!str)) {
				MARS_ERR("#%d string alloc error\n", msock->s_debug_nr);
				goto done;
			}
			*(void**)item = str;
			item = str;
		}

		/* fallthrough */
	default:
		if (likely(len > 0)) {
			status = mars_recv_raw(msock, item, len, len);
			if (unlikely(status < 0))
				goto done;
		}
		res = len;
	}
done:
	return res;
}

#define MARS_DESC_MAGIC_OLD 0x73f0A2ec6148f48dll

struct mars_desc_header_old {
	u64 h_magic;
	u64 h_cookie;
	s16 h_meta_len;
	s16 h_index;
};

static inline
int _desc_send_struct_old(struct mars_socket *msock, int cache_index, const void *data, int h_meta_len, bool cork)
{
	const struct mars_desc_cache_old *mc = (void *)msock->s_desc_send[cache_index];
	struct mars_desc_header_old header = {
		.h_magic = MARS_DESC_MAGIC_OLD,
		.h_cookie = mc->cache_sender_cookie,
		.h_meta_len = h_meta_len,
		.h_index = data ? cache_index : -1,
	};
	int index;
	int count = 0;
	int status = 0;

	status = mars_send_raw(msock, &header, sizeof(header), cork || data);
	if (unlikely(status < 0))
		goto err;

	if (unlikely(h_meta_len > 0)) {
		status = mars_send_raw(msock, mc, h_meta_len, true);
		if (unlikely(status < 0))
			goto err;
	}

	if (likely(data)) {
		for (index = 0; index < mc->cache_items; index++) {
			status = _desc_send_item_old(msock, data, mc, index, cork || index < mc->cache_items-1);
			if (unlikely(status < 0))
				goto err;
			count++;
		}
	}

	if (status >= 0)
		status = count;
err:
	return status;
}

int desc_send_struct_old(struct mars_socket *msock, const void *data, const struct meta *meta, bool cork)
{
	struct mars_desc_cache_old *mc;
	int i;
	int h_meta_len = 0;
	int status = -EINVAL;

	for (i = 0; i < MAX_DESC_CACHE; i++) {
		mc = (void *)msock->s_desc_send[i];
		if (!mc)
			break;
		if (mc->cache_sender_cookie == (u64)meta)
			goto found;
	}

	mc = make_sender_cache_old(msock, meta, &i);
	if (unlikely(!mc))
		goto done;

	h_meta_len = mc->cache_items * sizeof(struct mars_desc_item_old) + sizeof(struct mars_desc_cache_old);

found:
	status = _desc_send_struct_old(msock, i, data, h_meta_len, cork);

done:
	return status;
}

int desc_recv_struct_old(struct mars_socket *msock, void *data, const struct meta *meta, int line)
{
	struct mars_desc_header_old header = {};
	struct mars_desc_cache_old *mc;
	int cache_index; 
	int index;
	int count = 0;
	int status = 0;

	status = mars_recv_raw(msock, &header, sizeof(header), sizeof(header));
	if (unlikely(status < 0))
		goto err;

	if (unlikely(header.h_magic != MARS_DESC_MAGIC_OLD)) {
		MARS_WRN("#%d called from line %d bad packet header magic = %llx\n", msock->s_debug_nr, line, header.h_magic);
		use_old_format = 0;
		status = -ENOMSG;
		goto err;
	}

	cache_index = header.h_index;
	if (cache_index < 0) { // EOR
		goto done;
	}
	if (unlikely(cache_index >= MAX_DESC_CACHE - 1)) {
		MARS_WRN("#%d called from line %d bad cache index %d\n", msock->s_debug_nr, line, cache_index);
		status = -EBADF;
		goto err;
	}

	mc = (void *)msock->s_desc_recv[cache_index];
	if (unlikely(!mc)) {
		if (unlikely(header.h_meta_len <= 0)) {
			MARS_WRN("#%d called from line %d missing meta information\n", msock->s_debug_nr, line);
			status = -ENOMSG;
			goto err;
		}

		mc = _brick_block_alloc(0, PAGE_SIZE, line);
		if (unlikely(!mc)) {
			MARS_WRN("#%d called from line %d out of memory\n", msock->s_debug_nr, line);
			status = -ENOMEM;
			goto err;
		}

		status = mars_recv_raw(msock, mc, header.h_meta_len, header.h_meta_len);
		if (unlikely(status < 0)) {
			brick_block_free(mc, PAGE_SIZE);
			goto err;
		}

		status = make_recver_cache_old(mc, meta);
		if (unlikely(status < 0)) {
			brick_block_free(mc, PAGE_SIZE);
			goto err;
		}
		msock->s_desc_recv[cache_index] = (void *)mc;
	} else if (unlikely(header.h_meta_len > 0)) {
		MARS_WRN("#%d called from line %d has %d unexpected meta bytes\n", msock->s_debug_nr, line, header.h_meta_len);
		status = -EMSGSIZE;
		goto err;
	} else if (unlikely(mc->cache_recver_cookie != (u64)meta)) {
		MARS_ERR("#%d protocol error %p != %p\n", msock->s_debug_nr, meta, (void*)mc->cache_recver_cookie);
		status = -EPROTO;
		goto err;
	}

	for (index = 0; index < mc->cache_items; index++) {
		status = _desc_recv_item_old(msock, data, mc, index, line);
		if (unlikely(status < 0))
			goto err;
		count++;
	}

done:
	if (status >= 0)
		status = count;
err:
	return status;
}
