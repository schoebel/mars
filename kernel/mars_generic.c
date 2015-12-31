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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/file.h>
#include <linux/fs.h>

#include "mars.h"

//////////////////////////////////////////////////////////////

// infrastructure

struct banning mars_global_ban = {};
atomic_t mars_global_io_flying = ATOMIC_INIT(0);

//////////////////////////////////////////////////////////////

// object stuff

const struct generic_object_type mref_type = {
        .object_type_name = "mref",
        .default_size = sizeof(struct mref_object),
	.object_type_nr = OBJ_TYPE_MREF,
};

//////////////////////////////////////////////////////////////

// brick stuff

/////////////////////////////////////////////////////////////////////

// meta descriptions

const struct meta mars_info_meta[] = {
	META_INI(current_size,    struct mars_info, FIELD_INT),
	META_INI(tf_align,        struct mars_info, FIELD_INT),
	META_INI(tf_min_size,     struct mars_info, FIELD_INT),
	{}
};

const struct meta mars_mref_meta[] = {
	META_INI(_object_cb.cb_error, struct mref_object, FIELD_INT),
	META_INI(ref_pos,          struct mref_object, FIELD_INT),
	META_INI(ref_len,          struct mref_object, FIELD_INT),
	META_INI(ref_may_write,    struct mref_object, FIELD_INT),
	META_INI(ref_prio,         struct mref_object, FIELD_INT),
	META_INI(ref_cs_mode,      struct mref_object, FIELD_INT),
	META_INI(ref_timeout,      struct mref_object, FIELD_INT),
	META_INI(ref_total_size,   struct mref_object, FIELD_INT),
	META_INI(ref_checksum,     struct mref_object, FIELD_RAW),
	META_INI(ref_flags,        struct mref_object, FIELD_INT),
	META_INI(ref_rw,           struct mref_object, FIELD_INT),
	META_INI(ref_id,           struct mref_object, FIELD_INT),
	META_INI(ref_skip_sync,    struct mref_object, FIELD_INT),
	{}
};

const struct meta mars_timespec_meta[] = {
	META_INI_TRANSFER(tv_sec,  struct timespec, FIELD_UINT, 8),
	META_INI_TRANSFER(tv_nsec, struct timespec, FIELD_UINT, 4),
	{}
};


//////////////////////////////////////////////////////////////

// crypto stuff

#include <linux/scatterlist.h>
#include <linux/crypto.h>

static struct crypto_hash *mars_tfm;
static struct semaphore tfm_sem;
int mars_digest_size;

void mars_digest(unsigned char *digest, void *data, int len)
{
	struct hash_desc desc = {
		.tfm = mars_tfm,
		.flags = 0,
	};
	struct scatterlist sg;

	memset(digest, 0, mars_digest_size);

	// TODO: use per-thread instance, omit locking
	down(&tfm_sem);

	crypto_hash_init(&desc);
	sg_init_table(&sg, 1);
	sg_set_buf(&sg, data, len);
	crypto_hash_update(&desc, &sg, sg.length);
	crypto_hash_final(&desc, digest);
	up(&tfm_sem);
}

void mref_checksum(struct mref_object *mref)
{
	unsigned char checksum[mars_digest_size];
	int len;

	if (mref->ref_cs_mode <= 0 || !mref->ref_data)
		goto out_return;
	mars_digest(checksum, mref->ref_data, mref->ref_len);

	len = sizeof(mref->ref_checksum);
	if (len > mars_digest_size)
		len = mars_digest_size;
	memcpy(&mref->ref_checksum, checksum, len);
out_return:;
}

/////////////////////////////////////////////////////////////////////

// init stuff

int __init init_mars(void)
{
	MARS_INF("init_mars()\n");

	sema_init(&tfm_sem, 1);

	mars_tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
	if (!mars_tfm) {
		MARS_ERR("cannot alloc crypto hash\n");
		return -ENOMEM;
	}
	if (IS_ERR(mars_tfm)) {
		MARS_ERR("alloc crypto hash failed, status = %d\n", (int)PTR_ERR(mars_tfm));
		return PTR_ERR(mars_tfm);
	}
	mars_digest_size = crypto_hash_digestsize(mars_tfm);
	MARS_INF("digest_size = %d\n", mars_digest_size);

	return 0;
}

void exit_mars(void)
{
	MARS_INF("exit_mars()\n");

	if (mars_tfm) {
		crypto_free_hash(mars_tfm);
	}
}
