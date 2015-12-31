/*
 * MARS Long Distance Replication Software
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
 */


#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/file.h>
#include <linux/fs.h>

#include "xio.h"

/************************************************************/

/*  infrastructure */

struct banning xio_global_ban = {};
atomic_t xio_global_io_flying = ATOMIC_INIT(0);

/************************************************************/

/*  object stuff */

const struct generic_object_type aio_type = {
	.object_type_name = "aio",
	.default_size = sizeof(struct aio_object),
	.object_type_nr = OBJ_TYPE_AIO,
};

/************************************************************/

/*  brick stuff */

/*******************************************************************/

/*  meta descriptions */

const struct meta xio_info_meta[] = {
	META_INI(current_size,	  struct xio_info, FIELD_INT),
	META_INI(tf_align,	  struct xio_info, FIELD_INT),
	META_INI(tf_min_size,	  struct xio_info, FIELD_INT),
	{}
};

const struct meta xio_aio_user_meta[] = {
	META_INI(_object_cb.cb_error, struct aio_object, FIELD_INT),
	META_INI(io_pos,	   struct aio_object, FIELD_INT),
	META_INI(io_len,	   struct aio_object, FIELD_INT),
	META_INI(io_may_write,	  struct aio_object, FIELD_INT),
	META_INI(io_prio,	   struct aio_object, FIELD_INT),
	META_INI(io_cs_mode,	   struct aio_object, FIELD_INT),
	META_INI(io_timeout,	   struct aio_object, FIELD_INT),
	META_INI(io_total_size,   struct aio_object, FIELD_INT),
	META_INI(io_checksum,	   struct aio_object, FIELD_RAW),
	META_INI(io_flags,	   struct aio_object, FIELD_INT),
	META_INI(io_rw,    struct aio_object, FIELD_INT),
	META_INI(io_id,    struct aio_object, FIELD_INT),
	META_INI(io_skip_sync,	  struct aio_object, FIELD_INT),
	{}
};

const struct meta xio_timespec_meta[] = {
	META_INI_TRANSFER(tv_sec,  struct timespec, FIELD_UINT, 8),
	META_INI_TRANSFER(tv_nsec, struct timespec, FIELD_UINT, 4),
	{}
};

/************************************************************/

/*  crypto stuff */

#include <linux/scatterlist.h>
#include <linux/crypto.h>

static struct crypto_hash *xio_tfm;
static struct semaphore tfm_sem;
int xio_digest_size;

void xio_digest(unsigned char *digest, void *data, int len)
{
	struct hash_desc desc = {
		.tfm = xio_tfm,
		.flags = 0,
	};
	struct scatterlist sg;

	memset(digest, 0, xio_digest_size);

	/*  TODO: use per-thread instance, omit locking */
	down(&tfm_sem);

	crypto_hash_init(&desc);
	sg_init_table(&sg, 1);
	sg_set_buf(&sg, data, len);
	crypto_hash_update(&desc, &sg, sg.length);
	crypto_hash_final(&desc, digest);
	up(&tfm_sem);
}

void aio_checksum(struct aio_object *aio)
{
	unsigned char checksum[xio_digest_size];
	int len;

	if (aio->io_cs_mode <= 0 || !aio->io_data)
		goto out_return;
	xio_digest(checksum, aio->io_data, aio->io_len);

	len = sizeof(aio->io_checksum);
	if (len > xio_digest_size)
		len = xio_digest_size;
	memcpy(&aio->io_checksum, checksum, len);
out_return:;
}

/*******************************************************************/

/*  init stuff */

int __init init_xio(void)
{
	XIO_INF("init_xio()\n");

	sema_init(&tfm_sem, 1);

	xio_tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
	if (!xio_tfm) {
		XIO_ERR("cannot alloc crypto hash\n");
		return -ENOMEM;
	}
	if (IS_ERR(xio_tfm)) {
		XIO_ERR("alloc crypto hash failed, status = %d\n", (int)PTR_ERR(xio_tfm));
		return PTR_ERR(xio_tfm);
	}
	xio_digest_size = crypto_hash_digestsize(xio_tfm);
	XIO_INF("digest_size = %d\n", xio_digest_size);

	return 0;
}

void exit_xio(void)
{
	XIO_INF("exit_xio()\n");

	if (xio_tfm)
		crypto_free_hash(xio_tfm);
}
