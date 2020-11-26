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
#include <linux/utsname.h>

#include "mars.h"
#include "mars_client.h"

//////////////////////////////////////////////////////////////

// infrastructure

struct banning mars_global_ban = {};
EXPORT_SYMBOL_GPL(mars_global_ban);
atomic_t mars_global_io_flying = ATOMIC_INIT(0);
EXPORT_SYMBOL_GPL(mars_global_io_flying);

static char id[__NEW_UTS_LEN + 2] = {};
static int id_len = 0;

/* TODO: use MAC addresses (or motherboard IDs etc) for _validation_
 * of nodenames.
 * When the nodename is misconfigured, data might be scrambled.
 * In ideal case, further checks should be added to prohibit accidental
 * name clashes.
 */
char *my_id(void)
{
	if (unlikely(!id[0])) {
		struct new_utsname *u;

		//down_read(&uts_sem); // FIXME: this is currenty not EXPORTed from the kernel!
		u = utsname();
		if (u) {
			strncpy(id, u->nodename, sizeof(id));
			id_len = strlen(id);
		}
		//up_read(&uts_sem);
	}
	return id;
}

int my_id_len(void)
{
	return id_len;
}

//////////////////////////////////////////////////////////////

// object stuff

const struct generic_object_type mref_type = {
        .object_type_name = "mref",
        .default_size = sizeof(struct mref_object),
	.object_type_nr = OBJ_TYPE_MREF,
};
EXPORT_SYMBOL_GPL(mref_type);

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
EXPORT_SYMBOL_GPL(mars_info_meta);

const struct meta mars_mref_meta[] = {
	META_INI(_object_cb.cb_error, struct mref_object, FIELD_INT),
	META_INI(ref_pos,          struct mref_object, FIELD_INT),
	META_INI(ref_len,          struct mref_object, FIELD_INT),
	META_INI(ref_may_write,    struct mref_object, FIELD_INT),
	META_INI(ref_prio,         struct mref_object, FIELD_INT),
	META_INI(ref_cs_mode,      struct mref_object, FIELD_INT),
	META_INI(ref_timeout,      struct mref_object, FIELD_INT),
	META_INI(ref_total_size,   struct mref_object, FIELD_INT),
	/* QUIRK: for compatibility with the old layout, we have to
	 * pseudo-split the field.
	 * TODO: port "make data transfer independent from register size and bytesex"
	 * and then revert this to its old simple form.
	 * However, all old instances must have been updated before.
	 */
	{
		__META_INI(ref_checksum,   FIELD_RAW,
			   OLD_MARS_DIGEST_SIZE,
			   offsetof(struct mref_object, ref_checksum)),
	},
	{
		__META_INI(ref_checksum_pseudo,   FIELD_RAW,
			   MARS_DIGEST_SIZE - OLD_MARS_DIGEST_SIZE,
			   offsetof(struct mref_object, ref_checksum)
			   + OLD_MARS_DIGEST_SIZE),
	},
	META_INI(ref_flags,        struct mref_object, FIELD_UINT),
	META_INI(ref_rw,           struct mref_object, FIELD_INT),
	META_INI(ref_id,           struct mref_object, FIELD_INT),
	META_INI(ref_skip_sync,    struct mref_object, FIELD_INT),
	{}
};
EXPORT_SYMBOL_GPL(mars_mref_meta);

const struct meta mars_lamport_time_meta[] = {
	META_INI(tv_sec,  struct lamport_time, FIELD_INT),
	META_INI(tv_nsec, struct lamport_time, FIELD_INT),
	{}
};
EXPORT_SYMBOL_GPL(mars_lamport_time_meta);


//////////////////////////////////////////////////////////////

// crypto stuff

#define MD5_DIGEST_SIZE 16

__u32 available_digest_mask = MREF_CHKSUM_MD5_OLD;
__u32 usable_digest_mask = MREF_CHKSUM_MD5_OLD;
__u32 used_log_digest = 0;
__u32 used_net_digest = 0;

#ifdef MARS_HAS_NEW_CRYPTO

/* For now, use shash.
 * Later, asynchronous support should be added for full exploitation
 * of crypto hardware.
 */
#include <crypto/hash.h>

static struct crypto_shash *md5_tfm = NULL;

#ifdef HAS_CRC32C
#define CRC32C_DIGEST_SIZE 4
static struct crypto_shash *crc32c_tfm = NULL;
#endif

#ifdef HAS_CRC32
#define CRC32_DIGEST_SIZE  4
static struct crypto_shash *crc32_tfm = NULL;
#endif

#ifdef HAS_SHA1
#define SHA1_DIGEST_SIZE 20
static struct crypto_shash *sha1_tfm = NULL;
#endif

struct mars_sdesc {
	struct shash_desc shash;
	char ctx[];
};

/* Note:
 * For compatibility to OLD_MARS_DIGEST_SIZE, the higher
 * digest bytes up to MARS_DIGEST_SIZE are not exploited
 * in this version.
 */
static
void md5_old_digest(void *digest, const void *data, int len)
{
	int size = sizeof(struct mars_sdesc) + crypto_shash_descsize(md5_tfm);
	struct mars_sdesc *sdesc = brick_mem_alloc(size);
	int status;

	sdesc->shash.tfm = md5_tfm;
	sdesc->shash.flags = 0;

	memset(digest, 0, MARS_DIGEST_SIZE);
	status = crypto_shash_digest(&sdesc->shash, data, len, digest);
	if (unlikely(status < 0)) {
		MARS_ERR("cannot calculate md5 chksum on %p len=%d, status=%d\n",
			 data, len,
			 status);
		memset(digest, 0, MARS_DIGEST_SIZE);
	}

	brick_mem_free(sdesc);
}

static
void md5_digest(void *digest, const void *data, int len)
{
	int size = sizeof(struct mars_sdesc) + crypto_shash_descsize(md5_tfm);
	struct mars_sdesc *sdesc = brick_mem_alloc(size);
	const int iterations = MARS_DIGEST_SIZE / MD5_DIGEST_SIZE;
	int chunksize = len / iterations;
	int offset = 0;
	int done_len = len;
	int i;
	int status;

	sdesc->shash.tfm = md5_tfm;
	sdesc->shash.flags = 0;

	memset(digest, 0, MARS_DIGEST_SIZE);

	/* exploit the bigger MARS_DIGEST_SIZE by computing MD5 in chunks */
	for (i = 0; i < iterations; i++) {
		char this_digest[MD5_DIGEST_SIZE] = {};

		status = crypto_shash_digest(&sdesc->shash,
					     data + offset,
					     chunksize,
					     this_digest);
		if (unlikely(status < 0)) {
			MARS_ERR("cannot calculate md5 chksum on %p len=%d, status=%d\n",
				 data,
				 chunksize,
				 status);
			memset(digest, 0, MARS_DIGEST_SIZE);
			break;
		}
		memcpy(digest + i * MD5_DIGEST_SIZE,
		       this_digest, MD5_DIGEST_SIZE);
		offset += chunksize;
		done_len -= chunksize;
	}
	if (unlikely(done_len))
		MARS_ERR("md5 chksum remain %d\n", done_len);

	brick_mem_free(sdesc);
}

#ifdef HAS_CRC32C
static
void crc32c_digest(void *digest, const void *data, int len)
{
	int size = sizeof(struct mars_sdesc) + crypto_shash_descsize(crc32c_tfm);
	struct mars_sdesc *sdesc = brick_mem_alloc(size);
	const int iterations = MARS_DIGEST_SIZE / CRC32C_DIGEST_SIZE;
	int chunksize = len / iterations;
	int offset = 0;
	int done_len = len;
	int i;
	int status;

	sdesc->shash.tfm = crc32c_tfm;
	sdesc->shash.flags = 0;
	memset(digest, 0, MARS_DIGEST_SIZE);

	/* exploit the bigger MARS_DIGEST_SIZE by computing CRC32C in chunks */
	for (i = 0; i < iterations; i++) {
		char this_digest[CRC32C_DIGEST_SIZE] = {};

		if (i == iterations - 1)
			chunksize = done_len;

		status = crypto_shash_digest(&sdesc->shash,
					     data + offset, chunksize,
					     this_digest);
		if (unlikely(status < 0)) {
			MARS_ERR("cannot calculate crc32c chksum on %p len=%d, status=%d\n",
				 data, chunksize,
				 status);
			continue;
		}
		memcpy(digest + i * CRC32C_DIGEST_SIZE, this_digest, CRC32C_DIGEST_SIZE);
		offset += chunksize;
		done_len -= chunksize;
	}
	if (unlikely(done_len))
		MARS_ERR("crc32c chksum remain %d\n", done_len);

	brick_mem_free(sdesc);
}
#endif

#ifdef HAS_CRC32
static
void crc32_digest(void *digest, const void *data, int len)
{
	int size = sizeof(struct mars_sdesc) + crypto_shash_descsize(crc32_tfm);
	struct mars_sdesc *sdesc = brick_mem_alloc(size);
	const int iterations = MARS_DIGEST_SIZE / CRC32_DIGEST_SIZE;
	int chunksize = len / iterations;
	int offset = 0;
	int done_len = len;
	int i;
	int status;

	sdesc->shash.tfm = crc32_tfm;
	sdesc->shash.flags = 0;
	memset(digest, 0, MARS_DIGEST_SIZE);

	/* exploit the bigger MARS_DIGEST_SIZE by computing CRC32 in chunks */
	for (i = 0; i < iterations; i++) {
		char this_digest[CRC32_DIGEST_SIZE] = {};

		if (i == iterations - 1)
			chunksize = done_len;

		status = crypto_shash_digest(&sdesc->shash,
					     data + offset, chunksize,
					     this_digest);
		if (unlikely(status < 0)) {
			MARS_ERR("cannot calculate crc32 chksum on %p len=%d, status=%d\n",
				 data, chunksize,
				 status);
			continue;
		}
		memcpy(digest + i * CRC32_DIGEST_SIZE, this_digest, CRC32_DIGEST_SIZE);
		offset += chunksize;
		done_len -= chunksize;
	}
	if (unlikely(done_len))
		MARS_ERR("crc32 chksum remain %d\n", done_len);

	brick_mem_free(sdesc);
}
#endif

#ifdef HAS_SHA1
static
void sha1_digest(void *digest, const void *data, int len)
{
	int size = sizeof(struct mars_sdesc) + crypto_shash_descsize(sha1_tfm);
	struct mars_sdesc *sdesc = brick_mem_alloc(size);
	unsigned char tmp[SHA1_DIGEST_SIZE] = {};
	int status;

	sdesc->shash.tfm = sha1_tfm;
	sdesc->shash.flags = 0;

	status = crypto_shash_digest(&sdesc->shash, data, len, tmp);
	if (unlikely(status < 0)) {
		MARS_ERR("cannot calculate sha1 chksum on %p len=%d, status=%d\n",
			 data, len,
			 status);
		memset(digest, 0, MARS_DIGEST_SIZE);
	} else {
		memcpy(digest, tmp, SHA1_DIGEST_SIZE);
		memset(digest + SHA1_DIGEST_SIZE, 0, 
		       MARS_DIGEST_SIZE - SHA1_DIGEST_SIZE);
	}

	brick_mem_free(sdesc);
}
#endif

__u32 mars_digest(__u32 digest_flags,
		  __u32 *used_flags,
		  void *digest,
		  const void *data, int len)
{
	/* The order defines the preference:
	 * place the most performant algorithms first.
	 */
#ifdef HAS_CRC32C
	if (digest_flags & MREF_CHKSUM_CRC32C && crc32c_tfm) {
		crc32c_digest(digest, data, len);
		if (used_flags)
			*used_flags = MREF_CHKSUM_CRC32C;
		return MREF_CHKSUM_CRC32C;
	}
#endif
#ifdef HAS_CRC32
	if (digest_flags & MREF_CHKSUM_CRC32 && crc32_tfm) {
		crc32_digest(digest, data, len);
		if (used_flags)
			*used_flags = MREF_CHKSUM_CRC32;
		return MREF_CHKSUM_CRC32;
	}
#endif
	if (digest_flags & MREF_CHKSUM_MD5 && md5_tfm) {
		md5_digest(digest, data, len);
		if (used_flags)
			*used_flags = MREF_CHKSUM_MD5;
		return MREF_CHKSUM_MD5;
	}
#ifdef HAS_SHA1
	if (digest_flags & MREF_CHKSUM_SHA1 && sha1_tfm) {
		sha1_digest(digest, data, len);
		if (used_flags)
			*used_flags = MREF_CHKSUM_SHA1;
		return MREF_CHKSUM_SHA1;
	}
#endif

	/* always fallback to old md5 regardless of digest_flags */
	md5_old_digest(digest, data, len);
	if (used_flags)
		*used_flags = MREF_CHKSUM_MD5_OLD;
	return MREF_CHKSUM_MD5_OLD;
}

#ifdef CONFIG_MARS_BENCHMARK

static
void benchmark_digest(char *name, __u32 flags)
{
	unsigned char*testpage = kzalloc(PAGE_SIZE, GFP_KERNEL);
	unsigned char old_test[MARS_DIGEST_SIZE] = {};
	unsigned char new_test[MARS_DIGEST_SIZE];
	long long delta;
	__u32 res_flags;
	unsigned char bit;
	int i;

	usable_digest_mask = MREF_CHKSUM_ANY;

	delta =
		TIME_THIS(
			  for (bit = 1; bit; bit <<= 1) {
				  for (i = 0; i < PAGE_SIZE; i++) {
					  testpage[i] ^= bit;
					  res_flags = mars_digest(flags,
								  NULL,
								  new_test,
								  testpage,
								  PAGE_SIZE);
					  if (unlikely(!(res_flags & flags))) {
						  MARS_ERR("digest %s failed\n",
							   name);
						  goto err;
					  }
					  if (unlikely(!memcmp(old_test, new_test, MARS_DIGEST_SIZE))) {
						  MARS_ERR("digest %s is not good enough\n",
							   name);
						  goto err;
					  }
					  memcpy(old_test, new_test, MARS_DIGEST_SIZE);
				  }
			  }
			  );
	printk("%-10s digest duration = %12lld ns\n",
	       name, delta);
 err:
	kfree(testpage);
	usable_digest_mask = MREF_CHKSUM_MD5_OLD;
}

#endif

static
int init_mars_digest(void)
{
	int status;

	md5_tfm = crypto_alloc_shash("md5", 0, 0);
	if (unlikely(!md5_tfm) || IS_ERR(md5_tfm)) {
		MARS_ERR("cannot alloc crypto hash, status=%ld\n",
			 PTR_ERR(md5_tfm));
		md5_tfm = NULL;
		return -ELIBACC;
	}
	status = crypto_shash_digestsize(md5_tfm);
	if (unlikely(status != MD5_DIGEST_SIZE)) {
		MARS_ERR("md5 bad digest size %d\n", status);
		return -ELIBACC;
	}
	available_digest_mask |= MREF_CHKSUM_MD5;

#ifdef HAS_CRC32C
	crc32c_tfm = crypto_alloc_shash("crc32c", 0, 0);
	if (unlikely(!crc32c_tfm) || IS_ERR(crc32c_tfm)) {
		MARS_ERR("cannot alloc crc32c crypto hash, status=%ld\n",
			 PTR_ERR(crc32c_tfm));
		crc32c_tfm = NULL;
	} else {
		status = crypto_shash_digestsize(crc32c_tfm);
		if (unlikely(status != CRC32C_DIGEST_SIZE)) {
			MARS_ERR("crc32c bad digest size %d\n", status);
			return -ELIBACC;
		}
		available_digest_mask |= MREF_CHKSUM_CRC32C;
	}
#endif
#ifdef HAS_CRC32
	crc32_tfm = crypto_alloc_shash("crc32", 0, 0);
	if (unlikely(!crc32_tfm) || IS_ERR(crc32_tfm)) {
		MARS_ERR("cannot alloc crc32 crypto hash, status=%ld\n",
			 PTR_ERR(crc32_tfm));
		crc32_tfm = NULL;
	} else {
		status = crypto_shash_digestsize(crc32_tfm);
		if (unlikely(status != CRC32_DIGEST_SIZE)) {
			MARS_ERR("crc32 bad digest size %d\n", status);
			return -ELIBACC;
		}
		available_digest_mask |= MREF_CHKSUM_CRC32;
	}
#endif

#ifdef HAS_SHA1
	sha1_tfm = crypto_alloc_shash("sha1", 0, 0);
	if (unlikely(!sha1_tfm) || IS_ERR(sha1_tfm)) {
		MARS_ERR("cannot alloc crypto hash, status=%ld\n",
			 PTR_ERR(sha1_tfm));
		sha1_tfm = NULL;
	} else {
		status = crypto_shash_digestsize(sha1_tfm);
		if (unlikely(status != SHA1_DIGEST_SIZE)) {
			MARS_ERR("sha1 bad digest size %d\n", status);
			return -ELIBACC;
		}
		available_digest_mask |= MREF_CHKSUM_SHA1;
	}
#endif

#ifdef CONFIG_MARS_BENCHMARK
#ifdef HAS_CRC32C
	benchmark_digest("crc32c", MREF_CHKSUM_CRC32C);
#endif
#ifdef HAS_CRC32
	benchmark_digest("crc32",  MREF_CHKSUM_CRC32);
#endif
#ifdef HAS_SHA1
	benchmark_digest("sha1",   MREF_CHKSUM_SHA1);
#endif
	benchmark_digest("md5old", MREF_CHKSUM_MD5_OLD);
	benchmark_digest("md5",    MREF_CHKSUM_MD5);
#endif
	return 0;
}

static
void exit_mars_digest(void)
{
	if (md5_tfm) {
		crypto_free_shash(md5_tfm);
	}
#ifdef HAS_CRC32C
	if (crc32c_tfm) {
		crypto_free_shash(crc32c_tfm);
	}
#endif
#ifdef HAS_CRC32
	if (crc32_tfm) {
		crypto_free_shash(crc32_tfm);
	}
#endif
#ifdef HAS_SHA1
	if (sha1_tfm) {
		crypto_free_shash(sha1_tfm);
	}
#endif
}

#else  /* MARS_HAS_NEW_CRYPTO */

/* Old implementation, to disappear.
 * Was a quick'n dirty lab prototype with unnecessary
 * global variables and locking.
 */

#define OBSOLETE_TFM_MAX 128

static struct crypto_hash *mars_tfm[OBSOLETE_TFM_MAX];
static struct semaphore tfm_sem[OBSOLETE_TFM_MAX];

__u32 mars_digest(__u32 digest_flags,
		  __u32 *used_flags,
		  void *digest,
		  void *data, int len)
{
	static unsigned int round_robin = 0;
	unsigned int i = round_robin++ % OBSOLETE_TFM_MAX;
	struct hash_desc desc = {
		.tfm = mars_tfm[i],
		.flags = 0,
	};
	struct scatterlist sg;

	memset(digest, 0, MARS_DIGEST_SIZE);

	down(&tfm_sem[i]);

	crypto_hash_init(&desc);
	sg_init_table(&sg, 1);
	sg_set_buf(&sg, data, len);
	crypto_hash_update(&desc, &sg, sg.length);
	crypto_hash_final(&desc, digest);
	up(&tfm_sem[i]);
	if (used_flags)
		*used_flags = MREF_CHKSUM_MD5_OLD;
	return MREF_CHKSUM_MD5_OLD;
}

#endif /* MARS_HAS_NEW_CRYPTO */

void mref_checksum(struct mref_object *mref)
{
	unsigned char checksum[MARS_DIGEST_SIZE];
	__u32 digest_flags;
	int len;

	digest_flags = mref->ref_flags & MREF_CHKSUM_ANY;
	if (!digest_flags || !mref->ref_data)
		return;

	digest_flags =
	  mars_digest(digest_flags,
		      &used_net_digest,
		      checksum,
		      mref->ref_data, mref->ref_len);

	mref->ref_flags = (mref->ref_flags & ~MREF_CHKSUM_ANY) | digest_flags;

	len = sizeof(mref->ref_checksum);
	if (len > MARS_DIGEST_SIZE)
		len = MARS_DIGEST_SIZE;
	memcpy(&mref->ref_checksum, checksum, len);
}

/*******************************************************************/

/* compression */

int compress_overhead = 0;

__u32 available_compression_mask =
#ifdef HAS_LZO
	MREF_COMPRESS_LZO |
#endif
#ifdef HAS_LZ4
	MREF_COMPRESS_LZ4 |
#endif
#ifdef HAS_ZLIB
	MREF_COMPRESS_ZLIB |
#endif
	0;

__u32 usable_compression_mask = 0;

__u32 used_compression = 0;

int mars_zlib_compression_level = 3;

int mars_compress(void *src_data,
		  int src_len,
		  void *dst_data,
		  int dst_len,
		  __u32 check_flags,
		  __u32 *result_flags)
{
	void *tmp_buf = dst_data;
	int res = 0;

	check_flags &= usable_compression_mask;
	if (!(check_flags & MREF_COMPRESS_ANY)) {
		used_compression = 0;
		return 0;
	}

	if (unlikely(src_len > MARS_MAX_COMPR_SIZE)) {
		MARS_ERR("tryping to compress %d, more than %ld bytes\n",
			 src_len, MARS_MAX_COMPR_SIZE);
		goto done;
	}

	/* The order determines the preferences */
#ifdef HAS_LZO
	if (check_flags & MREF_COMPRESS_LZO) {
		int max_len = lzo1x_worst_compress(src_len);
		void *wrkmem;
		size_t res_len = 0;
		int status;

		if (!dst_data) {
			tmp_buf = brick_mem_alloc(max_len);
		} else if (dst_len < max_len) {
			MARS_ERR("LZO compression buffer too small: %d < %d\n",
				 dst_len, max_len);
			return 0;
		}
		wrkmem = brick_mem_alloc(LZO1X_1_MEM_COMPRESS);

		status = lzo1x_1_compress(src_data, src_len,
					  tmp_buf, &res_len, wrkmem);

		/* ensure that the result is really smaller */
		if (status == LZO_E_OK &&
		    res_len > 0 &&
		    res_len < src_len) {
			used_compression = MREF_COMPRESS_LZO;
			*result_flags |= MREF_COMPRESS_LZO;
			res = res_len;
			/*
			 * TODO: avoid memcpy() by swizzling the src_data pointer
			 */
			if (!dst_data)
				memcpy(src_data, tmp_buf, res_len);
		}
		brick_mem_free(wrkmem);
		/* do not try other compression methods */
		goto done;
	}
#endif
#ifdef HAS_LZ4
	if (check_flags & MREF_COMPRESS_LZ4) {
#ifdef HAS_FAST_LZ4
		size_t max_len = LZ4_COMPRESSBOUND(src_len);
#else
		size_t max_len = lz4_compressbound(src_len);
#endif
		size_t res_len = 0;
		void *wrkmem;
		int status;

		if (!dst_data) {
			tmp_buf = brick_mem_alloc(max_len);
		} else if (dst_len < max_len) {
			MARS_ERR("LZ4 compression buffer too small: %d < %lu\n",
				 dst_len, max_len);
			return 0;
		}

		wrkmem = brick_block_alloc(0, LZ4_MEM_COMPRESS);

#ifdef HAS_FAST_LZ4
		res_len = LZ4_compress_fast(src_data,
					    tmp_buf,
					    src_len,
					    max_len,
					    LZ4_ACCELERATION_DEFAULT,
					    wrkmem);
		status = 0;
#else
		status = lz4_compress(src_data, src_len,
				      tmp_buf, &res_len,
				      wrkmem);
#endif
		if (likely(!status && res_len > 0 && res_len < src_len)) {
			used_compression = MREF_COMPRESS_LZ4;
			*result_flags |= MREF_COMPRESS_LZ4;
			res = res_len;
			/*
			 * TODO: avoid memcpy() by swizzling the src_data pointer
			 */
			if (!dst_data)
				memcpy(src_data, tmp_buf, res_len);
		}
		brick_block_free(wrkmem, LZ4_MEM_COMPRESS);
		/* do not try other compression methods */
		goto done;
	}
#endif
#ifdef HAS_ZLIB
	if (check_flags & MREF_COMPRESS_ZLIB) {
		size_t zlib_deflate_wrk_size = zlib_deflate_workspacesize(MAX_WBITS, MAX_MEM_LEVEL);
		struct z_stream_s stream = {
			.workspace = brick_mem_alloc(zlib_deflate_wrk_size),
		};
		int status;

		if (!dst_data) {
			tmp_buf = brick_mem_alloc(src_len);
		} else if (dst_len < src_len) {
			MARS_ERR("ZLIB compression buffer too small: %d < %d\n",
				 dst_len, src_len);
			return 0;
		}

		status = zlib_deflateInit(&stream, mars_zlib_compression_level);
		if (unlikely(status != Z_OK)) {
			MARS_ERR("cannot init zlib compression stream\n");
			goto zlib_err;
		}

		stream.next_in = src_data;
		stream.avail_in = src_len;
		stream.next_out = tmp_buf;
		stream.avail_out = src_len;

		status = zlib_deflate(&stream, Z_FINISH);
		if (status != Z_STREAM_END)
			goto zlib_err;

		status = zlib_deflateEnd(&stream);
		if (status == Z_OK && stream.total_out < src_len) {
			used_compression = MREF_COMPRESS_ZLIB;
			*result_flags |= MREF_COMPRESS_ZLIB;
			res = stream.total_out;
			/*
			 * TODO: avoid memcpy() by swizzling the src_data pointer
			 */
			if (!dst_data)
				memcpy(src_data, tmp_buf, stream.total_out);
		}

	zlib_err:
		brick_mem_free(stream.workspace);
		/* do not try other compression methods */
		goto done;
	}
#endif
	used_compression = 0;

 done:
	if (!dst_data)
		brick_mem_free(tmp_buf);
	return res;
}

void *mars_decompress(void *src_data,
		      int src_len,
		      void *dst_data,
		      int dst_len,
		      __u32 check_flags)
{
	void *res_buf = dst_data;

	if (!res_buf)
		res_buf = brick_mem_alloc(dst_len);

#ifdef HAS_LZO
	if (check_flags & MREF_COMPRESS_LZO) {
		size_t res_len = dst_len;
		int status;

		status = lzo1x_decompress_safe(src_data, src_len,
					       res_buf, &res_len);
		if (status == LZO_E_OK && dst_len == res_len)
			goto done;

		MARS_ERR("bad LZO decompression from %d to %ld bytes (requested %d)\n",
			 src_len, res_len, dst_len);
		goto err;
	}
#endif
#ifdef HAS_LZ4
	if (check_flags & MREF_COMPRESS_LZ4) {
		size_t new_len = src_len;
		int status = 0;

#ifdef HAS_FAST_LZ4
		new_len = LZ4_decompress_safe(src_data,
					      res_buf,
					      src_len,
					      dst_len);
		if (!status && new_len == dst_len)
			goto done;

		MARS_ERR("bad LZ4 decompression %d to %lu != %d bytes\n",
			 src_len, new_len, dst_len);
#else
		status = lz4_decompress(src_data, &new_len,
					res_buf, dst_len);
		if (!status && new_len == src_len)
			goto done;

		MARS_ERR("bad LZ4 decompression %d != %lu to %d bytes\n",
			 src_len, new_len, dst_len);
#endif
		goto err;
	}
#endif
#ifdef HAS_ZLIB
	if (check_flags & MREF_COMPRESS_ZLIB) {
		size_t zlib_inflate_wrk_size = zlib_inflate_workspacesize();
		struct z_stream_s stream = {
			.workspace = brick_mem_alloc(zlib_inflate_wrk_size),
		};
		int status;

		status = zlib_inflateInit(&stream);
		if (unlikely(status != Z_OK)) {
			MARS_ERR("cannot init zlib decompression stream\n");
			goto zlib_err;
		}

		stream.next_in = src_data;
		stream.avail_in = src_len;
		stream.next_out = res_buf;
		stream.avail_out = dst_len;

		status = zlib_inflate(&stream, Z_FINISH);
		if (unlikely(status != Z_STREAM_END)) {
			MARS_ERR("bad ZLIB decompression %d (requested %d)\n",
				 src_len, dst_len);
			goto zlib_err;
		}

		status = zlib_inflateEnd(&stream);
		if (likely(status == Z_OK)) {
			brick_mem_free(stream.workspace);
			goto done;
		}

		MARS_ERR("unfinished ZLIB decompression %d (requested %d)\n",
			 src_len, dst_len);

	zlib_err:
		brick_mem_free(stream.workspace);
		goto err;
	}
#endif

	MARS_ERR("decompression not compiled into kernel module\n");

 err:
	if (!dst_data)
		brick_mem_free(res_buf);
	res_buf = NULL;

 done:
	return res_buf;
}

#ifdef CONFIG_MARS_BENCHMARK
#define MARS_CLEAN_SIZE 256

static
void make_fake_page(__u32 *testpage)
{
	int i;

	/* some fake compression data */
	for (i = 0; i < PAGE_SIZE / sizeof(__u32); i++)
		testpage[i] = (__u32)i;
}

static
void benchmark_compress(char *name, __u32 flags)
{
	void *testpage = kmalloc(PAGE_SIZE, GFP_KERNEL);
	__u32 result_flags;
	long long delta;
	int status;
	int i;

	usable_compression_mask = MREF_COMPRESS_ANY;

	make_fake_page(testpage);
	delta = TIME_THIS(
			  for (i = 0; i < 10000; i++) {
				  memset(testpage, 0, MARS_CLEAN_SIZE);
				  result_flags = 0;
				  status =
				  mars_compress(testpage, PAGE_SIZE,
						NULL, PAGE_SIZE + compress_overhead,
						flags, &result_flags);
				  if (unlikely(status <= 0) || !(flags & result_flags)) {
					  MARS_ERR("%s compress failure, status=%d, flags=%x\n",
						   name, status, result_flags);
					  goto err;
				  }
			  }
			  );
	printk("%-8s compress duration = %12lld ns\n", name, delta);

 err:
	kfree(testpage);
	usable_compression_mask = 0;
}

#endif

static
int init_mars_compress(void)
{
	int max_len = 0;

#ifdef HAS_LZO
	max_len = lzo1x_worst_compress(MARS_MAX_COMPR_SIZE) - MARS_MAX_COMPR_SIZE;
	if (max_len > compress_overhead)
		compress_overhead = max_len;
#endif
#ifdef HAS_LZ4
#ifdef HAS_FAST_LZ4
	max_len = LZ4_COMPRESSBOUND(MARS_MAX_COMPR_SIZE) - MARS_MAX_COMPR_SIZE;
#else
	max_len = lz4_compressbound(MARS_MAX_COMPR_SIZE) - MARS_MAX_COMPR_SIZE;
#endif
	if (max_len > compress_overhead)
		compress_overhead = max_len;
#endif

#ifdef CONFIG_MARS_BENCHMARK
#ifdef HAS_LZO
	benchmark_compress("lzo", MREF_COMPRESS_LZO);
#endif
#ifdef HAS_LZ4
	benchmark_compress("lz4", MREF_COMPRESS_LZ4);
#endif
#ifdef HAS_ZLIB
	benchmark_compress("zlib", MREF_COMPRESS_ZLIB);
#endif
	(void)benchmark_compress;
#endif
	return 0;
}

static
void exit_mars_compress(void)
{
}

/////////////////////////////////////////////////////////////////////

// tracing

#ifdef MARS_TRACING

unsigned long long start_trace_clock = 0;
EXPORT_SYMBOL_GPL(start_trace_clock);

struct file *mars_log_file = NULL;
loff_t mars_log_pos = 0;

void _mars_log(char *buf, int len)
{
	static DEFINE_MUTEX(trace_lock);

#ifdef MARS_HAS_KERNEL_READ
	mutex_lock(&trace_lock);
	(void)kernel_write(mars_log_file,
			   buf,
			   len,
			   &mars_log_pos);
	mutex_unlock(&trace_lock);
#else
	mm_segment_t oldfs;
	
	oldfs = get_fs();
	set_fs(get_ds());
	mutex_lock(&trace_lock);

	vfs_write(mars_log_file, buf, len, &mars_log_pos);

	mutex_unlock(&trace_lock);
	set_fs(oldfs);
#endif
}
EXPORT_SYMBOL_GPL(_mars_log);

void mars_log(const char *fmt, ...)
{
	char *buf = brick_string_alloc(0);
	va_list args;
	int len;
	if (!buf)
		return;

	va_start(args, fmt);
	len = vscnprintf(buf, PAGE_SIZE, fmt, args);
	va_end(args);

	_mars_log(buf, len);

	brick_string_free(buf);
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
	char *buf = brick_string_alloc(0);
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

	len = scnprintf(buf, PAGE_SIZE, "%c ;%12lld ;%6d;%10llu",
			mref->ref_flags & MREF_WRITE ? 'W' : 'R',
			mref->ref_pos, mref->ref_len, diff / 1000);

	old = start_trace_clock;
	for (i = 0; i < mref->ref_traces; i++) {
		diff = mref->ref_trace_stamp[i] - old;
		
		len += scnprintf(buf + len, PAGE_SIZE - len, " ; %s ;%10llu", mref->ref_trace_info[i], diff / 1000);
		old = mref->ref_trace_stamp[i];
	}
	len +=scnprintf(buf + len, PAGE_SIZE - len, "\n");

	_mars_log(buf, len);

 done:
	brick_string_free(buf);
	mref->ref_traces = 0;
}
EXPORT_SYMBOL_GPL(mars_log_trace);

#endif // MARS_TRACING

/////////////////////////////////////////////////////////////////////

// power led handling

void mars_power_led_on(struct mars_brick *brick, bool val)
{
	bool oldval = brick->power.led_on;
	if (val != oldval) {
		//MARS_DBG("brick '%s' type '%s' led_on %d -> %d\n", brick->brick_path, brick->type->type_name, oldval, val);
		set_led_on(&brick->power, val);
		mars_trigger();
	}
}
EXPORT_SYMBOL_GPL(mars_power_led_on);

void mars_power_led_off(struct mars_brick *brick, bool val)
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

struct mm_struct *mm_fake = NULL;
EXPORT_SYMBOL_GPL(mm_fake);
struct task_struct *mm_fake_task = NULL;
atomic_t mm_fake_count = ATOMIC_INIT(0);
EXPORT_SYMBOL_GPL(mm_fake_count);

int __init init_mars(void)
{
	int status;

	MARS_INF("init_mars()\n");

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

#ifdef MARS_HAS_NEW_CRYPTO
	status = init_mars_digest();
	if (unlikely(status))
		return status;

#else  /* MARS_HAS_NEW_CRYPTO */

	{
		int i;

		for (i = 0; i < OBSOLETE_TFM_MAX; i++) {
			sema_init(&tfm_sem[i], 1);
			mars_tfm[i] = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
			if (!mars_tfm[i]) {
				MARS_ERR("cannot alloc crypto hash\n");
				return -ENOMEM;
			}
			if (IS_ERR(mars_tfm)) {
				MARS_ERR("alloc crypto hash failed, status = %d\n", (int)PTR_ERR(mars_tfm));
				return PTR_ERR(mars_tfm);
			}
		}
	}
#if 0
	if (crypto_tfm_alg_type(crypto_hash_tfm(mars_tfm)) != CRYPTO_ALG_TYPE_DIGEST) {
		MARS_ERR("bad crypto hash type\n");
		return -EINVAL;
	}
#endif
	status = crypto_hash_digestsize(mars_tfm[0]);
	MARS_INF("digest_size = %d\n", status);
	if (unlikely(status != MARS_DIGEST_SIZE)) {
		MARS_ERR("bad md5 crypto hash size %d\n", status);
		return -EINVAL;
	}
#endif /* MARS_HAS_NEW_CRYPTO */

	init_mars_compress();

	return 0;
}

void exit_mars(void)
{
	MARS_INF("exit_mars()\n");

	put_fake();

	exit_mars_compress();

#ifdef MARS_HAS_NEW_CRYPTO
	exit_mars_digest();
#else  /* MARS_HAS_NEW_CRYPTO */
	if (mars_tfm[0]) {
		int i;

		for (i = 0; i < OBSOLETE_TFM_MAX; i++)
			crypto_free_hash(mars_tfm[i]);
	}
#endif /* MARS_HAS_NEW_CRYPTO */

#ifdef MARS_TRACING
	if (mars_log_file) {
		filp_close(mars_log_file, NULL);
		mars_log_file = NULL;
	}
#endif
}
