// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

// Trans_Logger brick (just for demonstration)

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/bio.h>

#include "mars.h"

///////////////////////// own type definitions ////////////////////////

#include "mars_trans_logger.h"

///////////////////////// own helper functions ////////////////////////


static inline int hash_fn(unsigned int base_index)
{
	// simple and stupid
	unsigned int tmp;
	tmp = base_index ^ (base_index / TRANS_HASH_MAX);
	tmp += tmp / 13;
	tmp ^= tmp / (TRANS_HASH_MAX * TRANS_HASH_MAX);
	return tmp % TRANS_HASH_MAX;
}

static struct trans_logger_mars_ref_aspect *hash_find(struct hash_anchor *table, loff_t pos, int len)
{
	unsigned int base_index = ((unsigned int)pos) >> REGION_SIZE_BITS;
	int hash = hash_fn(base_index);
	struct hash_anchor *start = &table[hash];
	struct list_head *tmp;
	struct trans_logger_mars_ref_aspect *res = NULL;
	struct trans_logger_mars_ref_aspect *test_a;
	struct mars_ref_object *test;
	loff_t min_pos = -1;
	int count = 0;
	unsigned int flags;

	traced_readlock(&start->hash_lock, flags);

	/* Caution: there may be duplicates in the list, some of them
	 * overlapping in many different ways.
	 * Always find the both _newest_ and _lowest_ overlapping element!
	 */
	for (tmp = start->hash_anchor.next; tmp != &start->hash_anchor; tmp = tmp->next) {
#if 1
		static int max = 0;
		if (++count > max) {
			max = count;
			if (!(max % 10)) {
				MARS_INF("hash maxlen=%d hash=%d base_index=%u\n", max, hash, base_index);
			}
		}
#endif
		test_a = container_of(tmp, struct trans_logger_mars_ref_aspect, hash_head);
		test = test_a->object;
		if (pos < test->ref_pos + test->ref_len && pos + len > test->ref_pos) {
			if (test->ref_pos >= pos) {
				// always prefer the lowest distance, even if elder
				if (test->ref_pos < min_pos || min_pos < 0) {
					min_pos = test->ref_pos;
					res = test_a;
				}
			} else {
				// always take the newest one, distance does not matter
				if (min_pos < 0) {
					min_pos = test->ref_pos;
					res = test_a;
				}
			}
		}
	}

	traced_readunlock(&start->hash_lock, flags);

	return res;
}

static inline void hash_insert(struct hash_anchor *table, struct trans_logger_mars_ref_aspect *elem)
{
	unsigned int base_index = ((unsigned int)elem->object->ref_pos) >> REGION_SIZE_BITS;
	int hash = hash_fn(base_index);
	struct hash_anchor *start = &table[hash];
	unsigned int flags;

	traced_writelock(&start->hash_lock, flags);

	list_add(&elem->hash_head, &start->hash_anchor);

	traced_writeunlock(&start->hash_lock, flags);
}

static inline void hash_delete(struct hash_anchor *table, struct trans_logger_mars_ref_aspect *elem)
{
	unsigned int base_index = ((unsigned int)elem->object->ref_pos) >> REGION_SIZE_BITS;
	int hash = hash_fn(base_index);
	struct hash_anchor *start = &table[hash];
	unsigned int flags;

	traced_writelock(&start->hash_lock, flags);

	list_del_init(&elem->hash_head);

	traced_writeunlock(&start->hash_lock, flags);
}

////////////////// own brick / input / output operations //////////////////

static int trans_logger_get_info(struct trans_logger_output *output, struct mars_info *info)
{
	struct trans_logger_input *input = output->brick->inputs[0];
	return GENERIC_INPUT_CALL(input, mars_get_info, info);
}

static int trans_logger_ref_get(struct trans_logger_output *output, struct mars_ref_object *mref)
{
	struct trans_logger_input *input = output->brick->inputs[0];
	unsigned int base_offset = ((unsigned int)mref->ref_pos) & (REGION_SIZE - 1);
	struct trans_logger_mars_ref_aspect *shadow_a;

	if (base_offset + mref->ref_len > REGION_SIZE)
		mref->ref_len = REGION_SIZE - base_offset;

	if (mref->ref_rw == READ) {
		/* Look if the is a newer version on the fly which shadows
		 * the old one.
		 * When a shadow is found, use it as buffer for the mref.
		 */
		shadow_a = hash_find(output->hash_table, mref->ref_pos, mref->ref_len);
		if (shadow_a) {
			struct mars_ref_object *shadow = shadow_a->object;
			int diff = shadow->ref_pos - mref->ref_pos;
			int restlen;
			if (diff > 0) {
				/* Although the shadow is overlapping, the
				 * region before its start is _not_ shadowed.
				 * Thus we return this (smaller) unshadowed
				 * region.
				 */
				mref->ref_len = diff;
				goto call;
			}
			restlen = shadow->ref_len + diff;
			if (mref->ref_len > restlen)
				mref->ref_len = restlen;
			//...
			return -ENOSYS;
		}
	call:
		return GENERIC_INPUT_CALL(input, mars_ref_get, mref);
	}
	//...
	return -ENOSYS;
}

static void trans_logger_ref_put(struct trans_logger_output *output, struct mars_ref_object *mref)
{
	struct trans_logger_input *input = output->brick->inputs[0];
	GENERIC_INPUT_CALL(input, mars_ref_put, mref);
}

static void trans_logger_ref_io(struct trans_logger_output *output, struct mars_ref_object *mref, int rw)
{
	struct trans_logger_input *input = output->brick->inputs[0];
	GENERIC_INPUT_CALL(input, mars_ref_io, mref, rw);
}

//////////////// object / aspect constructors / destructors ///////////////

static int trans_logger_mars_ref_aspect_init_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct trans_logger_mars_ref_aspect *ini = (void*)_ini;
	INIT_LIST_HEAD(&ini->hash_head);
	(void)ini;
	return 0;
}

static void trans_logger_mars_ref_aspect_exit_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct trans_logger_mars_ref_aspect *ini = (void*)_ini;
	CHECK_HEAD_EMPTY(&ini->hash_head);
	(void)ini;
}

MARS_MAKE_STATICS(trans_logger);

////////////////////// brick constructors / destructors ////////////////////

static int trans_logger_brick_construct(struct trans_logger_brick *brick)
{
	return 0;
}

static int trans_logger_output_construct(struct trans_logger_output *output)
{
	int i;
	for (i = 0; i < TRANS_HASH_MAX; i++) {
		struct hash_anchor *start = &output->hash_table[i];
		rwlock_init(&start->hash_lock);
		INIT_LIST_HEAD(&start->hash_anchor);
	}
	return 0;
}

///////////////////////// static structs ////////////////////////

static struct trans_logger_brick_ops trans_logger_brick_ops = {
};

static struct trans_logger_output_ops trans_logger_output_ops = {
	.make_object_layout = trans_logger_make_object_layout,
	.mars_get_info = trans_logger_get_info,
	.mars_ref_get = trans_logger_ref_get,
	.mars_ref_put = trans_logger_ref_put,
	.mars_ref_io = trans_logger_ref_io,
};

static const struct trans_logger_input_type trans_logger_input_type = {
	.type_name = "trans_logger_input",
	.input_size = sizeof(struct trans_logger_input),
};

static const struct trans_logger_input_type *trans_logger_input_types[] = {
	&trans_logger_input_type,
};

static const struct trans_logger_output_type trans_logger_output_type = {
	.type_name = "trans_logger_output",
	.output_size = sizeof(struct trans_logger_output),
	.master_ops = &trans_logger_output_ops,
	.output_construct = &trans_logger_output_construct,
	.aspect_types = trans_logger_aspect_types,
	.layout_code = {
		[BRICK_OBJ_MARS_REF] = LAYOUT_ALL,
	}
};

static const struct trans_logger_output_type *trans_logger_output_types[] = {
	&trans_logger_output_type,
};

const struct trans_logger_brick_type trans_logger_brick_type = {
	.type_name = "trans_logger_brick",
	.brick_size = sizeof(struct trans_logger_brick),
	.max_inputs = 1,
	.max_outputs = 1,
	.master_ops = &trans_logger_brick_ops,
	.default_input_types = trans_logger_input_types,
	.default_output_types = trans_logger_output_types,
	.brick_construct = &trans_logger_brick_construct,
};
EXPORT_SYMBOL_GPL(trans_logger_brick_type);

////////////////// module init stuff /////////////////////////

static int __init init_trans_logger(void)
{
	printk(MARS_INFO "init_trans_logger()\n");
	return trans_logger_register_brick_type();
}

static void __exit exit_trans_logger(void)
{
	printk(MARS_INFO "exit_trans_logger()\n");
	trans_logger_unregister_brick_type();
}

MODULE_DESCRIPTION("MARS trans_logger brick");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_trans_logger);
module_exit(exit_trans_logger);
