// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_TRANS_LOGGER_H
#define MARS_TRANS_LOGGER_H

#define REGION_SIZE_BITS 22
#define REGION_SIZE (1 << REGION_SIZE_BITS)
#define TRANS_HASH_MAX 32

struct trans_logger_mars_ref_aspect {
	GENERIC_ASPECT(mars_ref);
	struct list_head hash_head;
};

struct trans_logger_brick {
	MARS_BRICK(trans_logger);
};

struct trans_logger_input {
	MARS_INPUT(trans_logger);
};

struct hash_anchor {
	rwlock_t hash_lock;
	struct list_head hash_anchor;
};

struct trans_logger_output {
	MARS_OUTPUT(trans_logger);
	struct hash_anchor hash_table[TRANS_HASH_MAX];
};

MARS_TYPES(trans_logger);

#endif
