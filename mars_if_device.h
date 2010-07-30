// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_IF_DEVICE_H
#define MARS_IF_DEVICE_H

#define HT_SHIFT 6 //????
#define MARS_MAX_SEGMENT_SIZE (1U << (9+HT_SHIFT))

MARS_HELPERS(if_device);

struct if_device_mars_io_aspect {
	GENERIC_ASPECT(mars_io);
};

struct if_device_mars_buf_aspect {
	GENERIC_ASPECT(mars_buf);
};

struct if_device_brick {
	MARS_BRICK(if_device);
};

struct if_device_input {
	MARS_INPUT(if_device);
	struct request_queue *q;
	struct gendisk *disk;
	struct block_device *bdev;
	spinlock_t req_lock;
	struct if_device_alloc_helper mio_helper;
};

struct if_device_output {
	MARS_OUTPUT(if_device);
};

MARS_TYPES(if_device);

#endif
