// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_USEBUF_H
#define MARS_USEBUF_H

struct usebuf_mars_io_aspect {
	GENERIC_ASPECT(mars_io);
	atomic_t mio_count;
	int mio_error;
};

struct usebuf_mars_buf_aspect {
	GENERIC_ASPECT(mars_buf);
	struct mars_io_object *mio;
	struct bio_vec *bvec;
	int bvec_offset;
	int bvec_len;
};

struct usebuf_mars_buf_callback_aspect {
	GENERIC_ASPECT(mars_buf_callback);
};

struct usebuf_brick {
	MARS_BRICK(usebuf);
};

struct usebuf_input {
	MARS_INPUT(usebuf);
};

struct usebuf_output {
	MARS_OUTPUT(usebuf);
	struct mars_buf_object_layout *buf_layout;
	struct mars_buf_callback_object_layout *buf_callback_layout;
};

MARS_TYPES(usebuf);

#endif
