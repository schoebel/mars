// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_USEBUF_H
#define MARS_USEBUF_H

struct usebuf_mars_io_aspect {
	GENERIC_ASPECT(mars_io);
};

struct usebuf_mars_buf_aspect {
	GENERIC_ASPECT(mars_buf);
	struct mars_buf_object *origmbuf;
	struct bio_vec *bvec;
	int bvec_offset;
	int bvec_len;
	atomic_t mbuf_count;
};

struct usebuf_brick {
	MARS_BRICK(usebuf);
};

struct usebuf_input {
	MARS_INPUT(usebuf);
};

struct usebuf_output {
	MARS_OUTPUT(usebuf);
	struct generic_object_layout buf_object_layout;
};

MARS_TYPES(usebuf);

#endif
