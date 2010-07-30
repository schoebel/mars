// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_USEBUF_H
#define MARS_USEBUF_H

MARS_HELPERS(usebuf);

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

struct usebuf_brick {
	MARS_BRICK(usebuf);
};

struct usebuf_input {
	MARS_INPUT(usebuf);
};

struct usebuf_output {
	MARS_OUTPUT(usebuf);
	struct usebuf_alloc_helper buf_helper;
};

MARS_TYPES(usebuf);

#endif
