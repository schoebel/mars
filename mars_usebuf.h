// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_USEBUF_H
#define MARS_USEBUF_H

struct usebuf_mars_ref_aspect {
	GENERIC_ASPECT(mars_ref);
	struct mars_ref_object *origmref;
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
	struct generic_object_layout ref_object_layout;
};

MARS_TYPES(usebuf);

#endif
