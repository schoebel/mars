// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_USEBUF_H
#define MARS_USEBUF_H

struct usebuf_mref_aspect {
	GENERIC_ASPECT(mref);
	struct usebuf_mref_aspect *sub_mref_a;
	struct usebuf_input *input;
	struct generic_callback cb;
#if 1
	int yyy;
#endif
};

struct usebuf_brick {
	MARS_BRICK(usebuf);
};

struct usebuf_input {
	MARS_INPUT(usebuf);
};

struct usebuf_output {
	MARS_OUTPUT(usebuf);
	struct generic_object_layout mref_object_layout;
};

MARS_TYPES(usebuf);

#endif
