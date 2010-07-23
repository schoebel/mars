// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_DUMMY_H
#define MARS_DUMMY_H

struct dummy_mars_io_aspect {
	GENERIC_ASPECT(mars_io);
	int my_own;
};

struct dummy_mars_buf_aspect {
	GENERIC_ASPECT(mars_buf);
	int my_own;
};

struct dummy_mars_buf_callback_aspect {
	GENERIC_ASPECT(mars_buf_callback);
	int my_own;
};

struct dummy_brick {
	MARS_BRICK(dummy);
	int my_own;
};

struct dummy_input {
	MARS_INPUT(dummy);
};

struct dummy_output {
	MARS_OUTPUT(dummy);
	int my_own;
};

MARS_TYPES(dummy);

#endif
