// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
struct device_sio_brick {
	MARS_BRICK(device_sio);
};

struct device_sio_input {
	MARS_INPUT(device_sio);
};

struct device_sio_output {
	MARS_OUTPUT(device_sio);
};

MARS_TYPES(device_sio);
