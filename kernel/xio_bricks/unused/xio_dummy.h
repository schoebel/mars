/*
 * MARS Long Distance Replication Software
 *
 * Copyright (C) 2010-2014 Thomas Schoebel-Theuer
 * Copyright (C) 2011-2014 1&1 Internet AG
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef XIO_DUMMY_H
#define XIO_DUMMY_H

struct dummy_aio_aspect {
	GENERIC_ASPECT(aio);
	int my_own;
};

struct dummy_brick {
	XIO_BRICK(dummy);
	int my_own;
};

struct dummy_input {
	XIO_INPUT(dummy);
};

struct dummy_output {
	XIO_OUTPUT(dummy);
	int my_own;
};

XIO_TYPES(dummy);

#endif
