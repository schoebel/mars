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

#ifndef XIO_USEBUF_H
#define XIO_USEBUF_H

struct usebuf_aio_aspect {
	GENERIC_ASPECT(aio);
	struct usebuf_aio_aspect *sub_aio_a;
	struct usebuf_input *input;

#if 1
	int yyy;

#endif
};

struct usebuf_brick {
	XIO_BRICK(usebuf);
};

struct usebuf_input {
	XIO_INPUT(usebuf);
};

struct usebuf_output {
	XIO_OUTPUT(usebuf);
};

XIO_TYPES(usebuf);

#endif
