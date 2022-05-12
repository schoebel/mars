/*
 * MARS Long Distance Replication Software
 *
 * This file is part of MARS project: http://schoebel.github.io/mars/
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
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef MARS_DUMMY_H
#define MARS_DUMMY_H

struct dummy_mref_aspect {
	GENERIC_ASPECT(mref);
	int my_own;
};

struct dummy_brick {
	MARS_BRICK(dummy);
	/* parameters */
	/* private */
	int my_own;
};

struct dummy_input {
	MARS_INPUT(dummy);
	/* parameters */
	/* private */
};

struct dummy_output {
	MARS_OUTPUT(dummy);
	/* parameters */
	/* private */
	int my_own;
};

MARS_TYPES(dummy);

#endif
