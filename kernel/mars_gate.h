/*
 * MARS Long Distance Replication Software
 *
 * This file is part of MARS project: http://schoebel.github.io/mars/
 *
 * Copyright (C) 2010-2020 Thomas Schoebel-Theuer
 * Copyright (C) 2011-2020 1&1 Ionos
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

#ifndef MARS_GATE_H
#define MARS_GATE_H

struct gate_mref_aspect {
	GENERIC_ASPECT(mref);
	struct list_head gate_head;
};

struct gate_brick {
	MARS_BRICK(gate);
	/* public tunables */
	__s32 inhibit_mask;
	/* public readonly */
	int gate_queued;
	/* private */
	struct mutex mutex;
	struct list_head gate_anchor;
	wait_queue_head_t gate_event;
	brick_thread_t *gate_thread;
	bool terminated;
};

struct gate_input {
	MARS_INPUT(gate);
};

struct gate_output {
	MARS_OUTPUT(gate);
};

MARS_TYPES(gate);

#endif
