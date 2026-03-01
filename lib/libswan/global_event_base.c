/* global event_base storage, for libreswan
 *
 * Copyright (C) 2025 Eshaan Gupta
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#include "global_event_base.h"

static struct event_base *global_eb = NULL;

struct event_base *get_global_event_base(void)
{
	return global_eb;
}

void set_global_event_base(struct event_base *eb)
{
	global_eb = eb;
}
