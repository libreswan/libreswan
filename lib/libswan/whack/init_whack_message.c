/* init whack_message, for libreswan
 *
 * Copyright (C) 2025 Andrew Cagney
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

#include "whack.h"

void init_whack_message(struct whack_message *wm,
			enum whack_from whack_from)
{
	zero(wm);
	wm->whack_from = whack_from;
	wm->end[LEFT_END].leftright = "left";
	wm->end[RIGHT_END].leftright = "right";
	FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
		wm->end[end].conn = &wm->conn[end];
	}
}
