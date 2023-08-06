/* <<ipsec whack add ...>>, for libreswan
 *
 * Copyright (C) 2023 Andrew Cagney
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

#include "lswlog.h"	/* for RC_FATAL */
#include "whack.h"

#include "whack_add.h"
#include "show.h"
#include "connections.h"

void whack_add(const struct whack_message *wm, struct show *s)
{
	if (wm->name == NULL) {
		whack_log(RC_FATAL, s,
			  "received whack command to delete a connection, but did not receive the connection name - ignored");
		return;
	}

	/*
	 * "whack" semantics: attempt to add duplicate connection is
	 * rejected.
	 */
	if (connection_with_name_exists(wm->name)) {
		whack_log(RC_DUPNAME, s,
			  "attempt to redefine connection \"%s\"", wm->name);
		return;
	}

	add_connection(wm, show_logger(s));
}
