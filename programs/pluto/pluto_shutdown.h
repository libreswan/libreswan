/* shutting down pluto, for libreswan
 *
 * Copyright (C) 2020 Andrew Cagney
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

#ifndef PLUTO_SHUTDOWN_H
#define PLUTO_SHUTDOWN_H

#include <stdbool.h>

#include "lswcdefs.h"		/* for NEVER_RETURNS */

enum pluto_exit_code;

/*
 * The global EXITING_PLUTO is there as a hint to long running threads
 * that they should also shutdown (it should be tested in the thread's
 * main and some inner loops).  Just note that, on its own, it isn't
 * sufficient.  Any long running threads will also need a gentle nudge
 * (so that they loop around and detect the need to quit) and then a
 * join to confirm that they have exited.
 */

extern volatile bool exiting_pluto;

/*
 * "idle" then exit the event-loop, and then exit pluto.
 *
 * Recommended for shutting down while the event-loop is running.
 *
 * Using the event-loop: shutdown the helper threads; clean up any
 * child processes; delete any states / connections; and close any
 * open sockets.
 *
 * Then, once the event-loop exits (which should happen once there's
 * nothing to do), clean up any remaining memory and exit pluto.
 *
 * The important thing here is that for much of the shutdown the event
 * loop is still running.  This way helper threads and states can
 * continue to rely on the event-loop as they transition to the
 * shutdown state (rather than special abort paths).
 */

void shutdown_pluto(struct fd *whackfd, enum pluto_exit_code status, bool leave_state);

#endif
