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
 * Messily exit Pluto
 *
 * This code tries to shutdown pluto while the event loop is still
 * active and while worker threads are still running.  Funny enough,
 * it occasionally crashes or spews garbage, for instance:
 *
 * - a worker thread trying to access NSS after NSS has been shutdown
 *
 * - scary leak-detective errors because there are events sitting in
 *   the event queue
 *
 * The global EXITING_PLUTO is there as a hint to long running threads
 * that they should also shutdown (it should be tested in the thread's
 * main and some inner loops).  Just note that, on its own, it isn't
 * sufficient.  Any long running threads will also need a gentle nudge
 * (so that they loop around and detect the need to quit) and then a
 * join to confirm that they have exited.
 *
 * Also avoid pthread_cancel() which can crash.
 */

extern volatile bool exiting_pluto;
extern void exit_pluto(enum pluto_exit_code status) NEVER_RETURNS;

#endif
