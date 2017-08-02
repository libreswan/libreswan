/* XAUTH handling, for libreswan.
 *
 * Copyright (C) 2017 Andrew Cagney
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <pthread.h>

#include "constants.h"

struct id;
struct state;

/*
 * So code can determine if it isn't running on the main thread; or
 * that its thread is valid.
 */
extern pthread_t main_thread;

void xauth_cancel(so_serial_t serialno, pthread_t *thread);

#ifdef XAUTH_HAVE_PAM
void xauth_start_pam_thread(pthread_t *thread,
			    const char *name,
			    const char *password,
			    const char *connection_name,
			    const ip_address *remote_addr,
			    so_serial_t serialno,
			    unsigned long instance_serial,
			    const char *atype,
			    void (*callback)(struct state *st,
					     const char *name,
					     bool success));
#endif

/*
 * Force a pre-determined authentication outcome through the XAUTH
 * thread code.
 */

void xauth_start_always_thread(pthread_t *thread,
			       const char *method, const char *name,
			       so_serial_t serialno, bool success,
			       void (*callback)(struct state *st,
						const char *name,
						bool success));
