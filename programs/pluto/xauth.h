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

#include "constants.h"

struct id;
struct state;
struct xauth;

/*
 * XXX: Should XAUTH handle timeouts internall?
 */
void xauth_abort(so_serial_t serialno, struct xauth **xauth,
		 struct state *st_callback);

#ifdef XAUTH_HAVE_PAM
void xauth_start_pam_thread(struct xauth **xauth,
			    const char *name,
			    const char *password,
			    const char *connection_name,
			    const ip_address *remote_addr,
			    so_serial_t serialno,
			    unsigned long instance_serial,
			    const char *atype,
			    void (*callback)(struct state *st,
					     const char *name,
					     bool aborted,
					     bool success));
#endif

void xauth_next(struct xauth **xauth,
		const char *method, const char *name,
		so_serial_t serialno, bool success,
		void (*callback)(struct state *st,
				 const char *name,
				 bool aborted,
				 bool success));
