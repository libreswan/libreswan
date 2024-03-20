/* XAUTH PAM handling
 *
 * Copyright (C) 2017, 2021 Andrew Cagney
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
 */

#ifndef PAM_AUTH_H
#define PAM_AUTH_H

#ifndef USE_PAM_AUTH
#error USE_PAM_AUTH
#endif

#include <stdbool.h>

struct state;
struct msg_digest;

typedef stf_status pam_auth_callback_fn(struct state *st,
					struct msg_digest *md,
					const char *,
					bool success);

/*
 * XXX: Should XAUTH handle timeouts internally?
 */
void pam_auth_abort(struct state *st, const char *story);

bool pam_auth_fork_request(struct state *st,
			   struct msg_digest *md,
			   const char *name,
			   const char *password,
			   const char *atype,
			   pam_auth_callback_fn *callback);

#endif
