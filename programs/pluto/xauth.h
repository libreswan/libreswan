/* XAUTH PAM handling
 *
 * Copyright (C) 2017 Andrew Cagney
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

#include "constants.h"

struct state;
struct msg_digest;

/* ??? needlessly used even if !XAUTH_HAVE_PAM */

typedef void xauth_callback_t(struct state *st,
			      struct msg_digest **mdp,
			      const char *,
			      bool success);

#ifdef XAUTH_HAVE_PAM

/*
 * XXX: Should XAUTH handle timeouts internally?
 */
void xauth_pam_abort(struct state *st);

void xauth_start_pam_thread(struct state *st,
			    const char *name,
			    const char *password,
			    const char *atype,
			    xauth_callback_t *callback);

#endif
