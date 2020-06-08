/* IKEv2 Session Resumption RFC 5723
 *
 * Copyright (C) 2020 Nupur Agrawal <nupur202000@gmail.com>
 * Copyright (C) 2024 Andrew Cagney
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

#ifndef IKEV2_IKE_SESSION_RESUME_H
#define IKEV2_IKE_SESSION_RESUME_H

struct session;
struct jambuf;

void pfree_session(struct session **session);
void jam_session(struct jambuf *buf, const struct session *session);

#endif
