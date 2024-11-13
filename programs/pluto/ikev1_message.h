/* IKEv1 message contents, for libreswan
 *
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
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

#ifndef IKEV1_MESSAGE_H
#define IKEV1_MESSAGE_H

#include "shunk.h"
#include "chunk.h"

struct logger;
struct msg_digest;
struct host_end;
struct pbs_out;
struct state;
struct ike_sa;

struct isakmp_ipsec_id build_v1_id_payload(const struct host_end *end, shunk_t *body);

extern bool out_raw(const void *bytes, size_t len, struct pbs_out *outs, const char *name) MUST_USE_RESULT;

extern bool ikev1_justship_nonce(chunk_t *n, struct pbs_out *outs,
				 const char *name);

/* calls previous two routines */
extern bool ikev1_ship_nonce(chunk_t *n, chunk_t *nonce,
			     struct pbs_out *outs, const char *name);

extern v1_notification_t accept_v1_nonce(struct logger *logger,
					 struct msg_digest *md, chunk_t *dest,
					 const char *name);

extern bool ikev1_justship_KE(struct logger *logger, chunk_t *g, struct pbs_out *outs);

/* just calls previous two routines now */
extern bool ikev1_ship_KE(struct state *st, struct dh_local_secret *local_secret,
			  chunk_t *g, struct pbs_out *outs);

bool close_and_encrypt_v1_message(struct pbs_out *pbs, struct state *st);
bool close_v1_message(struct pbs_out *pbs, const struct ike_sa *ike);

/* macros to manipulate IVs in state */

#define update_iv(st)	{ \
	(st)->st_v1_iv = (st)->st_v1_new_iv; \
    }

#define set_ph1_iv_from_new(st)	{ \
	(st)->st_v1_ph1_iv = (st)->st_v1_new_iv; \
 }

#define save_iv(st, tmp) { \
	(tmp) = (st)->st_v1_iv; \
    }

#define restore_iv(st, tmp) { \
	(st)->st_v1_iv = (tmp); \
    }

#define save_new_iv(st, tmp)	{ \
	(tmp) = (st)->st_v1_new_iv; \
    }

#define restore_new_iv(st, tmp)	{ \
	(st)->st_v1_new_iv = (tmp); \
    }

void init_phase2_iv(struct state *st, const msgid_t msgid,
		    const char *why, where_t where);

#endif
