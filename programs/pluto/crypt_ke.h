/* compute dh-local-secret and/or nonce, for libreswan
 *
 * Copyright (C) 2020  Andrew Cagney
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

/*
 * This is an internal interface between the main and helper threads.
 *
 * The helper performs the heavy lifting of cryptographic functions
 * for pluto. It does this to avoid head-of-queue problems with aggressive
 * mode, and to deal with the asynchronous nature of hardware offload.
 *
 * (Unrelated to code to compartmentalize lookups to LDAP/HTTP/FTP for CRL fetching
 * and checking.)
 */

#ifndef CRYPT_KE_H
#define CRYPT_KE_H

typedef stf_status (ke_and_nonce_cb)(struct state *st, struct msg_digest *md,
				     struct dh_local_secret *local_secret,
				     chunk_t *nonce/*steal*/);

/*
 * When DH is non-null, compute do_local_secret.  Compute nonce.
 */

void submit_ke_and_nonce(struct state *callback_sa,
			 struct state *task_sa,
			 struct msg_digest *md,
			 const struct dh_desc *dh,
			 ke_and_nonce_cb *cb,
			 bool detach_whack, where_t where);

/*
 * KE and NONCE
 */

extern void unpack_KE_from_helper(struct state *st,
				  struct dh_local_secret *local_secret,
				  chunk_t *g);

#endif /* _PLUTO_CRYPT_H */
