/* IPsec DOI and Oakley resolution routines
 * Copyright (C) 1998-2002,2010-2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2007,2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012-2018 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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

#include "fd.h"
#include "pluto_timing.h"

struct payload_digest;
struct state;
struct lswlog;

struct xfrm_user_sec_ctx_ike *uctx; /* forward declaration */

typedef void initiator_function(fd_t whack_sock,
				struct connection *c,
				struct state *predecessor,
				lset_t policy,
				unsigned long try,
				const threadtime_t *inception
#ifdef HAVE_LABELED_IPSEC
				, struct xfrm_user_sec_ctx_ike *uctx
#endif
				);

extern void ipsecdoi_initiate(fd_t whack_sock, struct connection *c,
			      lset_t policy, unsigned long try,
			      so_serial_t replacing,
			      const threadtime_t *inception
#ifdef HAVE_LABELED_IPSEC
			      , struct xfrm_user_sec_ctx_ike *uctx
#endif
			      );

extern void ipsecdoi_replace(struct state *st, unsigned long try);

extern void init_phase2_iv(struct state *st, const msgid_t *msgid);

/*
 * forward
 */
struct dh_desc;
extern void send_delete(struct state *st);
extern bool accept_delete(struct msg_digest *md,
			  struct payload_digest *p);
extern void accept_self_delete(struct msg_digest *md);

extern void send_notification_from_state(struct state *st,
					 enum state_kind from_state,
					 notification_t type);
extern void send_notification_from_md(struct msg_digest *md, notification_t type);

extern bool accept_KE(chunk_t *dest, const char *val_name,
		      const struct dh_desc *gr,
		      struct payload_digest *ke_pd);

extern stf_status send_isakmp_notification(struct state *st,
					   uint16_t type, const void *data,
					   size_t len);

extern bool has_preloaded_public_key(const struct state *st);

extern bool extract_peer_id(enum ike_id_type kind, struct id *peer, const pb_stream *id_pbs);

struct pluto_crypto_req;	/* prevent struct type being local to function protocol */
extern void unpack_nonce(chunk_t *n, const struct pluto_crypto_req *r);

extern void lswlog_child_sa_established(struct lswlog *buf, struct state *st);
extern void lswlog_ike_sa_established(struct lswlog *buf, struct state *st);
