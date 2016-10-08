/*
 * IKE modular algorithm handling interface
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 * Copyright (C) 2003 Mathieu Lafon <mlafon@arkoon.net>
 * Copyright (C) 2006-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2010 Martin Schiller
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 Paul Wouters <pwouters@redhat.com>
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
 *
 * Fixes by:
 *      ML:	Mathieu Lafon <mlafon@arkoon.net>
 *
 * Fixes:
 *      ML:	ike_alg_ok_final() function (make F_STRICT consider hash/auth and modp).
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "sha1.h"
#include "md5.h"
#include "crypto.h"

#include "state.h"
#include "packet.h"
#include "log.h"
#include "whack.h"
#include "spdb.h"
#include "alg_info.h"
#include "ike_alg.h"
#include "db_ops.h"
#include "id.h"
#include "connections.h"
#include "kernel.h"
#include "plutoalg.h"

/*
 *      Show IKE algorithms for
 *      - this connection (result from ike= string)
 *      - newest SA
 */
void ike_alg_show_connection(const struct connection *c, const char *instance)
{
	const struct state *st;

	if (c->alg_info_ike != NULL) {
		char buf[1024];

		alg_info_ike_snprint(buf, sizeof(buf) - 1,
				     c->alg_info_ike);
		whack_log(RC_COMMENT,
			  "\"%s\"%s:   IKE algorithms wanted: %s",
			  c->name,
			  instance,
			  buf);

		alg_info_snprint_ike(buf, sizeof(buf), c->alg_info_ike);
		whack_log(RC_COMMENT,
			  "\"%s\"%s:   IKE algorithms found:  %s",
			  c->name,
			  instance,
			  buf);
	}
	st = state_with_serialno(c->newest_isakmp_sa);
	if (st != NULL) {
		struct esb_buf encbuf, prfbuf, integbuf, groupbuf;

		if (!st->st_ikev2) {
			/* IKEv1 */
			whack_log(RC_COMMENT,
			  "\"%s\"%s:   IKE algorithm newest: %s_%03d-%s-%s",
			  c->name,
			  instance,
			  enum_show_shortb(&oakley_enc_names, st->st_oakley.encrypt, &encbuf),
			  /* st->st_oakley.encrypter->keydeflen, */
			  st->st_oakley.enckeylen,
			  enum_show_shortb(&oakley_hash_names, st->st_oakley.prf_hash, &prfbuf),
			  enum_show_shortb(&oakley_group_names, st->st_oakley.group->group, &groupbuf));
		} else {
			/* IKEv2 */
			whack_log(RC_COMMENT,
			  "\"%s\"%s:   IKEv2 algorithm newest: %s_%03d-%s-%s-%s",
			  c->name,
			  instance,
			  enum_showb(&ikev2_trans_type_encr_names, st->st_oakley.encrypt, &encbuf),
			  /* st->st_oakley.encrypter->keydeflen, */
			  st->st_oakley.enckeylen,
			  enum_showb(&ikev2_trans_type_integ_names, st->st_oakley.integ_hash, &integbuf),
			  enum_showb(&ikev2_trans_type_prf_names, st->st_oakley.prf_hash, &prfbuf),
			  enum_show_shortb(&oakley_group_names, st->st_oakley.group->group, &groupbuf));
		}
	}
}
