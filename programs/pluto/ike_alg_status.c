/*
 * IKE modular algorithm handling interface
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 * 
 * ike_alg.c,v 1.1.2.18 2002/05/29 04:13:04 jjo Exp
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
 * 	ML:	Mathieu Lafon <mlafon@arkoon.net>
 *
 * Fixes:
 * 	ML:	ike_alg_ok_final() funcion (make F_STRICT consider hash/auth and modp).
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>

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
 * 	Show registered IKE algorithms
 */
void
ike_alg_show_status(void)
{
	unsigned alg, i;
	struct ike_alg *algo;
	IKE_EALG_FOR_EACH(algo) {
		passert(algo != NULL);
		alg=algo->algo_id;
		whack_log(RC_COMMENT, "algorithm IKE encrypt: id=%d, name=%s, blocksize=%d, keydeflen=%d"
			, alg
			, enum_name(&oakley_enc_names, alg)
			, (int)((struct encrypt_desc *)algo)->enc_blocksize
			, ((struct encrypt_desc *)algo)->keydeflen
			);
		
	}
	IKE_HALG_FOR_EACH(algo) {
		whack_log(RC_COMMENT, "algorithm IKE hash: id=%d, name=%s, hashsize=%d"
			, algo->algo_id
			, enum_name(&oakley_hash_names, algo->algo_id)
			, (int)((struct hash_desc *)algo)->hash_digest_len
			);
	}
#define IKE_DH_ALG_FOR_EACH(idx) for(idx = 0; idx != oakley_group_size; idx++)
	IKE_DH_ALG_FOR_EACH(i) {
		const struct oakley_group_desc *gdesc=oakley_group+i;
		whack_log(RC_COMMENT, "algorithm IKE dh group: id=%d, name=%s, bits=%d"
			, gdesc->group
			, enum_name(&oakley_group_names, gdesc->group)
			, (int)gdesc->bytes*BITS_PER_BYTE
			);
	}
}
/*
 * 	Show IKE algorithms for 
 * 	- this connection (result from ike= string)
 * 	- newest SA
 */
void
ike_alg_show_connection(struct connection *c, const char *instance)
{
	char buf[256];
	struct state *st;
	if (c->alg_info_ike) {
		alg_info_snprint(buf, sizeof(buf)-1, 
				 (struct alg_info *)c->alg_info_ike, TRUE);
		whack_log(RC_COMMENT
		    , "\"%s\"%s:   IKE algorithms wanted: %s"
		    , c->name
		    , instance
		    , buf);
	}
	if (c->alg_info_ike) {
		alg_info_snprint_ike(buf, sizeof(buf)-1, c->alg_info_ike);
		whack_log(RC_COMMENT
		    , "\"%s\"%s:   IKE algorithms found:  %s"
		    , c->name
		    , instance
		    , buf);
	}
	st = state_with_serialno(c->newest_isakmp_sa);
	if (st)
		whack_log(RC_COMMENT
		, "\"%s\"%s:   IKE algorithm newest: %s_%d-%s-%s"
		, c->name
		, instance
		, enum_show(&oakley_enc_names, st->st_oakley.encrypt)
		+7 /* strlen("OAKLEY_") */
		/* , st->st_oakley.encrypter->keydeflen */
		, st->st_oakley.enckeylen
		, enum_show(&oakley_hash_names, st->st_oakley.hash)
		+7 /* strlen("OAKLEY_") */
		, enum_show(&oakley_group_names, st->st_oakley.group->group)
		+13 /* strlen("OAKLEY_GROUP_") */
	 );
}
