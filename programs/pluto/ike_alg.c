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

#define return_on(var, val) do { var=val;goto return_out; } while(0);

/*==========================================================
 *
 * 	IKE algo list handling
 *
 * 	- registration
 * 	- lookup
 *=========================================================*/
struct ike_alg *ike_alg_base[IKE_ALG_MAX+1] = {NULL, NULL};
/*	check if IKE encrypt algo is present */
bool ike_alg_enc_present(int ealg)
{
	struct encrypt_desc *enc_desc = ike_alg_get_encrypter(ealg);
	return enc_desc ? enc_desc->enc_blocksize : 0;
}
/*	check if IKE hash algo is present */
bool ike_alg_hash_present(int halg)
{
	struct hash_desc *hash_desc = ike_alg_get_hasher(halg);
	return hash_desc ? hash_desc->hash_digest_len : 0;
}
bool ike_alg_enc_ok(int ealg, unsigned key_len, 
		struct alg_info_ike *alg_info_ike __attribute__((unused)), 
		const char **errp)
{
	int ret=TRUE;
	struct encrypt_desc *enc_desc;
	char errbuf[256]="encrypt algo not found";
	/* 
	 * test #1: encrypt algo must be present 
	 */
	enc_desc = ike_alg_get_encrypter(ealg);
	if (!enc_desc) return_on(ret, FALSE);
	/* 
	 * test #2: if key_len specified, it must be in range 
	 */
	if ((key_len) && ((key_len < enc_desc->keyminlen) ||
			 (key_len > enc_desc->keymaxlen))) {
		snprintf(errbuf, sizeof(errbuf)-1,
				"key_len not in range: encalg=%d, "
				"key_len=%d, keyminlen=%d, keymaxlen=%d",
				ealg, key_len,
				enc_desc->keyminlen,
				enc_desc->keymaxlen
		       );
		plog ("ike_alg_enc_ok(): %s", errbuf);
		return_on(ret, FALSE);
	} 
#if 0 /* ML: logic moved to ike_alg_ok_final() */
	/* 
	 * test #3: if alg_info specified AND strict flag, only
	 * only allow algo iff listed in st->alg_info_esp
	 */
	else if (alg_info_ike && (alg_info_ike->alg_info_flags & ALG_INFO_F_STRICT) ) {
		int i;
		struct ike_info *ike_info;
		ALG_INFO_IKE_FOREACH(alg_info_ike, ike_info, i) {
			if ((ike_info->ike_ealg == ealg) &&
				((ike_info->ike_eklen==0) || (key_len==0) ||
				 (ike_info->ike_eklen==key_len))) {
				return_on(ret, TRUE);
			}
		}
		snprintf(errbuf, sizeof(errbuf),
				"strict flag and encrypt algorithm "
				"not in transform string list: "
				"ealg=%d, "
				"key_len=%d, keyminbits=%d, keymaxbits=%d",
				ealg, key_len,
				enc_desc->keyminlen,
				enc_desc->keymaxlen
		   );
		log("ike_alg_enc_ok(): %s", errbuf);
		return_on(ret, FALSE);
	}
#endif
return_out:
	DBG(DBG_KLIPS, 
		if (ret) 
			DBG_log("ike_alg_enc_ok(ealg=%d,key_len=%d): "
				"blocksize=%d, keyminlen=%d, "
				"keydeflen=%d, keymaxlen=%d, "
				"ret=%d",
				ealg, key_len,
				(int)enc_desc->enc_blocksize,
				enc_desc->keyminlen,
				enc_desc->keydeflen,
				enc_desc->keymaxlen,
				ret);
		else 
			DBG_log("ike_alg_enc_ok(ealg=%d,key_len=%d): NO",
				ealg, key_len);
	);
	if (!ret && *errp)
		*errp=errbuf;
	return ret;
}
/* 
 * ML: make F_STRICT logic consider enc,hash/auth,modp algorithms 
 */
bool ike_alg_ok_final(int ealg, unsigned key_len, int aalg, int group, struct alg_info_ike *alg_info_ike)
{
	/* 
	 * simple test to toss low key_len, will accept it only
	 * if specified in "esp" string
	 */
	int ealg_insecure=(key_len < 128) ;

	if (ealg_insecure || 
		(alg_info_ike && alg_info_ike->alg_info_flags & ALG_INFO_F_STRICT))
	{
		int i;
		struct ike_info *ike_info;
		if (alg_info_ike) {
			ALG_INFO_IKE_FOREACH(alg_info_ike, ike_info, i) {
				if ((ike_info->ike_ealg == ealg) &&
						((ike_info->ike_eklen==0) || (key_len==0) ||
						 (ike_info->ike_eklen==key_len)) &&
						(ike_info->ike_halg == aalg) &&
						(ike_info->ike_modp == group)) {
#ifndef USE_1DES
					if (ealg_insecure) 
						loglog(RC_LOG_SERIOUS, "You should NOT use insecure IKE algorithms (%s)!"
								, enum_name(&oakley_enc_names, ealg));
#endif
					return TRUE;
				}
			}
		}
		openswan_log("Oakley Transform [%s (%d), %s, %s] refused due to %s",
			enum_name(&oakley_enc_names, ealg), key_len,
			enum_name(&oakley_hash_names, aalg),
			enum_name(&oakley_group_names, group),
			ealg_insecure ? "insecure key_len and enc. alg. not listed in \"ike\" string" : "strict flag"
			);
		return FALSE;
	}
	return TRUE;
}
/*
 * 	return ike_algo object by {type, id}
 */
/* XXX:jjo use keysize */
struct ike_alg *
ike_alg_find(unsigned algo_type, unsigned algo_id, unsigned keysize __attribute__((unused)))
{
	struct ike_alg *e=ike_alg_base[algo_type];
	for(;e!=NULL;e=e->algo_next) {
		if (e->algo_id==algo_id)
			break;
	}
	return e;
}

/*
 * 	Main "raw" ike_alg list adding function
 */
int
ike_alg_add(struct ike_alg* a)
{
	int ret=0;
	const char *ugh="No error";
	if (a->algo_type > IKE_ALG_MAX)
	{
		ugh="Invalid algo_type";
		return_on(ret,-EINVAL);
	}
	if (ike_alg_find(a->algo_type, a->algo_id, 0))
	{
		ugh="Algorithm already exists";
		return_on(ret,-EEXIST);
	}
	if (ret==0) {
		a->algo_next=ike_alg_base[a->algo_type];
		ike_alg_base[a->algo_type]=a;
	}
return_out:
	if (ret) 
		openswan_log("ike_alg_add(): ERROR: %s", ugh);
	return ret;
}

/*
 * 	Validate and register IKE hash algorithm object
 */
int
ike_alg_register_hash(struct hash_desc *hash_desc)
{
	const char *alg_name = "<none>";
	int ret=0;

	if (hash_desc->common.algo_id > OAKLEY_HASH_MAX) {
		plog ("ike_alg_register_hash(): hash alg=%d < max=%d",
				hash_desc->common.algo_id, OAKLEY_HASH_MAX);
		return_on(ret,-EINVAL);
	}
	if (hash_desc->hash_ctx_size > sizeof (union hash_ctx)) {
		plog ("ike_alg_register_hash(): hash alg=%d has "
				"ctx_size=%d > hash_ctx=%d",
				hash_desc->common.algo_id, 
				(int)hash_desc->hash_ctx_size,
				(int)sizeof (union hash_ctx));
		return_on(ret,-EOVERFLOW);
	}
	if (!(hash_desc->hash_init&&hash_desc->hash_update&&hash_desc->hash_final)) {
		plog ("ike_alg_register_hash(): hash alg=%d needs  "
				"hash_init(), hash_update() and hash_final()",
				hash_desc->common.algo_id);
		return_on(ret,-EINVAL);
	}

	alg_name=enum_name(&oakley_hash_names, hash_desc->common.algo_id);

	if (!alg_name) {
		plog ("ike_alg_register_hash(): WARNING: hash alg=%d not found in "
				"constants.c:oakley_hash_names  ",
				hash_desc->common.algo_id);
		alg_name="<NULL>";
	}
	
	if(hash_desc->common.name == NULL) {
	    hash_desc->common.name = clone_str(alg_name, "hasher name");
	}

return_out:
	if (ret==0)
		ret=ike_alg_add((struct ike_alg *)hash_desc);
	openswan_log("ike_alg_register_hash(): Activating %s: %s (ret=%d)", 
			alg_name, ret==0? "Ok" : "FAILED", ret);
	return ret;
}

/*
 * 	Validate and register IKE encryption algorithm object
 */
int
ike_alg_register_enc(struct encrypt_desc *enc_desc)
{
	const char *alg_name;
	int ret=0;

#if OAKLEY_ENCRYPT_MAX < 255
	if (enc_desc->common.algo_id > OAKLEY_ENCRYPT_MAX) {
		plog ("ike_alg_register_enc(): enc alg=%d < max=%d\n",
				enc_desc->common.algo_id, OAKLEY_ENCRYPT_MAX);
		return_on(ret, -EINVAL);
	}
#endif

	alg_name=enum_name(&oakley_enc_names, enc_desc->common.algo_id);
	if (!alg_name) {
		plog ("ike_alg_register_enc(): WARNING: enc alg=%d not found in "
				"constants.c:oakley_enc_names  ",
				enc_desc->common.algo_id);
		alg_name="<NULL>";
	}
#if OAKLEY_ENCRYPT_MAX < 255
return_out:
#endif

	if (ret==0)
		ret=ike_alg_add((struct ike_alg *)enc_desc);
	openswan_log("ike_alg_register_enc(): Activating %s: %s (ret=%d)", 
			alg_name, ret==0? "Ok" : "FAILED", ret);
	return 0;
}
/* Get pfsgroup for this connection */
const struct oakley_group_desc *
ike_alg_pfsgroup(struct connection *c, lset_t policy)
{
	const struct oakley_group_desc * ret = NULL;
	if ( (policy & POLICY_PFS) && 
			c->alg_info_esp && c->alg_info_esp->esp_pfsgroup)
		ret = lookup_group(c->alg_info_esp->esp_pfsgroup);
	return ret;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
