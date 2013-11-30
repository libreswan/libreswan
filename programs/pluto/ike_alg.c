/*
 * IKE modular algorithm handling interface
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
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
 *      ML:	ike_alg_ok_final() funcion (make F_STRICT consider hash/auth and modp).
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <libreswan.h>
#include <libreswan/ipsec_policy.h>

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

#define return_on(var, val) { (var) = (val); goto return_out; }

/*==========================================================
*
*       IKE algo list handling
*
*       - registration
*       - lookup
*=========================================================*/

struct ike_alg *ike_alg_base[IKE_ALG_ROOF] = { NULL, NULL, NULL };

static const char *ike_alg_type_name[] = { "encryption", "hashing", "integrity" };

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
		    const char **errp, char *ugh_buf, size_t ugh_buf_len)
{
	int ret = TRUE;
	struct encrypt_desc *enc_desc;

	enc_desc = ike_alg_get_encrypter(ealg);
	if (!enc_desc) {
		/* failure: encrypt algo must be present */
		snprintf(ugh_buf, ugh_buf_len, "encrypt algo not found");
		ret = FALSE;
	} else if ((key_len) && ((key_len < enc_desc->keyminlen) ||
				 (key_len > enc_desc->keymaxlen))) {
		/* failure: if key_len specified, it must be in range */
		snprintf(ugh_buf, ugh_buf_len,
			 "key_len not in range: encalg=%d, "
			 "key_len=%d, keyminlen=%d, keymaxlen=%d",
			 ealg, key_len,
			 enc_desc->keyminlen,
			 enc_desc->keymaxlen
			 );
		libreswan_log("ike_alg_enc_ok(): %.*s", (int)ugh_buf_len,  ugh_buf);
		ret = FALSE;
	}

	DBG(DBG_KERNEL,
	    if (ret) {
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
	    } else {
		    DBG_log("ike_alg_enc_ok(ealg=%d,key_len=%d): NO",
			    ealg, key_len);
	    }
	    );
	if (!ret && errp)
		*errp = ugh_buf;
	return ret;
}

/*
 * ML: make F_STRICT logic consider enc,hash/auth,modp algorithms
 */
bool ike_alg_ok_final(int ealg, unsigned key_len, int aalg, unsigned int group,
		      struct alg_info_ike *alg_info_ike)
{
	/*
	 * simple test to toss low key_len, will accept it only
	 * if specified in "esp" string
	 */
	int ealg_insecure = (key_len < 128);

	if (ealg_insecure || alg_info_ike) {
		int i;
		struct ike_info *ike_info;
		if (alg_info_ike) {
			ALG_INFO_IKE_FOREACH(alg_info_ike, ike_info, i) {
				if ((ike_info->ike_ealg == ealg) &&
				    ((ike_info->ike_eklen == 0) ||
				     (key_len == 0) ||
				     (ike_info->ike_eklen == key_len)) &&
				    (ike_info->ike_halg == aalg) &&
				    (ike_info->ike_modp == group)) {
					if (ealg_insecure) {
						loglog(RC_LOG_SERIOUS,
						       "You should NOT use insecure/broken IKE algorithms (%s)!",
						       enum_name(&
								 oakley_enc_names,
								 ealg));
					}
					return TRUE;
				}
			}
		}
		libreswan_log(
			"Oakley Transform [%s (%d), %s, %s] refused %s",
			enum_name(&oakley_enc_names, ealg), key_len,
			enum_name(&oakley_hash_names, aalg),
			enum_name(&oakley_group_names,
				  group),
			ealg_insecure ? "due to insecure key_len and enc. alg. not listed in \"ike\" string" : ""
			);
		return FALSE;
	}
	return TRUE;
}

/*
 *      return ike_algo object by {type, id}
 */
/* XXX:jjo use keysize */
struct ike_alg *ike_alg_find(unsigned algo_type, unsigned algo_id, unsigned keysize __attribute__(
				     (unused)))
{
	struct ike_alg *e;

	for (e = ike_alg_base[algo_type]; e != NULL; e = e->algo_next) {
		if (e->algo_id == algo_id)
			break;
	}
	return e;
}

struct ike_alg *ike_alg_ikev2_find(unsigned algo_type,
				   enum ikev2_trans_type_encr algo_v2id,
				   unsigned keysize __attribute__((unused)))
{
	struct ike_alg *e = ike_alg_base[algo_type];

	for (; e != NULL; e = e->algo_next) {
		if (e->algo_v2id == algo_v2id)
			break;
	}
	return e;
}

/*
 *      Main "raw" ike_alg list adding function
 */
int ike_alg_add(struct ike_alg* a)
{
	passert(a->algo_type < IKE_ALG_ROOF);
	passert(a->algo_id != 0 || a->algo_v2id != 0);

	if (ike_alg_find(a->algo_type, a->algo_id, 0)) {
		libreswan_log(
			"ike_alg_add(): ERROR: %s algorithm, algo_id %d, algorithm type already registered",
			ike_alg_type_name[a->algo_type],
			a->algo_id);
		return -EEXIST;
	}

	a->algo_next = ike_alg_base[a->algo_type];
	ike_alg_base[a->algo_type] = a;
	return 0;
}

/*
 *      Validate and register IKE hash algorithm object
 *      XXX: BUG: This uses IKEv1 oakley_hash_names, but for
 *           IKEv2 we have more entries, see ikev2_trans_type_integ_names
 */
int ike_alg_register_hash(struct hash_desc *hash_desc)
{
	const char *alg_name = "<none>";
	int ret = 0;

	if (hash_desc->common.algo_id > OAKLEY_HASH_MAX) {
		libreswan_log("ike_alg_register_hash(): hash alg=%d < max=%d",
		     hash_desc->common.algo_id, OAKLEY_HASH_MAX);
		return_on(ret, -EINVAL);
	}
	if (hash_desc->hash_ctx_size > sizeof(union hash_ctx)) {
		libreswan_log("ike_alg_register_hash(): hash alg=%d has "
		     "ctx_size=%d > hash_ctx=%d",
		     hash_desc->common.algo_id,
		     (int)hash_desc->hash_ctx_size,
		     (int)sizeof(union hash_ctx));
		return_on(ret, -EOVERFLOW);
	}
	if (!(hash_desc->hash_init && hash_desc->hash_update &&
	      hash_desc->hash_final)) {
		libreswan_log("ike_alg_register_hash(): hash alg=%d needs  "
		     "hash_init(), hash_update() and hash_final()",
		     hash_desc->common.algo_id);
		return_on(ret, -EINVAL);
	}

	alg_name = enum_name(&oakley_hash_names, hash_desc->common.algo_id);

	/* Don't add anything we do not know the name for */
	if (!alg_name) {
		libreswan_log("ike_alg_register_hash(): ERROR: hash alg=%d not found in "
		     "constants.c:oakley_hash_names  ",
		     hash_desc->common.algo_id);
		alg_name = "<NULL>";
		return_on(ret, -EINVAL);
	}

	if (hash_desc->common.name == NULL)
		hash_desc->common.name = clone_str(alg_name, "hasher name");

return_out:
	if (ret == 0)
		ret = ike_alg_add((struct ike_alg *)hash_desc);
	libreswan_log("ike_alg_register_hash(): Activating %s: %s (ret=%d)",
		      alg_name,
		      ret == 0 ? "Ok" : "FAILED",
		      ret);
	return ret;
}

/*
 *      Validate and register IKE encryption algorithm object
 */
int ike_alg_register_enc(struct encrypt_desc *enc_desc)
{
	const char *alg_name;
	int ret = 0;

	/* XXX struct algo_aes_ccm_8 up to algo_aes_gcm_16, where
	 * "common.algo_id" is not defined need this officename fallback.
	 * These are defined in kernel_netlink.c and need to move to
	 * the proper place - even if klips does not support these
	 */
	alg_name = enum_name(&oakley_enc_names, enc_desc->common.algo_id);
	if (!alg_name) {
		alg_name = enc_desc->common.officname;
		if (!alg_name) {
			libreswan_log("ike_alg_register_enc(): ERROR: enc alg=%d not found in "
			     "constants.c:oakley_enc_names  ",
			     enc_desc->common.algo_id);
			alg_name = "<NULL>";
			return_on(ret, -EINVAL);
		}
	}
return_out:

	if (ret == 0)
		ret = ike_alg_add((struct ike_alg *)enc_desc);
	libreswan_log("ike_alg_register_enc(): Activating %s: %s (ret=%d)",
		      alg_name, ret == 0 ? "Ok" : "FAILED", ret);
	return 0;
}
/* Get pfsgroup for this connection */
const struct oakley_group_desc *ike_alg_pfsgroup(struct connection *c,
						 lset_t policy)
{
	const struct oakley_group_desc * ret = NULL;

	if ( (policy & POLICY_PFS) &&
	     c->alg_info_esp && c->alg_info_esp->esp_pfsgroup)
		ret = lookup_group(c->alg_info_esp->esp_pfsgroup);
	return ret;
}
