/*
 * IKE modular algorithm handling interface
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 * Copyright (C) 2003 Mathieu Lafon <mlafon@arkoon.net>
 * Copyright (C) 2005-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007 Ken Bantoft <ken@xelerance.com>
 * Copyright (C) 2011-2012 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013-2014 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013-2014 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
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
#ifdef USE_3DES
#include "ike_alg_3des.h"
#endif

/*==========================================================
*
*       IKE algo list handling
*
*       - registration
*       - lookup
*=========================================================*/

#define IKE_ALG_FOR_EACH(ALG,A)						\
	for (const struct ike_alg *(A) = ike_alg_base[ALG];		\
	     (A) != NULL;						\
	     (A) = (A)->algo_next)

static const struct ike_alg *ike_alg_base[IKE_ALG_ROOF] = { NULL, NULL, NULL };

bool ike_alg_enc_requires_integ(const struct encrypt_desc *enc_desc)
{
	return enc_desc != NULL && enc_desc->do_aead_crypt_auth == NULL;
}

bool ike_alg_enc_present(int ealg)
{
	const struct encrypt_desc *enc_desc = ikev1_alg_get_encrypter(ealg);

	return enc_desc != NULL && enc_desc->enc_blocksize != 0;
}

/*	check if IKE hash algo is present */
bool ike_alg_hash_present(int halg)
{
	const struct hash_desc *hash_desc = ikev1_alg_get_hasher(halg);

	return hash_desc != NULL && hash_desc->hash_digest_len != 0;
}

bool ike_alg_enc_ok(int ealg, unsigned key_len,
		    struct alg_info_ike *alg_info_ike __attribute__((unused)),
		    const char **errp, char *ugh_buf, size_t ugh_buf_len)
{
	int ret = TRUE;
	const struct encrypt_desc *enc_desc = ikev1_alg_get_encrypter(ealg);

	passert(ugh_buf_len != 0);
	if (enc_desc == NULL) {
		/* failure: encrypt algo must be present */
		snprintf(ugh_buf, ugh_buf_len, "encrypt algo not found");
		ret = FALSE;
	} else if (key_len != 0 && (key_len < enc_desc->keyminlen ||
				    key_len > enc_desc->keymaxlen)) {
		/* failure: if key_len specified, it must be in range */
		snprintf(ugh_buf, ugh_buf_len,
			 "key_len not in range: encalg=%d, key_len=%d, keyminlen=%d, keymaxlen=%d",
			 ealg, key_len,
			 enc_desc->keyminlen,
			 enc_desc->keymaxlen);
		libreswan_log("ike_alg_enc_ok(): %s", ugh_buf);
		ret = FALSE;
	}

	DBG(DBG_KERNEL,
	    if (ret) {
		    DBG_log("ike_alg_enc_ok(ealg=%d,key_len=%d): blocksize=%d, keyminlen=%d, keydeflen=%d, keymaxlen=%d, ret=%d",
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
	if (!ret && errp != NULL)
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
	bool ealg_insecure = (key_len < 128);

	if (ealg_insecure || alg_info_ike != NULL) {
		if (alg_info_ike != NULL) {
			struct ike_info *ike_info;
			int i;

			ALG_INFO_IKE_FOREACH(alg_info_ike, ike_info, i) {
				if (ike_info->ike_ealg == ealg &&
				    (ike_info->ike_eklen == 0 ||
				     key_len == 0 ||
				     ike_info->ike_eklen == key_len) &&
				    ike_info->ike_halg == aalg &&
				    ike_info->ike_modp == group) {
					if (ealg_insecure) {
						loglog(RC_LOG_SERIOUS,
						       "You should NOT use insecure/broken IKE algorithms (%s)!",
						       enum_name(
								&oakley_enc_names,
								ealg));
					}
					return TRUE;
				}
			}
		}
		libreswan_log(
			"Oakley Transform [%s (%d), %s, %s] refused%s",
			enum_name(&oakley_enc_names, ealg), key_len,
			enum_name(&oakley_hash_names, aalg),
			enum_name(&oakley_group_names, group),
			ealg_insecure ?
				" due to insecure key_len and enc. alg. not listed in \"ike\" string" :
				"");
		return FALSE;
	}
	return TRUE;
}

/*
 *      return ike_algo object by {type, id}
 *      this is also used in ikev2 despite name :/
 */
static const struct ike_alg *ikev1_alg_find(enum ike_alg_type algo_type,
					    unsigned algo_id)
{
	IKE_ALG_FOR_EACH(algo_type, e) {
		if (e->algo_id == algo_id)
			return e;
	}
	return NULL;
}

const struct hash_desc *ikev1_alg_get_hasher(int alg)
{
	return (const struct hash_desc *) ikev1_alg_find(IKE_ALG_HASH, alg);
}

const struct encrypt_desc *ikev1_alg_get_encrypter(int alg)
{
	return (const struct encrypt_desc *) ikev1_alg_find(IKE_ALG_ENCRYPT, alg);
}

static const struct ike_alg *ikev2_alg_find(enum ike_alg_type algo_type,
					    enum ikev2_trans_type_encr algo_v2id)
{
	IKE_ALG_FOR_EACH(algo_type, e) {
		if (e->algo_v2id == algo_v2id)
			return e;
	}
	return NULL;
}

const struct encrypt_desc *ikev2_alg_get_encrypter(int id)
{
	/*
	 * these types are mixed up, so go along with it :(
	 * IKEv2_ENCR_CAMELLIA_CBC_ikev1 == ESP_CAMELLIAv1
	 * IKEv2_ENCR_CAMELLIA_CBC == ESP_CAMELLIA
	 */
	if (id == IKEv2_ENCR_CAMELLIA_CBC_ikev1)
		id = IKEv2_ENCR_CAMELLIA_CBC;

	return (const struct encrypt_desc *) ikev2_alg_find(IKE_ALG_ENCRYPT, id);
}

const struct hash_desc *ikev2_alg_get_hasher(int id)
{
	return (const struct hash_desc *) ikev2_alg_find(IKE_ALG_HASH, id);
}

const struct hash_desc *ikev2_alg_get_integ(int id)
{
	return (const struct hash_desc *) ikev2_alg_find(IKE_ALG_INTEG, id);
}

/*
 *      Main "raw" ike_alg list adding function
 */
void ike_alg_add(struct ike_alg *a)
{
	passert(a->algo_type < IKE_ALG_ROOF);
	passert(a->algo_id != 0 || a->algo_v2id != 0);	/* must be useful for v1 or v2 */

	/* must not duplicate what has already been added */
	passert(a->algo_id == 0 || ikev1_alg_find(a->algo_type, a->algo_id) == NULL);
	passert(a->algo_v2id == 0 || ikev2_alg_find(a->algo_type, a->algo_v2id) == NULL);

	passert(a->algo_next == NULL);	/* must not already be on a list */
	a->algo_next = ike_alg_base[a->algo_type];
	ike_alg_base[a->algo_type] = a;
}

/*
 * Validate and register IKE hash algorithm object
 *
 * XXX: BUG: This uses IKEv1 oakley_hash_names, but for
 * IKEv2 we have more entries, see ikev2_trans_type_integ_names
 * ??? why is this only used by ike_alg_sha2_init?
 */
bool ike_alg_register_hash(struct hash_desc *hash_desc)
{
	const char *alg_name = "<none>";
	bool ret = FALSE;

	if (hash_desc->common.algo_id > OAKLEY_HASH_MAX) {
		libreswan_log("ike_alg_register_hash(): hash alg=%d < max=%d",
		     hash_desc->common.algo_id, OAKLEY_HASH_MAX);
	} else if (hash_desc->hash_ctx_size > sizeof(union hash_ctx)) {
		libreswan_log("ike_alg_register_hash(): hash alg=%d has ctx_size=%d > hash_ctx=%d",
		     hash_desc->common.algo_id,
		     (int)hash_desc->hash_ctx_size,
		     (int)sizeof(union hash_ctx));
	} else if (hash_desc->hash_init == NULL ||
			hash_desc->hash_update == NULL ||
			hash_desc->hash_final == NULL) {
		libreswan_log("ike_alg_register_hash(): hash alg=%d missing hash_init(), hash_update(), or hash_final()",
		     hash_desc->common.algo_id);
	} else {
		alg_name = enum_name(&oakley_hash_names, hash_desc->common.algo_id);

		/* Don't add anything we do not know the name for */
		if (alg_name == NULL) {
			libreswan_log("ike_alg_register_hash(): ERROR: hash alg=%d not found in constants.c:oakley_hash_names",
			     hash_desc->common.algo_id);
			alg_name = "<NULL>";
		} else {
			/* success! */
			ret = TRUE;
			if (hash_desc->common.name == NULL)
				hash_desc->common.name = clone_str(alg_name, "hasher name (ignore)");

			ike_alg_add(&hash_desc->common);
		}
	}

	libreswan_log("ike_alg_register_hash(): Activating %s: %s",
		      alg_name,
		      ret ? "Ok" : "FAILED");
	return ret;
}

/*
 *      Validate and register IKE encryption algorithm object
 */
bool ike_alg_register_enc(struct encrypt_desc *enc_desc)
{
	const char *alg_name;
	bool ret = TRUE;

	/* XXX struct algo_aes_ccm_8 up to algo_aes_gcm_16, where
	 * "common.algo_id" is not defined need this officname fallback.
	 * These are defined in kernel_netlink.c and need to move to
	 * the proper place - even if klips does not support these
	 */
	alg_name = enum_name(&oakley_enc_names, enc_desc->common.algo_id);
	if (alg_name == NULL) {
		alg_name = enc_desc->common.officname;
		if (alg_name == NULL) {
			libreswan_log("ike_alg_register_enc(): ERROR: enc alg=%d not found in constants.c:oakley_enc_names",
			     enc_desc->common.algo_id);
			alg_name = "<NULL>";
			ret = FALSE;
		}
	}

	if (ret)
		ike_alg_add(&enc_desc->common);

	libreswan_log("ike_alg_register_enc(): Activating %s: %s",
		      alg_name,
		      ret? "Ok" : "FAILED");

	return ret;
}

/* Get pfsgroup for this connection */
const struct oakley_group_desc *ike_alg_pfsgroup(struct connection *c,
						 lset_t policy)
{
	const struct oakley_group_desc * ret = NULL;

	/* ??? 0 isn't a legitimate value for esp_pfsgroup */
	if ((policy & POLICY_PFS) &&
	    c->alg_info_esp != NULL &&
	    c->alg_info_esp->esp_pfsgroup != 0)
		ret = lookup_group(c->alg_info_esp->esp_pfsgroup);
	return ret;
}

CK_MECHANISM_TYPE nss_encryption_mech(const struct encrypt_desc *encrypter)
{
	/* the best wey have for "undefined" */
	CK_MECHANISM_TYPE mechanism = CKM_VENDOR_DEFINED;

	switch (encrypter->common.algo_id) {
	case OAKLEY_3DES_CBC:
		mechanism = CKM_DES3_CBC;
		break;
#ifdef NOT_YET
	case OAKLEY_CAST_CBC:
		mechanism = CKM_CAST5_CBC:
		break;
#endif
	case OAKLEY_AES_CBC:
		mechanism = CKM_AES_CBC;
		break;
	case OAKLEY_CAMELLIA_CBC:
		mechanism = CKM_CAMELLIA_CBC;
		break;
	case OAKLEY_AES_CTR:
		mechanism = CKM_AES_CTR;
		break;
#ifdef NOT_YET
	case OAKLEY_AES_CCM_8:
	case OAKLEY_AES_CCM_12:
	case OAKLEY_AES_CCM_16:
		mechanism = CKM_AES_CCM;
		break;
#endif
	case OAKLEY_AES_GCM_8:
	case OAKLEY_AES_GCM_12:
	case OAKLEY_AES_GCM_16:
		mechanism = CKM_AES_GCM;
		break;
#ifdef NOT_YET
	case OAKLEY_TWOFISH_CBC:
		mechanism = CKM_TWOFISH_CBC;
		break;
#endif
	default:
		loglog(RC_LOG_SERIOUS,
			"NSS: Unsupported encryption mechanism for %s",
			enum_short_name(&oakley_enc_names,
				encrypter->common.algo_id));
		break;
	}
	return mechanism;
}

/*
 * Show registered IKE algorithms
 */
void ike_alg_show_status(void)
{
	whack_log(RC_COMMENT, "IKE algorithms supported:");
	whack_log(RC_COMMENT, " "); /* spacer */

	IKE_ALG_FOR_EACH(IKE_ALG_ENCRYPT, algo) {
		struct esb_buf v1namebuf, v2namebuf;
		const struct encrypt_desc *encrypt = (const struct encrypt_desc *)algo;

		passert(algo->algo_id != 0 || algo->algo_v2id != 0);
		whack_log(RC_COMMENT,
			  "algorithm IKE encrypt: v1id=%d, v1name=%s, v2id=%d, v2name=%s, blocksize=%zu, keydeflen=%u",
			  algo->algo_id,
			  enum_showb(&oakley_enc_names, algo->algo_id, &v1namebuf),
			  algo->algo_v2id,
			  enum_showb(&ikev2_trans_type_encr_names, algo->algo_v2id, &v2namebuf),
			  encrypt->enc_blocksize,
			  encrypt->keydeflen);
	}
	IKE_ALG_FOR_EACH(IKE_ALG_HASH, algo) {
		const struct hash_desc *hash = (const struct hash_desc *)algo;
		/*
		 * ??? we think that hash_integ_len is meaningless
		 * (and 0) for IKE hashes.
		 *
		 * Hash algorithms have hash_integ_len == 0.
		 * Integrity algorithms (a different list) do not.
		 */
		pexpect(hash->hash_integ_len == 0);
		whack_log(RC_COMMENT,
			  "algorithm IKE hash: id=%d, name=%s, hashlen=%zu",
			  algo->algo_id,
			  enum_name(&oakley_hash_names, algo->algo_id),
			  hash->hash_digest_len);
	}

	const struct oakley_group_desc *gdesc;
	for (gdesc = next_oakley_group(NULL);
	     gdesc != NULL;
	     gdesc = next_oakley_group(gdesc)) {
		whack_log(RC_COMMENT,
			  "algorithm IKE dh group: id=%d, name=%s, bits=%d",
			  gdesc->group,
			  enum_name(&oakley_group_names, gdesc->group),
			  (int)gdesc->bytes * BITS_PER_BYTE);
	}

	whack_log(RC_COMMENT, " "); /* spacer */
}

/*
 * Validate and register IKE algorithm objects
 */

static struct ike_alg *algorithms[] = {
#ifdef USE_3DES
	&ike_alg_encrypt_3des_cbc.common,
#endif
};

void ike_alg_init(void)
{
	for (unsigned i = 0; i < elemsof(algorithms); i++) {
		struct ike_alg *alg = algorithms[i];
		DBG(DBG_CRYPT, DBG_log("adding algorithm %s, id: %d, v2id: %d",
				       alg->name, alg->algo_id, alg->algo_v2id));
		ike_alg_add(alg);
	}
}
