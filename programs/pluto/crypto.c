/* crypto interfaces
 * Copyright (C) 1998-2001,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
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
 *
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>

#include <libreswan.h>

#include <errno.h>

#include "constants.h"
#include "defs.h"
#include "state.h"
#include "log.h"
#include "md5.h"
#include "sha1.h"
#include "crypto.h" /* requires sha1.h and md5.h */
#include "alg_info.h"
#include "ike_alg.h"
#include "test_buffer.h"
#include "connections.h"

void init_crypto(void)
{
	ike_alg_init();
}

/* Oakley group description
 *
 * See:
 * RFC-2409 "The Internet key exchange (IKE)" Section 6
 * RFC-3526 "More Modular Exponential (MODP) Diffie-Hellman groups"
 */

/* magic signifier */
const struct oakley_group_desc unset_group = {
	.group = OAKLEY_GROUP_invalid,
};

static struct oakley_group_desc oakley_group[] = {
	/* modp768_modulus no longer supported - too weak */
	{
		.group = OAKLEY_GROUP_MODP1024,
		.gen = MODP_GENERATOR,
		.modp = MODP1024_MODULUS,
		.bytes = BYTES_FOR_BITS(1024),
	},
	{
		.group = OAKLEY_GROUP_MODP1536,
		.gen = MODP_GENERATOR,
		.modp = MODP1536_MODULUS,
		.bytes = BYTES_FOR_BITS(1536),
	},
	{
		.group = OAKLEY_GROUP_MODP2048,
		.gen = MODP_GENERATOR,
		.modp = MODP2048_MODULUS,
		.bytes = BYTES_FOR_BITS(2048),
	},
	{
		.group = OAKLEY_GROUP_MODP3072,
		.gen = MODP_GENERATOR,
		.modp = MODP3072_MODULUS,
		.bytes = BYTES_FOR_BITS(3072),
	},
	{
		.group = OAKLEY_GROUP_MODP4096,
		.gen = MODP_GENERATOR,
		.modp = MODP4096_MODULUS,
		.bytes = BYTES_FOR_BITS(4096),
	},
	{
		.group = OAKLEY_GROUP_MODP6144,
		.gen = MODP_GENERATOR,
		.modp = MODP6144_MODULUS,
		.bytes = BYTES_FOR_BITS(6144),
	},
	{
		.group = OAKLEY_GROUP_MODP8192,
		.gen = MODP_GENERATOR,
		.modp = MODP8192_MODULUS,
		.bytes = BYTES_FOR_BITS(8192),
	},
#ifdef USE_DH22
	{
		.group = OAKLEY_GROUP_DH22,
		.gen = MODP_GENERATOR_DH22,
		.modp = MODP1024_MODULUS_DH22,
		.bytes = BYTES_FOR_BITS(1024),
	},
#endif
	{
		.group = OAKLEY_GROUP_DH23,
		.gen = MODP_GENERATOR_DH23,
		.modp = MODP2048_MODULUS_DH23,
		.bytes = BYTES_FOR_BITS(2048),
	},
	{
		.group = OAKLEY_GROUP_DH24,
		.gen = MODP_GENERATOR_DH24,
		.modp = MODP2048_MODULUS_DH24,
		.bytes = BYTES_FOR_BITS(2048),
	},
};

const struct oakley_group_desc *lookup_group(u_int16_t group)
{
	int i;

	for (i = 0; i != elemsof(oakley_group); i++)
		if (group == oakley_group[i].group)
			return &oakley_group[i];

	return NULL;
}

const struct oakley_group_desc *next_oakley_group(const struct oakley_group_desc *group)
{
	if (group == NULL) {
		return &oakley_group[0];
	} else if (group < &oakley_group[elemsof(oakley_group) - 1]) {
		return group + 1;
	} else {
		return NULL;
	}
}

void get_oakley_group_param(const struct oakley_group_desc *group,
			    chunk_t *base, chunk_t *prime)
{
	*base = decode_hex_to_chunk(group->gen, group->gen);
	*prime = decode_hex_to_chunk(group->modp, group->modp);
}

/* Encryption Routines
 *
 * Each uses and updates the state object's st_new_iv.
 * This must already be initialized.
 * 1DES support removed - it is simply too weak
 * BLOWFISH support removed - author suggests TWOFISH instead
 */

void crypto_cbc_encrypt(const struct encrypt_desc *e, bool enc,
			u_int8_t *buf, size_t size, struct state *st)
{
	passert(st->st_new_iv_len >= e->enc_blocksize);
	st->st_new_iv_len = e->enc_blocksize;   /* truncate */

#if 0
	DBG(DBG_CRYPT,
	    DBG_log("encrypting buf=%p size=%d NSS keyptr: %p, iv: %p enc: %d",
		    buf, size, st->st_enc_key_nss,
		    st->st_new_iv, enc));
#endif

	e->do_crypt(buf, size, st->st_enc_key_nss, st->st_new_iv, enc);
}

/*
 * Return a required oakley or ipsec keysize or 0 if not required.
 * The first parameter uses 0 for ESP, and anything above that for
 * IKE major version
 */
int crypto_req_keysize(enum crk_proto ksproto, int algo)
{
	switch (ksproto) {
	case CRK_IKEv2:
		switch (algo) {
		case IKEv2_ENCR_CAST:
			return CAST_KEY_DEF_LEN;
		case IKEv2_ENCR_AES_CBC:
		case IKEv2_ENCR_AES_CTR:
		case IKEv2_ENCR_AES_CCM_8:
		case IKEv2_ENCR_AES_CCM_12:
		case IKEv2_ENCR_AES_CCM_16:
		case IKEv2_ENCR_AES_GCM_8:
		case IKEv2_ENCR_AES_GCM_12:
		case IKEv2_ENCR_AES_GCM_16:
		case IKEv2_ENCR_CAMELLIA_CBC_ikev1: /* IANA ikev1/ipsec-v3 fixup */
		case IKEv2_ENCR_CAMELLIA_CBC:
		case IKEv2_ENCR_NULL_AUTH_AES_GMAC:
			return AES_KEY_DEF_LEN;
		case IKEv2_ENCR_CAMELLIA_CTR:
		case IKEv2_ENCR_CAMELLIA_CCM_A:
		case IKEv2_ENCR_CAMELLIA_CCM_B:
		case IKEv2_ENCR_CAMELLIA_CCM_C:
			return CAMELLIA_KEY_DEF_LEN;
		/* private use */
		case IKEv2_ENCR_SERPENT_CBC:
			return SERPENT_KEY_DEF_LEN;
		case IKEv2_ENCR_TWOFISH_CBC:
		case IKEv2_ENCR_TWOFISH_CBC_SSH: /* ?? */
			return TWOFISH_KEY_DEF_LEN;
		default:
			return 0;
		}

	case CRK_IKEv1:
		switch (algo) {
		case OAKLEY_CAST_CBC:
			return CAST_KEY_DEF_LEN;
		case OAKLEY_AES_CBC:
			return AES_KEY_DEF_LEN;
		case OAKLEY_CAMELLIA_CBC:
			return CAMELLIA_KEY_DEF_LEN;
		/* private use */
		case OAKLEY_SERPENT_CBC:
			return SERPENT_KEY_DEF_LEN;
		case OAKLEY_TWOFISH_CBC:
		case OAKLEY_TWOFISH_CBC_SSH: /* ?? */
			return TWOFISH_KEY_DEF_LEN;
		default:
			return 0;
		}

	case CRK_ESPorAH:
		switch (algo) {
		case ESP_CAST:
			return CAST_KEY_DEF_LEN;
		case ESP_AES:
			return AES_KEY_DEF_LEN;
		case ESP_AES_CTR:
			return AES_CTR_KEY_DEF_LEN;
		case ESP_AES_CCM_8:
		case ESP_AES_CCM_12:
		case ESP_AES_CCM_16:
			return AES_CCM_KEY_DEF_LEN;
		case ESP_AES_GCM_8:
		case ESP_AES_GCM_12:
		case ESP_AES_GCM_16:
			return AES_GCM_KEY_DEF_LEN;
		case ESP_CAMELLIA:
		case ESP_CAMELLIAv1:
			return CAMELLIA_KEY_DEF_LEN;
		case ESP_NULL_AUTH_AES_GMAC:
			return AES_GMAC_KEY_DEF_LEN;
		/* private use */
		case ESP_SERPENT:
			return SERPENT_KEY_DEF_LEN;
		case ESP_TWOFISH:
			return TWOFISH_KEY_DEF_LEN;
		default:
			return 0;
		}

	default:
		bad_case(ksproto);
	}
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
