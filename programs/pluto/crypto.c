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
#include "crypto.h"
#include "alg_info.h"
#include "ike_alg.h"
#include "test_buffer.h"
#include "connections.h"

#include "ike_alg_camellia.h"
#include "ike_alg_aes.h"

#include "ctr_test_vectors.h"
#include "cbc_test_vectors.h"
#include "gcm_test_vectors.h"

#include "kernel_alg.h"

void init_crypto(void)
{
	ike_alg_init();

	passert(test_cbc_vectors(&ike_alg_encrypt_camellia_cbc,
				 camellia_cbc_tests));
	passert(test_gcm_vectors(&ike_alg_encrypt_aes_gcm_16,
				 aes_gcm_tests));
	passert(test_ctr_vectors(&ike_alg_encrypt_aes_ctr,
				 aes_ctr_tests));
	passert(test_cbc_vectors(&ike_alg_encrypt_aes_cbc,
				 aes_cbc_tests));

	/*
	 * Cross check IKE_ALG with legacy code.
	 *
	 * Showing that IKE_ALG provides equivalent information is the
	 * first step to deleting the legacy code.
	 */

	/* alg_info_esp2sadb() */
	for (const struct integ_desc **integp = next_integ_desc(NULL);
	     integp != NULL; integp = next_integ_desc(integp)) {
		const struct integ_desc *integ = *integp;
		if (integ->integ_ikev1_ah_id != 0) {
			passert_ike_alg(&integ->common,
					alg_info_esp_aa2sadb(integ->common.id[IKEv1_ESP_ID])
					== integ->integ_ikev1_ah_id);
		}
	}

	/* crypto_req_keysize() */
	for (const struct encrypt_desc **encryptp = next_encrypt_desc(NULL);
	     encryptp != NULL; encryptp = next_encrypt_desc(encryptp)) {
		const struct encrypt_desc *encrypt = *encryptp;
		if (encrypt->common.id[IKEv1_ESP_ID] > 0) {
			if (encrypt->keylen_omitted) {
				passert_ike_alg(&encrypt->common,
						crypto_req_keysize(CRK_ESPorAH,
								   encrypt->common.id[IKEv1_ESP_ID])
						== 0);
			} else {
				passert_ike_alg(&encrypt->common,
						crypto_req_keysize(CRK_ESPorAH,
								   encrypt->common.id[IKEv1_ESP_ID])
						== encrypt->keydeflen);
			}
		}
	}

}

/*
 * Return a required oakley or ipsec keysize or 0 if not required.
 * The first parameter uses 0 for ESP, and anything above that for
 * IKE major version
 */
unsigned crypto_req_keysize(enum crk_proto ksproto, int algo)
{
	switch (ksproto) {

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
			return CAMELLIA_KEY_DEF_LEN;
		case ESP_CAMELLIA_CTR:
			return CAMELLIA_CTR_KEY_DEF_LEN;
		case ESP_NULL_AUTH_AES_GMAC:
			return AES_GMAC_KEY_DEF_LEN;
		case ESP_3DES:
			/* 0 means send no keylen */
			return 0;
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
	if ((policy & POLICY_PFS) && c->alg_info_esp != NULL)
		/* might be NULL. */
		return c->alg_info_esp->esp_pfsgroup;
	return NULL;
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
		struct esb_buf encbuf, prfbuf, integbuf;

		if (!st->st_ikev2) {
			/* IKEv1 */
			whack_log(RC_COMMENT,
			  "\"%s\"%s:   IKE algorithm newest: %s_%03d-%s-%s",
			  c->name,
			  instance,
			  enum_show_shortb(&oakley_enc_names, st->st_oakley.encrypt, &encbuf),
			  /* st->st_oakley.encrypter->keydeflen, */
			  st->st_oakley.enckeylen,
			  enum_show_shortb(&oakley_hash_names,
					   st->st_oakley.prf->common.ikev1_oakley_id,
					   &prfbuf),
				  st->st_oakley.group->common.name);
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
			  enum_showb(&ikev2_trans_type_prf_names,
				     st->st_oakley.prf->common.id[IKEv2_ALG_ID],
				     &prfbuf),
				  st->st_oakley.group->common.name);
		}
	}
}

/*
 * Show registered IKE algorithms
 */
void ike_alg_show_status(void)
{
	whack_log(RC_COMMENT, "IKE algorithms supported:");
	whack_log(RC_COMMENT, " "); /* spacer */

	for (const struct encrypt_desc **algp = next_encrypt_desc(NULL);
	     algp != NULL; algp = next_encrypt_desc(algp)) {
		const struct encrypt_desc *alg = (*algp);
		if (ike_alg_is_ike(&(alg)->common)) {
			struct esb_buf v1namebuf, v2namebuf;
			passert(alg->common.ikev1_oakley_id != 0 || alg->common.id[IKEv2_ALG_ID] != 0);
			whack_log(RC_COMMENT,
				  "algorithm IKE encrypt: v1id=%d, v1name=%s, v2id=%d, v2name=%s, blocksize=%zu, keydeflen=%u",
				  alg->common.ikev1_oakley_id,
				  enum_showb(&oakley_enc_names,
					     alg->common.ikev1_oakley_id,
					     &v1namebuf),
				  alg->common.id[IKEv2_ALG_ID],
				  enum_showb(&ikev2_trans_type_encr_names,
					     alg->common.id[IKEv2_ALG_ID],
					     &v2namebuf),
				  alg->enc_blocksize,
				  alg->keydeflen);
		}
	}

	for (const struct prf_desc **algp = next_prf_desc(NULL);
	     algp != NULL; algp = next_prf_desc(algp)) {
		const struct prf_desc *alg = (*algp);
		if (ike_alg_is_ike(&(alg)->common)) {
			whack_log(RC_COMMENT,
				  "algorithm IKE hash: id=%d, name=%s, hashlen=%zu",
				  alg->common.ikev1_oakley_id,
				  enum_name(&oakley_hash_names, alg->common.ikev1_oakley_id),
				  alg->prf_output_size);
		}
	}

	for (const struct oakley_group_desc **gdescp = next_oakley_group(NULL);
	     gdescp != NULL; gdescp = next_oakley_group(gdescp)) {
		const struct oakley_group_desc *gdesc = *gdescp;
		whack_log(RC_COMMENT,
			  "algorithm IKE DH Key Exchange: name=%s, bits=%d",
			  gdesc->common.name,
			  (int)gdesc->bytes * BITS_PER_BYTE);
	}

	whack_log(RC_COMMENT, " "); /* spacer */
}
