/*
 * Algorithm info parsing and creation functions
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 *
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2015-2017 Andrew Cagney
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
#include <stdint.h>
#include <limits.h>

#include "constants.h"  /* some how sucks in u_int8_t for pfkeyv2.h */
#include "libreswan/pfkeyv2.h"
#include "lswalloc.h"
#include "lswlog.h"
#include "alg_info.h"
#include "alg_byname.h"
#include "kernel_alg.h"
#include "lswfips.h"

#include "ike_alg.h"
#include "ike_alg_null.h"
#include "ike_alg_aes.h"
#include "ike_alg_sha1.h"

/*
 * Add ESP alg info _with_ logic (policy):
 */
static bool esp_proposal_ok(const struct proposal_info *proposal,
			    char *err_buf, size_t err_buf_len)
{
	if (!DBGP(IMPAIR_ALLOW_NULL_NULL) &&
	    !proposal_aead_none_ok(proposal, err_buf, err_buf_len)) {
		return false;
	}

	passert(proposal->encrypt != NULL);
	passert(proposal->prf == NULL);
	passert(proposal->integ != NULL);
	return true;
}

static const struct ike_alg *default_esp_encrypt[] = {
	&ike_alg_encrypt_aes_cbc.common,
	NULL,
};

static const struct ike_alg *default_esp_integ[] = {
	&ike_alg_integ_sha1.common,
	NULL,
};

const struct proposal_defaults esp_defaults = {
	.encrypt = default_esp_encrypt,
	.integ = default_esp_integ,
};

const struct parser_protocol esp_parser_protocol = {
	.name = "ESP",
	.ikev1_alg_id = IKEv1_ESP_ID,
	.protoid = PROTO_IPSEC_ESP,
	.ikev1_defaults = &esp_defaults,
	.ikev2_defaults = &esp_defaults,
	.proposal_ok = esp_proposal_ok,
	.encrypt_alg_byname = encrypt_alg_byname,
	.integ_alg_byname = integ_alg_byname,
	.dh_alg_byname = dh_alg_byname,
};

static bool ah_proposal_ok(const struct proposal_info *proposal,
			   char *err_buf, size_t err_buf_len)
{
	passert(proposal->encrypt == NULL);
	passert(proposal->prf == NULL);
	passert(proposal->integ != NULL);

	if (DBGP(IMPAIR_ALLOW_NULL_NULL))
		return true;

	/* ah=null is invalid */
	if (proposal->integ == &ike_alg_integ_none) {
		snprintf(err_buf, err_buf_len,
			 "AH cannot have 'none' as the integrity algorithm");
		return false;
	}
	return true;
}

static const struct ike_alg *default_ah_integ[] = {
	&ike_alg_integ_sha1.common,
	NULL,
};

const struct proposal_defaults ah_defaults = {
	.integ = default_ah_integ,
};

const struct parser_protocol ah_parser_protocol = {
	.name = "AH",
	.ikev1_alg_id = IKEv1_ESP_ID,
	.protoid = PROTO_IPSEC_AH,
	.ikev1_defaults = &ah_defaults,
	.ikev2_defaults = &ah_defaults,
	.proposal_ok = ah_proposal_ok,
	.integ_alg_byname = integ_alg_byname,
	.dh_alg_byname = dh_alg_byname,
};

/*
 * Pluto only accepts one ESP/AH DH algorithm and it must come at the
 * end and be separated with a ';'.  Enforce this (even though the
 * parer is far more forgiving).
 */

static struct alg_info_esp *alg_info_discover_pfsgroup_hack(struct alg_info_esp *aie,
							    const char *alg_str,
							    char *err_buf, size_t err_buf_len)
{
	if (aie == NULL) {
		return NULL;
	}

	/*
	 * Find the first and last proposal, if present (never know,
	 * there could be no algorithms).
	 */
	struct proposal_info *first = NULL;
	FOR_EACH_ESP_INFO(aie, esp_info) {
		first = esp_info;
		break;
	}
	struct proposal_info *last = NULL;
	FOR_EACH_ESP_INFO(aie, esp_info) {
		last = esp_info;
	}
	if (last == NULL) {
		/* let caller deal with this. */
		return aie;
	}

	/*
	 * Make certain that either all algorithms have the same DH or
	 * all are NULL (with the exception of the last).
	 *
	 * For instance, aes-modp1024,aes-modp2048 isn't allowed
	 * because pluto assumes only one PFS group.
	 */
	FOR_EACH_ESP_INFO(aie, esp_info) {
		if (esp_info == last) {
			continue;
		}
		if (first->dh != esp_info->dh) {
			snprintf(err_buf, err_buf_len,
				 "%s DH algorithm '%s' must be specified last",
				 esp_info->protocol->name,
				 (first->dh != NULL ? first->dh : esp_info->dh)->common.fqn);
			alg_info_free(&aie->ai);
			return NULL;
		}
		if (esp_info->dh != NULL && last->dh == NULL) {
			snprintf(err_buf, err_buf_len,
				 "%s DH algorithm '%s' must be specified last",
				 esp_info->protocol->name,
				 esp_info->dh->common.fqn);
			alg_info_free(&aie->ai);
			return NULL;
		}
		if (esp_info->dh != NULL && esp_info->dh != last->dh) {
			snprintf(err_buf, err_buf_len,
				 "%s DH algorithm must be specified once",
				 esp_info->protocol->name);
			alg_info_free(&aie->ai);
			return NULL;
		}
	}

	/*
	 * Restrict the DH separator character to ';' and the last
	 * proposal.
	 *
	 * While the parser allows both "...;modp1024" and
	 * "...-modp1024", pluto only admits to the former - so that
	 * it stands out as something not part of the individual
	 * proposals.
	 *
	 * Why? Because this is how it worked in the past.  Presumably
	 * ';' makes it clear that it applies to all algorithms?
	 *
	 * Conversely, if all proposals include DH don't allow any
	 * ';'.
	 */
	if (last->dh != NULL) {
		char *last_dash = strrchr(alg_str, '-');
		char *last_semi = strrchr(alg_str, ';');
		char *last_comma = strrchr(alg_str, ',');
		if (first != last && first->dh == NULL) {
			/* reject missing ';'. */
			if (last_semi == NULL) {
				snprintf(err_buf, err_buf_len,
					 "%s DH algorithm '%s' must be separated using a ';'",
					 last->protocol->name,
					 last->dh->common.fqn);
				alg_info_free(&aie->ai);
				return NULL;
			}
			/* reject xxx;DH,yyy */
			if (last_comma != NULL && last_semi < last_comma) {
				snprintf(err_buf, err_buf_len,
					 "%s DH algorithm must appear after last proposal",
					 last->protocol->name);
				alg_info_free(&aie->ai);
				return NULL;
			}
			/* reject yyy,xxx-DH */
			if (last_dash != NULL && last_semi < last_dash) {
				snprintf(err_buf, err_buf_len,
					 "%s DH algorithm must be at end of proposal",
					 last->protocol->name);
				alg_info_free(&aie->ai);
				return NULL;
			}
		} else if (first != last && first->dh != NULL) {
			/* reject ...;... */
			if (last_semi != NULL) {
				snprintf(err_buf, err_buf_len,
					 "%s DH algorithm must appear once after last proposal",
					 last->protocol->name);
				alg_info_free(&aie->ai);
				return NULL;
			}
		}
	}

	/*
	 * Now go through and force all DHs to a consistent value.
	 *
	 * This way, something printing an individual proposal will
	 * include the common DH; and for IKEv2 it can just pick up
	 * that DH.
	 */
	FOR_EACH_ESP_INFO(aie, esp_info) {
		esp_info->dh = last->dh;
	}

	/*
	 * Use last's DH for PFS.  Could be NULL but that is ok.
	 *
	 * Since DH is set uniformly, could use first.DH instead.
	 */
	aie->esp_pfsgroup = last->dh;
	return aie;
}

/*
 * ??? why is this called _ah_ when almost everything refers to esp?
 * XXX: Because it is parsing an "ah" line which requires a different
 * parser configuration - encryption isn't allowed.
 *
 * ??? the only difference between this and alg_info_esp is in two
 * parameters to alg_info_parse_str.  XXX: Things are down to just the
 * last parameter being different - but that is critical as it
 * determines what is allowed.
 *
 * XXX: On the other hand, since "struct ike_info" and "struct
 * esp_info" are effectively the same, they can be merged.  Doing
 * that, would eliminate the AH using ESP confusion.
 */

/* This function is tested in testing/algparse/algparse.c */
struct alg_info_esp *alg_info_esp_create_from_str(const struct parser_policy *policy,
						  const char *alg_str,
						  char *err_buf, size_t err_buf_len)
{
	/*
	 * alg_info storage should be sized dynamically
	 * but this may require two passes to know
	 * transform count in advance.
	 */
	struct alg_info_esp *alg_info_esp = alloc_thing(struct alg_info_esp,
							"alg_info_esp");
	/*
	 * These calls can free alg_info_esp!
	 */
	alg_info_esp = (struct alg_info_esp *)
		alg_info_parse_str(policy,
				   &alg_info_esp->ai,
				   alg_str,
				   err_buf, err_buf_len,
				   &esp_parser_protocol);
	alg_info_esp = alg_info_discover_pfsgroup_hack(alg_info_esp, alg_str,
						       err_buf, err_buf_len);
	return alg_info_esp;
}

/* This function is tested in testing/algparse/algparse.c */
struct alg_info_esp *alg_info_ah_create_from_str(const struct parser_policy *policy,
						 const char *alg_str,
						 char *err_buf, size_t err_buf_len)
{
	/*
	 * alg_info storage should be sized dynamically
	 * but this may require two passes to know
	 * transform count in advance.
	 */
	struct alg_info_esp *alg_info_ah = alloc_thing(struct alg_info_esp, "alg_info_ah");

	/*
	 * These calls can free ALG_INFO_AH.
	 */
	alg_info_ah = (struct alg_info_esp *)
		alg_info_parse_str(policy,
				   &alg_info_ah->ai,
				   alg_str,
				   err_buf, err_buf_len,
				   &ah_parser_protocol);
	alg_info_ah = alg_info_discover_pfsgroup_hack(alg_info_ah, alg_str,
						      err_buf, err_buf_len);
	return alg_info_ah;
}
