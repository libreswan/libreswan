/*
 * Kernel runtime algorithm handling interface definitions
 * Originally by: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 * Reworked into openswan 2.x by Michael Richardson <mcr@xelerance.com>
 *
 * (C)opyright 2012 Paul Wouters <pwouters@redhat.com>
 * (C)opyright 2012-2013 Paul Wouters <paul@libreswan.org>
 * (C)opyright 2012-2013 D. Hugh Redelmeier
 * Copyright (C) 2015-2017 Andrew Cagney <cagney@gnu.com>
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

#include <sys/types.h>
#include <stdlib.h>
#include <libreswan.h>
#include <libreswan/pfkeyv2.h>
#include <libreswan/passert.h>

#include "sysdep.h"
#include "constants.h"
#include "log.h"
#include "lswalloc.h"
#include "defs.h"
#include "id.h"
#include "connections.h"
#include "state.h"
#include "kernel_alg.h"
#include "alg_info.h"
#include "ike_alg.h"
#include "plutoalg.h"
#include "crypto.h"
#include "spdb.h"
#include "db_ops.h"
#include "log.h"
#include "whack.h"

static bool kernel_alg_db_add(struct db_context *db_ctx,
			      const struct proposal_info *esp_info,
			      lset_t policy, bool logit)
{
	int ealg_i = SADB_EALG_NONE;

	if (policy & POLICY_ENCRYPT) {
		ealg_i = esp_info->ikev1esp_transid;
		if (!ESP_EALG_PRESENT(ealg_i)) {
			if (logit) {
				loglog(RC_LOG_SERIOUS,
				       "requested kernel enc ealg_id=%d not present",
				       ealg_i);
			} else {
				DBG_log("requested kernel enc ealg_id=%d not present",
					ealg_i);
			}
			return FALSE;
		}
	}

	int aalg_i = alg_info_esp_aa2sadb(esp_info->ikev1esp_auth);

	if (!ESP_AALG_PRESENT(aalg_i)) {
		DBG_log("kernel_alg_db_add() kernel auth aalg_id=%d not present",
			aalg_i);
		return FALSE;
	}

	if (policy & POLICY_ENCRYPT) {
		/*open new transformation */
		db_trans_add(db_ctx, ealg_i);

		/* add ESP auth attr (if present) */
		if (esp_info->ikev1esp_auth != AUTH_ALGORITHM_NONE) {
			db_attr_add_values(db_ctx,
					   AUTH_ALGORITHM,
					   esp_info->ikev1esp_auth);
		}

		/* add keylength if specified in esp= string */
		if (esp_info->enckeylen != 0) {
				db_attr_add_values(db_ctx,
						   KEY_LENGTH,
						   esp_info->enckeylen);
		} else {
			/* no key length - if required add default here and add another max entry */
			int def_ks = crypto_req_keysize(CRK_ESPorAH, ealg_i);

			if (def_ks != 0) {
				int max_ks = BITS_PER_BYTE *
					kernel_alg_esp_enc_max_keylen(ealg_i);

				db_attr_add_values(db_ctx,
					KEY_LENGTH,
					def_ks);
				/* add this trans again with max key size */
				if (def_ks != max_ks) {
					db_trans_add(db_ctx, ealg_i);
					if (esp_info->ikev1esp_auth != AUTH_ALGORITHM_NONE) {
						db_attr_add_values(db_ctx,
							AUTH_ALGORITHM,
							esp_info->ikev1esp_auth);
					}
					db_attr_add_values(db_ctx,
						KEY_LENGTH,
						max_ks);
				}
			}
		}
	} else if (policy & POLICY_AUTHENTICATE) {
		/* open new transformation */
		db_trans_add(db_ctx, aalg_i);

		/* add ESP auth attr */
		db_attr_add_values(db_ctx,
				   AUTH_ALGORITHM, esp_info->ikev1esp_auth);
	}

	return TRUE;
}

/*
 *	Create proposal with runtime kernel algos, merging
 *	with passed proposal if not NULL
 *
 * ??? is this still true?  Certainly not free(3):
 *	for now this function does free() previous returned
 *	malloced pointer (this quirk allows easier spdb.c change)
 */
static struct db_context *kernel_alg_db_new(struct alg_info_esp *alg_info,
				     lset_t policy, bool logit)
{
	unsigned int trans_cnt = 0;
	int protoid = PROTO_RESERVED;

	if (policy & POLICY_ENCRYPT) {
		trans_cnt = (esp_ealg_num * esp_aalg_num);
		protoid = PROTO_IPSEC_ESP;
	} else if (policy & POLICY_AUTHENTICATE) {
		trans_cnt = esp_aalg_num;
		protoid = PROTO_IPSEC_AH;
	}

	DBG(DBG_EMITTING, DBG_log("kernel_alg_db_new() initial trans_cnt=%d",
				  trans_cnt));

	/*	pass aprox. number of transforms and attributes */
	struct db_context *ctx_new = db_prop_new(protoid, trans_cnt, trans_cnt * 2);

	/*
	 *      Loop: for each element (struct esp_info) of
	 *      alg_info, if kernel support is present then
	 *      build the transform (and attrs)
	 *
	 *      if NULL alg_info, propose everything ...
	 */

	bool success = TRUE;
	if (alg_info != NULL) {
		FOR_EACH_ESP_INFO(alg_info, esp_info) {
			if (!kernel_alg_db_add(ctx_new,
					esp_info,
					policy, logit))
				success = FALSE;	/* ??? should we break? */
		}
	} else {
		int ealg_i;

		ESP_EALG_FOR_EACH_DOWN(ealg_i) {
			struct proposal_info tmp_esp_info;
			int aalg_i;

			tmp_esp_info.ikev1esp_transid = ealg_i;
			tmp_esp_info.enckeylen = 0;
			ESP_AALG_FOR_EACH(aalg_i) {
				tmp_esp_info.ikev1esp_auth =
					alg_info_esp_sadb2aa(aalg_i);
				kernel_alg_db_add(ctx_new, &tmp_esp_info,
						  policy, FALSE);
			}
		}
	}

	if (!success) {
		/* NO algorithms were found. oops */
		db_destroy(ctx_new);
		return NULL;
	}

	struct db_prop  *prop = db_prop_get(ctx_new);

	DBG(DBG_CONTROL | DBG_EMITTING,
		DBG_log("kernel_alg_db_new() will return p_new->protoid=%d, p_new->trans_cnt=%d",
			prop->protoid,
			prop->trans_cnt));

	unsigned int tn = 0;
	struct db_trans *t;
	for (t = prop->trans, tn = 0;
	     t != NULL && t[tn].transid != 0 && tn < prop->trans_cnt;
	     tn++) {
		DBG(DBG_CONTROL | DBG_EMITTING,
		    DBG_log("kernel_alg_db_new()     trans[%d]: transid=%d, attr_cnt=%d, attrs[0].type=%d, attrs[0].val=%d",
			    tn,
			    t[tn].transid, t[tn].attr_cnt,
			    t[tn].attrs ? t[tn].attrs[0].type.ipsec : 255,
			    t[tn].attrs ? t[tn].attrs[0].val : 255
			    ));
	}
	prop->trans_cnt = tn;

	return ctx_new;
}

bool ikev1_verify_esp(int ealg, unsigned int key_len, int aalg,
			const struct alg_info_esp *alg_info)
{
	if (alg_info == NULL)
		return TRUE;

	if (key_len == 0)
		key_len = crypto_req_keysize(CRK_ESPorAH, ealg);

	FOR_EACH_ESP_INFO(alg_info, esp_info) {
		if (esp_info->ikev1esp_transid == ealg &&
		    (esp_info->enckeylen == 0 ||
		     key_len == 0 ||
		     esp_info->enckeylen == key_len) &&
		    esp_info->ikev1esp_auth == aalg) {
			return TRUE;
		}
	}

	libreswan_log("ESP IPsec Transform [%s (%d), %s] refused",
		enum_name(&esp_transformid_names, ealg),
		key_len, enum_name(&auth_alg_names, aalg));
	return FALSE;
}

bool ikev1_verify_ah(int aalg, const struct alg_info_esp *alg_info)
{
	if (alg_info == NULL)
		return TRUE;

	FOR_EACH_ESP_INFO(alg_info, esp_info) {	/* really AH */
		if (esp_info->ikev1esp_auth == aalg)
			return TRUE;
	}

	libreswan_log("AH IPsec Transform [%s] refused",
		enum_name(&ah_transformid_names, aalg));
	return FALSE;
}

void kernel_alg_show_status(void)
{
	unsigned sadb_id;

	whack_log(RC_COMMENT, "ESP algorithms supported:");
	whack_log(RC_COMMENT, " "); /* spacer */

	ESP_EALG_FOR_EACH(sadb_id) {
		const struct sadb_alg *alg_p = &esp_ealg[sadb_id];

		whack_log(RC_COMMENT,
			"algorithm ESP encrypt: id=%d, name=%s, ivlen=%d, keysizemin=%d, keysizemax=%d",
			sadb_id,
			enum_name(&esp_transformid_names, sadb_id),
			alg_p->sadb_alg_ivlen,
			alg_p->sadb_alg_minbits,
			alg_p->sadb_alg_maxbits);
	}

	ESP_AALG_FOR_EACH(sadb_id) {
		unsigned id = alg_info_esp_sadb2aa(sadb_id);
		const struct sadb_alg *alg_p = &esp_aalg[sadb_id];

		whack_log(RC_COMMENT,
			"algorithm AH/ESP auth: id=%d, name=%s, keysizemin=%d, keysizemax=%d",
			id,
			enum_name(&auth_alg_names, id),
			alg_p->sadb_alg_minbits,
			alg_p->sadb_alg_maxbits);
	}

	whack_log(RC_COMMENT, " "); /* spacer */
}

void kernel_alg_show_connection(const struct connection *c, const char *instance)
{
	const char *satype;

	switch (c->policy & (POLICY_ENCRYPT | POLICY_AUTHENTICATE)) {
	default:	/* shut up gcc */
	case 0u:
		satype = "noESPnoAH";
		break;

	case POLICY_ENCRYPT:
		satype = "ESP";
		break;

	case POLICY_AUTHENTICATE:
		satype = "AH";
		break;

	case POLICY_ENCRYPT | POLICY_AUTHENTICATE:
		satype = "ESP+AH";
		break;
	}

	const char *pfsbuf;
	struct esb_buf esb;

	if (c->policy & POLICY_PFS) {
		/* ??? 0 isn't a legitimate value for esp_pfsgroup */
		if (c->alg_info_esp != NULL && c->alg_info_esp->esp_pfsgroup != 0) {
			pfsbuf = enum_show_shortb(&oakley_group_names,
						  c->alg_info_esp->esp_pfsgroup->group,
						  &esb);
		} else {
			pfsbuf = "<Phase1>";
		}
	} else {
		pfsbuf = "<N/A>";
	}

	if (c->alg_info_esp != NULL) {
		char buf[1024];

		alg_info_esp_snprint(buf, sizeof(buf),
				     c->alg_info_esp);
		whack_log(RC_COMMENT,
			  "\"%s\"%s:   %s algorithms wanted: %s",
			  c->name,
			  instance, satype,
			  buf);

		alg_info_snprint_phase2(buf, sizeof(buf), c->alg_info_esp);
		whack_log(RC_COMMENT,
			  "\"%s\"%s:   %s algorithms loaded: %s",
			  c->name,
			  instance, satype,
			  buf);
	}

	const struct state *st = state_with_serialno(c->newest_ipsec_sa);

	if (st != NULL && st->st_esp.present) {
		whack_log(RC_COMMENT,
			  "\"%s\"%s:   %s algorithm newest: %s_%03d-%s; pfsgroup=%s",
			  c->name,
			  instance, satype,
			  enum_short_name(&esp_transformid_names,
				    st->st_esp.attrs.transattrs.encrypt),
			  st->st_esp.attrs.transattrs.enckeylen,
			  enum_short_name(&auth_alg_names,
				    st->st_esp.attrs.transattrs.integ_hash),
			  pfsbuf);
	}

	if (st != NULL && st->st_ah.present) {
		whack_log(RC_COMMENT,
			  "\"%s\"%s:   %s algorithm newest: %s; pfsgroup=%s",
			  c->name,
			  instance, satype,
			  enum_short_name(&auth_alg_names,
				    st->st_esp.attrs.transattrs.integ_hash),
			  pfsbuf);
	}
}

struct db_sa *kernel_alg_makedb(lset_t policy, struct alg_info_esp *ei,
				bool logit)
{
	if (ei == NULL) {
		struct db_sa *sadb;
		lset_t pm = POLICY_ENCRYPT | POLICY_AUTHENTICATE;

#if 0
		if (can_do_IPcomp)
			pm |= POLICY_COMPRESS;
#endif

		sadb = &ipsec_sadb[(policy & pm) >> POLICY_IPSEC_SHIFT];

		/* make copy, to keep from freeing the static policies */
		sadb = sa_copy_sa(sadb);
		sadb->parentSA = FALSE;

		DBG(DBG_CONTROL,
		    DBG_log("empty esp_info, returning defaults"));
		return sadb;
	}

	struct db_context *dbnew = kernel_alg_db_new(ei, policy, logit);

	if (dbnew == NULL) {
		libreswan_log("failed to translate esp_info to proposal, returning empty");
		return NULL;
	}

	struct db_prop *p = db_prop_get(dbnew);

	if (p == NULL) {
		libreswan_log("failed to get proposal from context, returning empty");
		db_destroy(dbnew);
		return NULL;
	}

	struct db_prop_conj pc = { .prop_cnt = 1, .props = p };

	struct db_sa t = { .prop_conj_cnt = 1, .prop_conjs = &pc };

	/* make a fresh copy */
	struct db_sa *n = sa_copy_sa(&t);
	n->parentSA = FALSE;

	db_destroy(dbnew);

	DBG(DBG_CONTROL,
	    DBG_log("returning new proposal from esp_info"));
	return n;
}
