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
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
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
#include "defs.h"
#include "log.h"
#include "lswalloc.h"
#include "id.h"
#include "connections.h"
#include "state.h"
#include "kernel_alg.h"
#include "alg_info.h"
#include "ike_alg.h"
#include "ike_alg_integ.h"
#include "ike_alg_encrypt.h"
#include "plutoalg.h"
#include "crypto.h"
#include "spdb.h"
#include "db_ops.h"
#include "log.h"
#include "whack.h"
#include "ikev1.h"	/* for ikev1_quick_dh() */

static bool kernel_alg_db_add(struct db_context *db_ctx,
			      const struct proposal_info *esp_info,
			      lset_t policy, bool logit)
{
	int ealg_i = SADB_EALG_NONE;

	if (policy & POLICY_ENCRYPT) {
		ealg_i = esp_info->encrypt->common.id[IKEv1_ESP_ID];
		/* already checked by the parser? */
		if (!kernel_alg_encrypt_ok(esp_info->encrypt)) {
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

	int aalg_i = esp_info->integ->integ_ikev1_ah_transform;

	/* already checked by the parser? */
	if (!kernel_alg_integ_ok(esp_info->integ)) {
		DBG_log("kernel_alg_db_add() kernel auth aalg_id=%d not present",
			aalg_i);
		return FALSE;
	}

	if (policy & POLICY_ENCRYPT) {
		/*open new transformation */
		db_trans_add(db_ctx, ealg_i);

		/* add ESP auth attr (if present) */
		if (esp_info->integ != &ike_alg_integ_none) {
			db_attr_add_values(db_ctx,
					   AUTH_ALGORITHM,
					   esp_info->integ->common.id[IKEv1_ESP_ID]);
		}

		/* add keylength if specified in esp= string */
		if (esp_info->enckeylen != 0) {
				db_attr_add_values(db_ctx,
						   KEY_LENGTH,
						   esp_info->enckeylen);
		} else {
			/* no key length - if required add default here and add another max entry */
			int def_ks = (esp_info->encrypt->keylen_omitted ? 0
				      : esp_info->encrypt->keydeflen);

			if (def_ks != 0) {
				db_attr_add_values(db_ctx, KEY_LENGTH, def_ks);
				/* add this trans again with max key size */
				int max_ks = encrypt_max_key_bit_length(esp_info->encrypt);
				if (def_ks != max_ks) {
					db_trans_add(db_ctx, ealg_i);
					if (esp_info->integ != &ike_alg_integ_none) {
						db_attr_add_values(db_ctx,
							AUTH_ALGORITHM,
							esp_info->integ->common.id[IKEv1_ESP_ID]);
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
				   AUTH_ALGORITHM, esp_info->integ->common.id[IKEv1_ESP_ID]);
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
		trans_cnt = kernel_alg_encrypt_count() * kernel_alg_integ_count();
		protoid = PROTO_IPSEC_ESP;
	} else if (policy & POLICY_AUTHENTICATE) {
		trans_cnt = kernel_alg_integ_count();
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
		FOR_EACH_ESP_INFO(alg_info, proposal) {
			LSWDBGP(DBG_CONTROL | DBG_EMITTING, buf) {
				lswlogs(buf, "adding proposal: ");
				lswlog_proposal_info(buf, proposal);
			}
			if (!kernel_alg_db_add(ctx_new, proposal,
					       policy, logit))
				success = FALSE;	/* ??? should we break? */
		}
	} else {
		PEXPECT_LOG("%s", "alg_info should be non-NULL");
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

void kernel_alg_show_status(void)
{
	whack_log(RC_COMMENT, "Kernel algorithms supported:");
	whack_log(RC_COMMENT, " "); /* spacer */

	for (const struct encrypt_desc **alg_p = next_kernel_encrypt_desc(NULL);
	     alg_p != NULL; alg_p = next_kernel_encrypt_desc(alg_p)) {
		const struct encrypt_desc *alg = *alg_p;
		whack_log(RC_COMMENT,
			  "algorithm ESP encrypt: name=%s, keysizemin=%d, keysizemax=%d",
			  alg->common.fqn,
			  encrypt_min_key_bit_length(alg),
			  encrypt_max_key_bit_length(alg));
	}

	for (const struct integ_desc **alg_p = next_kernel_integ_desc(NULL);
	     alg_p != NULL; alg_p = next_kernel_integ_desc(alg_p)) {
		const struct integ_desc *alg = *alg_p;
		whack_log(RC_COMMENT,
			  "algorithm AH/ESP auth: name=%s, key-length=%zu",
			  alg->common.fqn,
			  alg->integ_keymat_size * BITS_PER_BYTE);
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

	if (c->policy & POLICY_PFS) {
		/*
		 * Get the DH algorthm specified for the child (ESP or AH).
		 *
		 * If this is NULL and PFS is required then callers fall back to using
		 * the parent's DH algorithm.
		 */
		const struct oakley_group_desc *dh = ikev1_quick_pfs(c->alg_info_esp);
		if (dh != NULL) {
			pfsbuf = dh->common.fqn;
		} else {
			pfsbuf = "<Phase1>";
		}
	} else {
		pfsbuf = "<N/A>";
	}

	if (c->alg_info_esp != NULL) {
		LSWLOG_WHACK(RC_COMMENT, buf) {
			/*
			 * If DH (PFS) was specified in the esp= or
			 * ah= line then the below will display it
			 * in-line for each crypto suite.  For
			 * instance:
			 *
			 *    AES_GCM-NULL-DH22
			 *
			 * This output can be fed straight back into
			 * the parser.  This is not true of the old
			 * style output:
			 *
			 *    AES_GCM-NULL; pfsgroup=DH22
			 *
			 * The real PFS is displayed in the 'algorithm
			 * newest' line further down.
			 */
			lswlogf(buf, "\"%s\"%s:   %s algorithms: ",
				c->name, instance, satype);
			lswlog_alg_info(buf, &c->alg_info_esp->ai);
		}
	}

	const struct state *st = state_with_serialno(c->newest_ipsec_sa);

	if (st != NULL && st->st_esp.present) {
		whack_log(RC_COMMENT,
			  "\"%s\"%s:   %s algorithm newest: %s_%03d-%s; pfsgroup=%s",
			  c->name,
			  instance, satype,
			  st->st_esp.attrs.transattrs.ta_encrypt->common.fqn,
			  st->st_esp.attrs.transattrs.enckeylen,
			  st->st_esp.attrs.transattrs.ta_integ->common.fqn,
			  pfsbuf);
	}

	if (st != NULL && st->st_ah.present) {
		whack_log(RC_COMMENT,
			  "\"%s\"%s:   %s algorithm newest: %s; pfsgroup=%s",
			  c->name,
			  instance, satype,
			  st->st_ah.attrs.transattrs.ta_integ->common.fqn,
			  pfsbuf);
	}
}

struct db_sa *kernel_alg_makedb(lset_t policy, struct alg_info_esp *ei,
				bool logit)
{
	if (ei == NULL) {
		struct db_sa *sadb;
		lset_t pm = POLICY_ENCRYPT | POLICY_AUTHENTICATE;

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
