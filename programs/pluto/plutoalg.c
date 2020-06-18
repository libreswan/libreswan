/*
 * Kernel runtime algorithm handling interface definitions
 * Originally by: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 * Reworked into openswan 2.x by Michael Richardson <mcr@xelerance.com>
 *
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012-2013 D. Hugh Redelmeier
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

#include "passert.h"
#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "log.h"
#include "lswalloc.h"
#include "id.h"
#include "connections.h"
#include "state.h"
#include "kernel_alg.h"
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
			      const struct proposal *proposal,
			      lset_t policy, bool logit)
{
	int ealg_i = SADB_EALG_NONE;

	struct v1_proposal algs = v1_proposal(proposal);
	if (policy & POLICY_ENCRYPT) {
		ealg_i = algs.encrypt->common.id[IKEv1_ESP_ID];
		/* already checked by the parser? */
		if (!kernel_alg_encrypt_ok(algs.encrypt)) {
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

	int aalg_i = algs.integ->integ_ikev1_ah_transform;

	/* already checked by the parser? */
	if (!kernel_alg_integ_ok(algs.integ)) {
		DBG_log("kernel_alg_db_add() kernel auth aalg_id=%d not present",
			aalg_i);
		return FALSE;
	}

	if (policy & POLICY_ENCRYPT) {
		/*open new transformation */
		db_trans_add(db_ctx, ealg_i);

		/* add ESP auth attr (if present) */
		if (algs.integ != &ike_alg_integ_none) {
			db_attr_add_values(db_ctx,
					   AUTH_ALGORITHM,
					   algs.integ->common.id[IKEv1_ESP_ID]);
		}

		/* add keylength if specified in esp= string */
		if (algs.enckeylen != 0) {
			db_attr_add_values(db_ctx,
					   KEY_LENGTH,
					   algs.enckeylen);
		} else {
			/* no key length - if required add default here and add another max entry */
			int def_ks = (algs.encrypt->keylen_omitted ? 0
				      : algs.encrypt->keydeflen);

			if (def_ks != 0) {
				db_attr_add_values(db_ctx, KEY_LENGTH, def_ks);
				/* add this trans again with max key size */
				int max_ks = encrypt_max_key_bit_length(algs.encrypt);
				if (def_ks != max_ks) {
					db_trans_add(db_ctx, ealg_i);
					if (algs.integ != &ike_alg_integ_none) {
						db_attr_add_values(db_ctx,
							AUTH_ALGORITHM,
							algs.integ->common.id[IKEv1_ESP_ID]);
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
		db_attr_add_values(db_ctx, AUTH_ALGORITHM,
				   algs.integ->common.id[IKEv1_ESP_ID]);
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
static struct db_context *kernel_alg_db_new(struct child_proposals proposals,
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

	dbg("%s() initial trans_cnt=%d", __func__, trans_cnt);

	/*	pass aprox. number of transforms and attributes */
	struct db_context *ctx_new = db_prop_new(protoid, trans_cnt, trans_cnt * 2);

	/*
	 *      Loop: for each element (struct esp_info) of
	 *      proposals, if kernel support is present then
	 *      build the transform (and attrs)
	 *
	 *      if NULL proposals, propose everything ...
	 */

	bool success = TRUE;
	if (proposals.p != NULL) {
		FOR_EACH_PROPOSAL(proposals.p, proposal) {
			LSWDBGP(DBG_BASE, buf) {
				lswlogs(buf, "adding proposal: ");
				fmt_proposal(buf, proposal);
			}
			if (!kernel_alg_db_add(ctx_new, proposal, policy, logit))
				success = FALSE;	/* ??? should we break? */
		}
	} else {
		PEXPECT_LOG("%s", "proposals should be non-NULL");
	}

	if (!success) {
		/* NO algorithms were found. oops */
		db_destroy(ctx_new);
		return NULL;
	}

	struct db_prop  *prop = db_prop_get(ctx_new);

	dbg("%s() will return p_new->protoid=%d, p_new->trans_cnt=%d",
	    __func__, prop->protoid, prop->trans_cnt);

	unsigned int tn = 0;
	struct db_trans *t;
	for (t = prop->trans, tn = 0;
	     t != NULL && t[tn].transid != 0 && tn < prop->trans_cnt;
	     tn++) {
		dbg("%s()     trans[%d]: transid=%d, attr_cnt=%d, attrs[0].type=%d, attrs[0].val=%d",
		    __func__, tn,
		    t[tn].transid, t[tn].attr_cnt,
		    t[tn].attrs ? t[tn].attrs[0].type.ipsec : 255,
		    t[tn].attrs ? t[tn].attrs[0].val : 255);
	}
	prop->trans_cnt = tn;

	return ctx_new;
}

void show_kernel_alg_status(struct show *s)
{
	show_separator(s);
	show_comment(s, "Kernel algorithms supported:");
	show_separator(s);

	for (const struct encrypt_desc **alg_p = next_kernel_encrypt_desc(NULL);
	     alg_p != NULL; alg_p = next_kernel_encrypt_desc(alg_p)) {
		const struct encrypt_desc *alg = *alg_p;
		if (alg != NULL) /* nostack gives us no algos */
			show_comment(s,
				"algorithm ESP encrypt: name=%s, keysizemin=%d, keysizemax=%d",
				alg->common.fqn,
				encrypt_min_key_bit_length(alg),
				encrypt_max_key_bit_length(alg));
	}

	for (const struct integ_desc **alg_p = next_kernel_integ_desc(NULL);
	     alg_p != NULL; alg_p = next_kernel_integ_desc(alg_p)) {
		const struct integ_desc *alg = *alg_p;
		if (alg != NULL) /* nostack doesn't give us algos */
			show_comment(s,
				"algorithm AH/ESP auth: name=%s, key-length=%zu",
				alg->common.fqn,
				alg->integ_keymat_size * BITS_PER_BYTE);
	}
}

void show_kernel_alg_connection(struct show *s,
				const struct connection *c,
				const char *instance)
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
		 * Get the DH algorithm specified for the child (ESP or AH).
		 *
		 * If this is NULL and PFS is required then callers fall back to using
		 * the parent's DH algorithm.
		 */
		const struct dh_desc *dh = ikev1_quick_pfs(c->child_proposals);
		if (dh != NULL) {
			pfsbuf = dh->common.fqn;
		} else {
			pfsbuf = "<Phase1>";
		}
	} else {
		pfsbuf = "<N/A>";
	}

	/*
	 * XXX: don't show the default proposal suite (assuming it is
	 * known).  Mainly so that test output doesn't get churned
	 * (originally it wasn't shown because it wasn't known).
	 */
	if (c->child_proposals.p != NULL &&
	    !default_proposals(c->child_proposals.p)) {
		WHACK_LOG(RC_COMMENT, show_fd(s), buf) {
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
			jam(buf, "\"%s\"%s:   %s algorithms: ",
			    c->name, instance, satype);
			jam_proposals(buf, c->child_proposals.p);
		}
	}

	const struct state *st = state_with_serialno(c->newest_ipsec_sa);

	if (st != NULL && st->st_esp.present) {
		show_comment(s,
			  "\"%s\"%s:   %s algorithm newest: %s_%03d-%s; pfsgroup=%s",
			  c->name,
			  instance, satype,
			  st->st_esp.attrs.transattrs.ta_encrypt->common.fqn,
			  st->st_esp.attrs.transattrs.enckeylen,
			  st->st_esp.attrs.transattrs.ta_integ->common.fqn,
			  pfsbuf);
	}

	if (st != NULL && st->st_ah.present) {
		show_comment(s,
			  "\"%s\"%s:   %s algorithm newest: %s; pfsgroup=%s",
			  c->name,
			  instance, satype,
			  st->st_ah.attrs.transattrs.ta_integ->common.fqn,
			  pfsbuf);
	}
}

struct db_sa *kernel_alg_makedb(lset_t policy,
				struct child_proposals proposals,
				bool logit)
{
	if (proposals.p == NULL) {
		struct db_sa *sadb;
		lset_t pm = policy & (POLICY_ENCRYPT | POLICY_AUTHENTICATE);

		dbg("empty esp_info, returning defaults for %s",
		    bitnamesof(sa_policy_bit_names, pm));

		sadb = &ipsec_sadb[pm >> POLICY_IPSEC_SHIFT];

		/* make copy, to keep from freeing the static policies */
		sadb = sa_copy_sa(sadb);
		sadb->parentSA = FALSE;
		return sadb;
	}

	struct db_context *dbnew = kernel_alg_db_new(proposals, policy, logit);

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

	dbg("returning new proposal from esp_info");
	return n;
}
