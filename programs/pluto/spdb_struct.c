/* Security Policy Data Base (such as it is)
 * Copyright (C) 1998-2001 D. Hugh Redelmeier.
 * Copyright (C) 2003-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2008 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2015,2017 Andrew Cagney <cagney@gnu.org>
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libreswan.h>
#include "libreswan/pfkeyv2.h"

#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"

#include "defs.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "packet.h"
#include "keys.h"
#include "kernel.h"     /* needs connections.h */
#include "log.h"
#include "spdb.h"
#include "whack.h"      /* for RC_LOG_SERIOUS */
#include "plutoalg.h"

#include "crypto.h"

#include "alg_info.h"
#include "kernel_alg.h"
#include "ike_alg.h"
#include "db_ops.h"

#include "nat_traversal.h"

/*
 * empty structure, for clone use.
 */
static struct db_attr otempty[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, -1 },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM,       -1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, -1 },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,    -1 },
	{ .type.oakley = OAKLEY_KEY_LENGTH,    -1 },
};

static struct db_trans oakley_trans_empty[] = {
	{ AD_TR(KEY_IKE, otempty) },
};

static struct db_prop oakley_pc_empty[] =
	{ { AD_PR(PROTO_ISAKMP, oakley_trans_empty) } };

static struct db_prop_conj oakley_props_empty[] =
	{ { AD_PC(oakley_pc_empty) } };

static struct db_sa oakley_empty = { AD_SAp(oakley_props_empty) };

/*
 * Create an OAKLEY proposal based on alg_info and policy
 *
 * single_dh is for Aggressive Mode where we must have exactly
 * one DH group.
 */

static struct db_sa *oakley_alg_mergedb(struct alg_info_ike *ai,
					enum ikev1_auth_method auth_method,
					bool single_dh);

static struct alg_info_ike *ikev1_default_ike_info(void)
{
	static const struct proposal_policy policy = {
		.ikev1 = TRUE,
		.alg_is_ok = ike_alg_is_ike,
		.warning = libreswan_log,
	};

	char err[100];
	struct alg_info_ike *defaults =
		alg_info_ike_create_from_str(&policy, NULL,
					     err, sizeof(err));
	if (defaults == NULL) {
		PEXPECT_LOG("Invalid IKEv1 default algorithms: %s", err);
	}

	return defaults;
}

struct db_sa *oakley_alg_makedb(struct alg_info_ike *ai,
				enum ikev1_auth_method auth_method,
				bool single_dh)
{
	/*
	 * start by copying the proposal that would have been picked by
	 * standard defaults.
	 */

	if (ai == NULL) {
		DBG(DBG_CONTROL, DBG_log(
			    "no specific IKE algorithms specified - using defaults"));
		struct alg_info_ike *default_info
			= ikev1_default_ike_info();
		struct db_sa *new_db = oakley_alg_mergedb(default_info,
							  auth_method,
							  single_dh);
		pfree(default_info);
		return new_db;
	} else {
		return oakley_alg_mergedb(ai, auth_method, single_dh);
	}
}

struct db_sa *oakley_alg_mergedb(struct alg_info_ike *ai,
				 enum ikev1_auth_method auth_method,
				 bool single_dh)
{
	passert(ai != NULL);

	struct db_sa *gsp = NULL;

	/* Next two are for multiple proposals in aggressive mode... */
	unsigned last_modp = 0;
	bool warned_dropped_dhgr = FALSE;

	int transcnt = 0;

	/*
	 * for each group, we will create a new proposal item, and then
	 * append it to the list of transforms in the conjoint point.
	 *
	 * when creating each item, we will use the first transform
	 * from the base item as the template.
	 */
	FOR_EACH_IKE_INFO(ai, ike_info) {
		struct db_sa *emp_sp;

		passert(ike_info->encrypt);
		passert(ike_info->prf);
		passert(ike_info->dh);

		unsigned ealg = ike_info->encrypt->common.ikev1_oakley_id;
		unsigned halg = ike_info->prf->common.ikev1_oakley_id;
		unsigned modp = ike_info->dh->group;
		unsigned eklen = ike_info->enckeylen;

		DBG(DBG_CONTROL,
		    DBG_log("oakley_alg_makedb() processing ealg=%s=%u halg=%s=%u modp=%s=%u eklen=%u",
			    ike_info->encrypt->common.name, ealg,
			    ike_info->prf->common.name, halg,
			    ike_info->dh->common.name, modp,
			    eklen));

		const struct encrypt_desc *enc_desc = ike_info->encrypt;
		if (eklen != 0 && !encrypt_has_key_bit_length(enc_desc, eklen)) {
			PEXPECT_LOG("IKEv1 proposal with ENCRYPT%s (specified) keylen:%d, not valid, should have been dropped",
				    enc_desc->common.name,
				    eklen);
			continue;
		}

		/*
		 * copy the template
		 */
		emp_sp = sa_copy_sa(&oakley_empty);
		passert(emp_sp->dynamic);
		passert(emp_sp->prop_conj_cnt == 1);
		passert(emp_sp->prop_conjs[0].prop_cnt == 1);
		passert(emp_sp->prop_conjs[0].props[0].trans_cnt == 1);
		struct db_trans *trans = &emp_sp->prop_conjs[0].props[0].trans[0];
		passert(trans->attr_cnt == 5);

		/*
		 * See "struct db_attr otempty" above, and spdb.c, for
		 * where these magic values come from.
		 */
		struct db_attr *enc  = &trans->attrs[0];
		struct db_attr *hash = &trans->attrs[1];
		struct db_attr *auth = &trans->attrs[2];
		struct db_attr *grp  = &trans->attrs[3];

		/*
		 * auth type for IKE must be set.
		 */
		passert(auth->type.oakley == OAKLEY_AUTHENTICATION_METHOD);
		auth->val = auth_method;

		if (eklen > 0) {
			struct db_attr *enc_keylen = &trans->attrs[4];

			passert(trans->attr_cnt == 5);
			passert(enc_keylen->type.oakley == OAKLEY_KEY_LENGTH);
			enc_keylen->val = eklen;
		} else {
			/* truncate */
			trans->attr_cnt = 4;
		}

		passert(enc->type.oakley == OAKLEY_ENCRYPTION_ALGORITHM);
		if (ealg > 0)
			enc->val = ealg;

		/*
		 * Either pass a hash algorithm or a PRF.
		 *
		 * Since AEAD algorithms don't need the hash,
		 * but do need a PRF, the hash field can be
		 * re-purposed as a PRF field.
		 *
		 * [cagney] While I suspect that type will
		 * never initially be OAKLEY_PRF (it is
		 * initialized using "struct db_attr otempty")
		 * it doesn't hurt to be safe.
		 */
		passert(hash->type.oakley == OAKLEY_HASH_ALGORITHM ||
			hash->type.oakley == OAKLEY_PRF);
		if (halg > 0) {
			hash->val = halg;
			if (encrypt_desc_is_aead(enc_desc)) {
				hash->type.oakley = OAKLEY_PRF;
			} else {
				hash->type.oakley = OAKLEY_HASH_ALGORITHM;
			}
		}

		passert(grp->type.oakley == OAKLEY_GROUP_DESCRIPTION);
		if (modp > 0)
			grp->val = modp;

		/*
		 * Aggressive mode really only works with a single DH group.
		 * If this is for Aggressive Mode, and we've previously seen
		 * a different DH group, we try to deal with this.
		 */
		if (single_dh && transcnt > 0 &&
		    ike_info->dh->group != last_modp) {
			if (
#ifdef USE_DH2
			    last_modp == OAKLEY_GROUP_MODP1024 ||
#endif
			    last_modp == OAKLEY_GROUP_MODP1536) {
				/*
				 * The previous group will work on old Cisco gear,
				 * so we can discard this one.
				 */

				if (!warned_dropped_dhgr) {
					/* complain only once */
					loglog(RC_LOG_SERIOUS,
						"multiple DH groups were set in aggressive mode. Only first one used.");
				}

				loglog(RC_LOG_SERIOUS,
				       "transform (%s,%s,%s keylen %zd) ignored.",
				       enum_name(&oakley_enc_names,
						 ike_info->encrypt->common.ikev1_oakley_id),
				       enum_name(&oakley_hash_names,
						 ike_info->prf->common.ikev1_oakley_id),
				       ike_info->dh->common.name,
				       ike_info->enckeylen);
				free_sa(&emp_sp);
			} else {
				/*
				 * The previous group won't work on old Cisco gear,
				 * so we discard the previous ones.
				 * Of course this modp might be just as bad;
				 * we won't look until the next one comes along.
				 *
				 * Lemma: there will be only a single previous
				 * one in gsp (any others were discarded).
				 */
				loglog(RC_LOG_SERIOUS,
				       "multiple DH groups in aggressive mode can cause interop failure");
				loglog(RC_LOG_SERIOUS,
					"Deleting previous proposal in the hopes of selecting DH 2 or DH 5");

				free_sa(&gsp);
			}

			warned_dropped_dhgr = TRUE;
		}

		 if (emp_sp != NULL) {
			 /*
			  * Exclude 3des et.al. which do not include
			  * default key lengths in the proposal.
			  */
			 if (ike_info->enckeylen == 0 &&
			     !ike_info->encrypt->keylen_omitted) {
				const struct encrypt_desc *enc_desc = ike_info->encrypt;
				int def_ks = enc_desc->keydeflen;
				passert(def_ks); /* ike=null not supported */
				int max_ks = encrypt_max_key_bit_length(enc_desc);
				int ks;

				passert(emp_sp->dynamic);
				passert(emp_sp->prop_conj_cnt == 1);
				passert(emp_sp->prop_conjs[0].prop_cnt == 1);
				passert(emp_sp->prop_conjs[0].props[0].trans_cnt == 1);

				if (emp_sp->prop_conjs[0].props[0].trans[0].attr_cnt == 4) {
					/* add a key length attribute of 0 */
					struct db_trans *tr = &emp_sp->prop_conjs[0].props[0].trans[0];
					const int n = tr->attr_cnt;	/* 4, actually */
					struct db_attr *old_attrs = tr->attrs;
					struct db_attr *new_attrs = alloc_bytes(
						(n + 1) * sizeof(old_attrs[0]),
						"extended trans");

					passert(emp_sp->dynamic);
					passert(old_attrs[0].type.oakley != OAKLEY_KEY_LENGTH &&
						old_attrs[1].type.oakley != OAKLEY_KEY_LENGTH &&
						old_attrs[2].type.oakley != OAKLEY_KEY_LENGTH &&
						old_attrs[3].type.oakley != OAKLEY_KEY_LENGTH);
					memcpy(new_attrs, old_attrs, n * sizeof(old_attrs[0]));
					new_attrs[n].type.oakley = OAKLEY_KEY_LENGTH;
					new_attrs[n].val = 0;

					pfree(old_attrs);
					tr->attrs = new_attrs;
					tr->attr_cnt++;
				}
				passert(emp_sp->prop_conjs[0].props[0].trans[0].attr_cnt == 5);
				passert(emp_sp->prop_conjs[0].props[0].trans[0].attrs[4].type.oakley == OAKLEY_KEY_LENGTH);

				/*
				 * This odd FOR loop executes its body for
				 * exactly two values of ks (max_ks and def_ks)
				 * unless def_ks == max_ks, in which case it is
				 * executed once.
				 */
				for (ks = max_ks; ; ks = def_ks) {
					emp_sp->prop_conjs[0].props[0].trans[0].attrs[4].val = ks;

					if (gsp == NULL) {
						gsp = sa_copy_sa(emp_sp);
					} else {
						struct db_sa *new = sa_merge_proposals(gsp, emp_sp);

						free_sa(&gsp);
						gsp = new;
					}
					if (ks == def_ks)
						break;
				}
				free_sa(&emp_sp);
			} else {
				if (gsp != NULL) {
					/* now merge emp_sa and gsp */
					struct db_sa *new = sa_merge_proposals(gsp, emp_sp);

					free_sa(&gsp);
					free_sa(&emp_sp);
					gsp = new;
				} else {
					gsp = emp_sp;
					emp_sp = NULL;
				}
			}
			last_modp = ike_info->dh->group;
		}

		transcnt++;
	}

	if (gsp != NULL)
		gsp->parentSA = TRUE;

	DBG(DBG_CONTROL,
	    DBG_log("oakley_alg_makedb() returning %p", gsp));
	return gsp;
}
