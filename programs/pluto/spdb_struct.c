/* Security Policy Data Base (such as it is)
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2003-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2008 Paul Wouters <paul@xelerance.com>
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
#include "secrets.h"
#include "kernel.h"     /* needs connections.h */
#include "log.h"
#include "spdb.h"
#include "whack.h"      /* for RC_LOG_SERIOUS */
#include "plutoalg.h"

#include "sha1.h"
#include "md5.h"
#include "crypto.h" /* requires sha1.h and md5.h */

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
struct db_sa *oakley_alg_makedb(struct alg_info_ike *ai,
				struct db_sa *base,
				bool single_dh)
{
	struct db_sa *gsp = NULL;
	struct ike_info *ike_info;

	/* Next two are for multiple proposals in agressive mode... */
	unsigned last_modp = 0, wrong_modp = 0;
	int transcnt = 0;
	int i;

	/*
	 * start by copying the proposal that would have been picked by
	 * standard defaults.
	 */

	if (ai == NULL) {
		DBG(DBG_CONTROL, DBG_log(
			    "no specific IKE algorithms specified - using defaults"));
		return NULL;
	}

	/*
	 * for each group, we will create a new proposal item, and then
	 * append it to the list of transforms in the conjoint point.
	 *
	 * when creating each item, we will use the first transform
	 * from the base item as the template.
	 */
	ALG_INFO_IKE_FOREACH(ai, ike_info, i) {
		struct db_sa *emp_sp;

		if (!ike_info->ike_default) {
			struct encrypt_desc *enc_desc;
			struct db_attr  *enc, *hash, *auth, *grp, *enc_keylen;

			unsigned ealg = ike_info->ike_ealg;
			unsigned halg = ike_info->ike_halg;
			unsigned modp = ike_info->ike_modp;
			unsigned eklen = ike_info->ike_eklen;

			if (!ike_alg_enc_present(ealg)) {
				DBG_log("oakley_alg_makedb() "
					"ike enc ealg=%d not present",
					ealg);
				continue;
			}
			if (!ike_alg_hash_present(halg)) {
				DBG_log("oakley_alg_makedb() "
					"ike hash halg=%d not present",
					halg);
				continue;
			}
			enc_desc = ike_alg_get_encrypter(ealg);

			passert(enc_desc != NULL);

			if (eklen != 0 &&
			    (eklen < enc_desc->keyminlen ||
			     eklen >  enc_desc->keymaxlen)) {
				DBG_log("ike_alg_db_new() ealg=%d (specified) keylen:%d, not valid min=%d, max=%d",
					ealg,
					eklen,
					enc_desc->keyminlen,
					enc_desc->keymaxlen);
				continue;
			}

			/*
			 * copy the basic item, and modify it.
			 *
			 * ??? what are these two cases and why does
			 * eklen select between them?
			 */
			if (eklen > 0) {
				/* duplicate, but change auth to match template */
				emp_sp = sa_copy_sa(&oakley_empty, 0);

				passert(emp_sp->dynamic);
				emp_sp->prop_conjs[0].props[0].trans[0].attrs[2] =
				  base->prop_conjs[0].props[0].trans[0].attrs[2];
			} else {
				emp_sp = sa_copy_sa_first(base);
			}

			passert(emp_sp->prop_conj_cnt == 1);
			passert(emp_sp->prop_conjs[0].prop_cnt == 1);
			passert(emp_sp->prop_conjs[0].props[0].trans_cnt == 1);

			{
				struct db_trans *trans = &emp_sp->prop_conjs[0].props[0].trans[0];

				passert(emp_sp->dynamic);
				passert(trans->attr_cnt == 4 || trans->attr_cnt == 5);
				enc  = &trans->attrs[0];
				hash = &trans->attrs[1];
				auth = &trans->attrs[2];
				grp  = &trans->attrs[3];

				if (eklen > 0) {
					enc_keylen = &trans->attrs[4];
					enc_keylen->val = eklen;
				} else {
					trans->attr_cnt = 4;
				}
			}

			passert(enc->type.oakley ==
				OAKLEY_ENCRYPTION_ALGORITHM);
			if (ealg > 0)
				enc->val = ealg;

			passert(hash->type.oakley == OAKLEY_HASH_ALGORITHM);
			if (halg > 0)
				hash->val = halg;

			/*
			 * auth type for IKE must be set
			 * (??? until we support AES-GCM in IKE)
			 */
			passert(auth->type.oakley ==
				OAKLEY_AUTHENTICATION_METHOD);

			passert(grp->type.oakley == OAKLEY_GROUP_DESCRIPTION);

			if (modp > 0)
				grp->val = modp;
		} else {
			emp_sp = sa_copy_sa(base, 0);
		}

		/* Are we allowing multiple DH groups? */

		if (single_dh && transcnt > 0 &&
		    ike_info->ike_modp != last_modp) {
			/* Not good.
			 * Already got a DH group and this one doesn't match
			 */
			if (wrong_modp == 0) {
				loglog(RC_LOG_SERIOUS,
				       "multiple DH groups were set in aggressive mode. Only first one used.");
			}

			loglog(RC_LOG_SERIOUS,
			       "transform (%s,%s,%s keylen %ld) ignored.",
			       enum_name(&oakley_enc_names, ike_info->ike_ealg),
			       enum_name(&oakley_hash_names, ike_info->ike_halg),
			       enum_name(&oakley_group_names, ike_info->ike_modp),
			       (long)ike_info->ike_eklen);

			wrong_modp++;

			free_sa(emp_sp);
			emp_sp = NULL;
		} else {
			int def_ks = 0;

			if (!ike_info->ike_default && ike_info->ike_eklen == 0)
				def_ks = crypto_req_keysize(CRK_IKEv1, ike_info->ike_ealg);

			if (def_ks != 0) {
				struct encrypt_desc *enc_desc = ike_alg_get_encrypter(ike_info->ike_ealg);
				int max_ks = enc_desc->keymaxlen;
				int ks;

				passert(emp_sp->dynamic);
				passert(emp_sp->prop_conj_cnt == 1);
				passert(emp_sp->prop_conjs[0].prop_cnt == 1);
				passert(emp_sp->prop_conjs[0].props[0].trans_cnt == 1);

				if (emp_sp->prop_conjs[0].props[0].trans[0].attr_cnt == 4) {
					/* copy and add a slot */
					struct db_trans *tr = &emp_sp->prop_conjs[0].props[0].trans[0];
					struct db_attr *old_attrs = tr->attrs;

					clone_trans(tr, 1);
					pfree(old_attrs);
					tr->attrs[4].type.oakley = OAKLEY_KEY_LENGTH;
				}
				passert(emp_sp->prop_conjs[0].props[0].trans[0].attr_cnt == 5);
				passert(emp_sp->prop_conjs[0].props[0].trans[0].attrs[4].type.oakley == OAKLEY_KEY_LENGTH);

				for (ks = def_ks; ; ks = max_ks) {
					emp_sp->prop_conjs[0].props[0].trans[0].attrs[4].val = ks;

					if (gsp == NULL) {
						gsp = sa_copy_sa(emp_sp, 0);
					} else {
						struct db_sa *new = sa_merge_proposals(gsp, emp_sp);

						free_sa(gsp);
						gsp = new;
					}
					if (ks == max_ks)
						break;
				}
				free_sa(emp_sp);
			} else {
				if (gsp != NULL) {
					/* now merge emp_sa and gsp */
					struct db_sa *new = sa_merge_proposals(gsp, emp_sp);

					free_sa(gsp);
					free_sa(emp_sp);
					emp_sp = NULL;
					gsp = new;
					
				} else {
					gsp = emp_sp;
					emp_sp = NULL;
				}
			}
			last_modp = ike_info->ike_modp;
		}

		transcnt++;
	}

	if (gsp != NULL)
		gsp->parentSA = TRUE;

	return gsp;
}
