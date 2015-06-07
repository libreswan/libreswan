/* Security Policy Data Base debugging routines
 * Copyright (C) 2005-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
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

#include "sha1.h"
#include "md5.h"
#include "crypto.h" /* requires sha1.h and md5.h */

#include "alg_info.h"
#include "kernel_alg.h"
#include "ike_alg.h"
#include "db_ops.h"
#include "spdb.h"

static void log_sa_attr_oakley(struct db_attr *at)
{
	const struct enum_names *en = NULL;

	if (at->type.oakley == OAKLEY_ATTR_undefined)
		return;

	if (at->type.oakley < oakley_attr_val_descs_roof)
		en = oakley_attr_val_descs[at->type.oakley];
	DBG_log("        type: %u(%s) val: %u(%s)\n",
	       at->type.oakley,
	       enum_name(&oakley_attr_names, at->type.oakley +
			 ISAKMP_ATTR_AF_TV),
	       at->val,  en ? enum_name(en, at->val) : "unknown");
}

static void log_sa_attr_ipsec(struct db_attr *at)
{
	const struct enum_names *en = NULL;

	if (at->type.ipsec == 0)
		return;

	if (at->type.ipsec < ipsec_attr_val_descs_roof)
		en = ipsec_attr_val_descs[at->type.ipsec];
	DBG_log("        type: %u(%s) val: %u(%s)\n",
	       at->type.ipsec,
	       enum_name(&ipsec_attr_names,
			 at->type.ipsec + ISAKMP_ATTR_AF_TV),
	       at->val,  en ? enum_name(en, at->val) : "unknown");
}

static void log_sa_trans(struct db_sa *f, struct db_trans *tr)
{
	unsigned int i;

	DBG_log("      transform: %u cnt: %u\n",
	       tr->transid, tr->attr_cnt);
	for (i = 0; i < tr->attr_cnt; i++) {
		if (f->parentSA)
			log_sa_attr_oakley(&tr->attrs[i]);
		else
			log_sa_attr_ipsec(&tr->attrs[i]);
	}
}

static void log_sa_prop(struct db_sa *f, struct db_prop *dp)
{
	unsigned int i;

	DBG_log("    protoid: %u (%s) cnt: %u\n",
	       dp->protoid,
	       enum_name(&protocol_names, dp->protoid),
	       dp->trans_cnt);
	for (i = 0; i < dp->trans_cnt; i++)
		log_sa_trans(f, &dp->trans[i]);
}

static void log_sa_prop_conj(struct db_sa *f, struct db_prop_conj *pc)
{
	unsigned int i;

	DBG_log("  conjunctions cnt: %u\n",
	       pc->prop_cnt);
	for (i = 0; i < pc->prop_cnt; i++)
		log_sa_prop(f, &pc->props[i]);
}

void sa_log(struct db_sa *f)
{
	unsigned int i;

	DBG_log("sa disjunct cnt: %u\n",
	       f->prop_conj_cnt);
	for (i = 0; i < f->prop_conj_cnt; i++)
		log_sa_prop_conj(f, &f->prop_conjs[i]);
}

static void log_sa_v2_attr(struct db_attr *at)
{
	if (at->type.v2 == 0)
		return;

	DBG_log("        type: %u(%s) val: %u(%s)\n",
	       at->type.v2,
	       enum_name(&ikev2_trans_attr_descs, at->type.v2 + ISAKMP_ATTR_AF_TV),
	       at->val,  "unknown (fixme in log_sa_v2_attr()");
}

static void log_sa_v2_trans(struct db_v2_trans *tr)
{
	unsigned int i;
	const struct enum_names *en = NULL;

	if (tr->transform_type < ikev2_transid_val_descs_roof)
		en = ikev2_transid_val_descs[tr->transform_type];

	DBG_log("      type: %u(%s) value: %u(%s) attr_cnt: %u\n",
	       tr->transform_type,
	       enum_name(&ikev2_trans_type_names, tr->transform_type),
	       tr->transid, en ? enum_name(en, tr->transid) : "unknown",
	       tr->attr_cnt);
	for (i = 0; i < tr->attr_cnt; i++)
		log_sa_v2_attr(&tr->attrs[i]);
}

static void log_sa_v2_prop_conj(struct db_v2_prop_conj *dp)
{
	unsigned int i;

	DBG_log("    proposal #%u protoid: %u (%s) cnt: %u\n",
	       dp->propnum,
	       dp->protoid,
	       enum_name(&protocol_names, dp->protoid),
	       dp->trans_cnt);
	for (i = 0; i < dp->trans_cnt; i++)
		log_sa_v2_trans(&dp->trans[i]);
}

static void log_sa_v2_prop(struct db_v2_prop *pc)
{
	unsigned int i;

	DBG_log("  conjunctions cnt: %u\n",
	       pc->prop_cnt);
	for (i = 0; i < pc->prop_cnt; i++)
		log_sa_v2_prop_conj(&pc->props[i]);
}

void sa_v2_log(struct db_sa *f)
{
	unsigned int i;

	DBG_log("sav2 disjoint cnt: %u\n",
	       f->v2_prop_disj_cnt);
	for (i = 0; i < f->v2_prop_disj_cnt; i++)
		log_sa_v2_prop(&f->v2_prop_disj[i]);
}
