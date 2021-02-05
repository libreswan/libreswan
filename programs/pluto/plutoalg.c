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
#include "ikev1_db_ops.h"
#include "log.h"
#include "whack.h"
#include "ikev1.h"	/* for ikev1_quick_dh() */

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
		switch (c->ike_version) {
#ifdef USE_IKEv1
		case IKEv1:
		{
			const struct dh_desc *dh = ikev1_quick_pfs(c->child_proposals);
			if (dh != NULL) {
				pfsbuf = dh->common.fqn;
			} else {
				pfsbuf = "<Phase1>";
			}
			break;
		}
#endif
		case IKEv2:
		default:
			pfsbuf = "<Phase1>";
			break;
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
		SHOW_JAMBUF(RC_COMMENT, s, buf) {
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
