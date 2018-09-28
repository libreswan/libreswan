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
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
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

#include "kernel_alg.h"

/*
 *      Show IKE algorithms for
 *      - this connection (result from ike= string)
 *      - newest SA
 */
void ike_alg_show_connection(const struct connection *c, const char *instance)
{
	if (c->alg_info_ike != NULL) {
		/*
		 * List the algorithms as found in alg_info_ike and as
		 * will be fed into the proposal code.
		 *
		 * XXX:
		 *
		 * An earlier variant of this code would append the
		 * "default" encryption key-length if it wasn't
		 * specified on the ike= line.  It isn't clear how
		 * helpful this is so it was removed:
		 *
		 * - it becomes hard to differentiate between ike=aes
		 *   and ike=aes_128
		 *
		 * - proposal code will likely generate a single
		 *   proposal containing TWO keys - max then default -
		 *   so just displaying default is very misleading.
		 *   MAX will probably be selected.
		 *
		 * - for 3DES_CBC, which has only one default, knowing
		 *   it is _192 probably isn't useful
		 *
		 * What is needed is a way to display all key lengths
		 * in the order that they will be proposed (remember
		 * ESP reverses this).  Something like
		 * AES_CBC_256+AES_CBC_128-... (which we hope is not
		 * impossible to parse)?
		 */
		LSWLOG_WHACK(RC_COMMENT, buf) {
			lswlogf(buf, "\"%s\"%s:   IKE algorithms: ",
				c->name, instance);
			lswlog_alg_info(buf, &c->alg_info_ike->ai);
		}
	}

	const struct state *st = state_with_serialno(c->newest_isakmp_sa);

	if (st != NULL) {
		/*
		 * Convert the crypt-suite into 'struct proposal_info'
		 * so that the parser's print-alg code can be used.
		 */
		const struct proposal_info p = {
			.encrypt = st->st_oakley.ta_encrypt,
			.enckeylen = st->st_oakley.enckeylen,
			.prf = st->st_oakley.ta_prf,
			.integ = st->st_oakley.ta_integ,
			.dh = st->st_oakley.ta_dh,
		};
		const char *v = st->st_ikev2 ? "IKEv2" : "IKE";
		LSWLOG_WHACK(RC_COMMENT, buf) {
			lswlogf(buf,
				"\"%s\"%s:   %s algorithm newest: ",
				c->name, instance, v);
			lswlog_proposal_info(buf, &p);
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
			passert(alg->common.ikev1_oakley_id >= 0 || alg->common.id[IKEv2_ALG_ID] >= 0);
			whack_log(RC_COMMENT,
				  "algorithm IKE encrypt: v1id=%d, v1name=%s, v2id=%d, v2name=%s, blocksize=%zu, keydeflen=%u",
				  alg->common.ikev1_oakley_id,
				  (alg->common.ikev1_oakley_id >= 0
				   ? enum_showb(&oakley_enc_names,
						alg->common.ikev1_oakley_id,
						&v1namebuf)
				   : "n/a"),
				  alg->common.id[IKEv2_ALG_ID],
				  (alg->common.id[IKEv2_ALG_ID] >= 0
				   ? enum_showb(&ikev2_trans_type_encr_names,
						alg->common.id[IKEv2_ALG_ID],
						&v2namebuf)
				   : "n/a"),
				  alg->enc_blocksize,
				  alg->keydeflen);
		}
	}

	for (const struct prf_desc **algp = next_prf_desc(NULL);
	     algp != NULL; algp = next_prf_desc(algp)) {
		const struct prf_desc *alg = (*algp);
		if (ike_alg_is_ike(&(alg)->common)) {
			whack_log(RC_COMMENT,
				  "algorithm IKE PRF: name=%s, hashlen=%zu",
				  alg->common.fqn, alg->prf_output_size);
		}
	}

	for (const struct oakley_group_desc **gdescp = next_oakley_group(NULL);
	     gdescp != NULL; gdescp = next_oakley_group(gdescp)) {
		const struct oakley_group_desc *gdesc = *gdescp;
		if (gdesc->bytes > 0) {
			/* nothing crazy like 'none' */
			whack_log(RC_COMMENT,
				  "algorithm IKE DH Key Exchange: name=%s, bits=%d",
				  gdesc->common.name,
				  (int)gdesc->bytes * BITS_PER_BYTE);
		}
	}

	whack_log(RC_COMMENT, " "); /* spacer */
}
