/* crypto interfaces
 * Copyright (C) 1998-2001,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2016-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2019 Paul Wouters <pwouters@redhat.com>
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
#include <errno.h>

#include "constants.h"
#include "defs.h"
#include "state.h"
#include "log.h"
#include "crypto.h"
#include "ike_alg.h"
#include "test_buffer.h"
#include "connections.h"
#include "ike_alg_integ.h"
#include "kernel_alg.h"
#include "show.h"

/*
 *      Show IKE algorithms for
 *      - this connection (result from ike= string)
 *      - newest SA
 */
void show_ike_alg_connection(struct show *s,
			     const struct connection *c)
{
	if (c->config->ike_proposals.p != NULL
	    && !default_proposals(c->config->ike_proposals.p)) {
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
		SHOW_JAMBUF(s, buf) {
			jam_connection_short(buf, c);
			jam_string(buf, ":  ");
			/* algs */
			jam_string(buf, " IKE algorithms: ");
			jam_proposals(buf, c->config->ike_proposals.p);
		}
	}

	const struct state *st = state_by_serialno(c->established_ike_sa);

	if (st != NULL) {
		SHOW_JAMBUF(s, buf) {
			jam_connection_short(buf, c);
			jam_string(buf, ":  ");
			/* algs */
			jam(buf, " %s algorithm newest: ",
			    st->st_connection->config->ike_info->version_name);
			const struct trans_attrs *ta = &st->st_oakley;
			const char *sep = "";
			if (ta->ta_encrypt != NULL) {
				jam_string(buf, sep); sep = "-";
				jam_string(buf, ta->ta_encrypt->common.fqn);
				if (ta->enckeylen != 0) {
					jam(buf, "_%d", ta->enckeylen);
				}
			}
			if (ta->ta_prf != NULL) {
				jam_string(buf, sep); sep = "-";
				jam_string(buf, ta->ta_prf->common.fqn);
			}
			/* XXX: should just print everything */
			if (ta->ta_integ != NULL) {
				if ((ta->ta_prf == NULL) ||
				    (encrypt_desc_is_aead(ta->ta_encrypt) &&
				     ta->ta_integ != &ike_alg_integ_none) ||
				    (!encrypt_desc_is_aead(ta->ta_encrypt) &&
				     ta->ta_integ->prf != ta->ta_prf)) {
					jam_string(buf, sep); sep = "-";
					jam_string(buf, ta->ta_integ->common.fqn);
				}
			}
			if (ta->ta_dh != NULL) {
				jam_string(buf, sep); sep = "-";
				jam_string(buf, ta->ta_dh->common.fqn);
			}
		}
	}
}

/*
 * Show registered IKE algorithms
 */
void show_ike_alg_status(struct show *s)
{
	show_separator(s);
	show(s, "IKE algorithms supported:");
	show_separator(s);

	for (const struct encrypt_desc **algp = next_encrypt_desc(NULL);
	     algp != NULL; algp = next_encrypt_desc(algp)) {
		const struct encrypt_desc *alg = (*algp);
		if (ike_alg_is_ike(&(alg)->common)) {
			passert(alg->common.ikev1_oakley_id >= 0 || alg->common.id[IKEv2_ALG_ID] >= 0);
			SHOW_JAMBUF(s, buf) {
				jam_string(buf, "algorithm IKE encrypt:");
				jam(buf, " v1id=%d, v1name=", alg->common.ikev1_oakley_id);
				if (alg->common.id[IKEv1_OAKLEY_ID] >= 0) {
					jam_enum(buf, &oakley_enc_names, alg->common.ikev1_oakley_id);
				} else {
					jam_string(buf, "n/a");
				}
				jam_string(buf, ",");
				jam(buf, " v2id=%d, v2name=", alg->common.id[IKEv2_ALG_ID]);
				if (alg->common.id[IKEv2_ALG_ID] >= 0) {
					jam_enum_short(buf, &ikev2_trans_type_encr_names,
						       alg->common.id[IKEv2_ALG_ID]);
				} else {
					jam_string(buf, "n/a");
				}
				jam_string(buf, ",");
				jam(buf, " blocksize=%zu, keydeflen=%u",
				    alg->enc_blocksize, alg->keydeflen);
			}
		}
	}

	for (const struct prf_desc **algp = next_prf_desc(NULL);
	     algp != NULL; algp = next_prf_desc(algp)) {
		const struct prf_desc *alg = (*algp);
		if (ike_alg_is_ike(&(alg)->common)) {
			show(s,
			     "algorithm IKE PRF: name=%s, hashlen=%zu",
			     alg->common.fqn, alg->prf_output_size);
		}
	}

	for (const struct dh_desc **gdescp = next_dh_desc(NULL);
	     gdescp != NULL; gdescp = next_dh_desc(gdescp)) {
		const struct dh_desc *gdesc = *gdescp;
		if (gdesc->bytes > 0) {
			/* nothing crazy like 'none' */
			show(s,
			     "algorithm IKE DH Key Exchange: name=%s, bits=%d",
			     gdesc->common.fqn,
			     (int)gdesc->bytes * BITS_IN_BYTE);
		}
	}
}
