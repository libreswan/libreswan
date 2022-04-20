/* do RSA operations for IKEv2
 *
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2018 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "sysdep.h"
#include "constants.h"

#include "defs.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "packet.h"
#include "crypto.h"
#include "ike_alg.h"
#include "ike_alg_hash.h"
#include "log.h"
#include "demux.h"      /* needs packet.h */
#include "ikev2.h"
#include "server.h"
#include "keys.h"
#include "secrets.h"
#include "crypt_hash.h"
#include "ietf_constants.h"
#include "ikev2_auth.h"

bool ikev2_calculate_rsa_hash(struct ike_sa *ike,
			      const struct crypt_mac *idhash,
			      pb_stream *a_pbs,
			      chunk_t *no_ppk_auth, /* optional output */
			      const struct hash_desc *hash_algo)
{
	const struct pubkey_type *type = &pubkey_type_rsa;
	statetime_t start = statetime_start(&ike->sa);
	const struct connection *c = ike->sa.st_connection;

	const struct private_key_stuff *pks = get_local_private_key(c, type,
								    ike->sa.st_logger);
	if (pks == NULL) {
		log_state(RC_LOG, &ike->sa, "No %s private key found", type->name);
		return false; /* failure: no key to use */
	}

	struct crypt_mac hash = v2_calculate_sighash(ike, idhash, hash_algo,
						     LOCAL_PERSPECTIVE);
	passert(hash.len <= sizeof(hash.ptr/*array*/));
	const struct pubkey_signer *signer;

	switch (hash_algo->common.ikev2_alg_id) {
	case IKEv2_HASH_ALGORITHM_SHA1:
		/* old style RSA with SHA1 */
		signer = &pubkey_signer_pkcs1_1_5_rsa;
		break;
	case IKEv2_HASH_ALGORITHM_SHA2_256:
	case IKEv2_HASH_ALGORITHM_SHA2_384:
	case IKEv2_HASH_ALGORITHM_SHA2_512:
		signer = &pubkey_signer_rsassa_pss;
		break;
	default:
		bad_case(hash_algo->common.ikev2_alg_id);
	}

	if (DBGP(DBG_CRYPT)) {
		DBG_dump_hunk("v2rsa octets", *idhash);
	}

	/* now generate signature blob */
	statetime_t sign_time = statetime_start(&ike->sa);
	struct hash_signature sig;
	passert(sizeof(sig.ptr/*array*/) >= RSA_MAX_OCTETS);
	sig = signer->sign_hash(pks, idhash->ptr, idhash->len,
				hash_algo, ike->sa.st_logger);
	statetime_stop(&sign_time, "%s() calling sign_hash_RSA()", __func__);
	if (sig.len == 0)
		return false;

	if (no_ppk_auth != NULL) {
		*no_ppk_auth = clone_hunk(sig, "NO_PPK_AUTH chunk");
		if (DBGP(DBG_PRIVATE) || DBGP(DBG_CRYPT)) {
			DBG_dump_hunk("NO_PPK_AUTH payload", *no_ppk_auth);
		}
	} else {
		if (!out_hunk(sig, a_pbs, "rsa signature"))
			return false;
	}

	statetime_stop(&start, "%s()", __func__);
	return true;
}
