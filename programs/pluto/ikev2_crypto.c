/* IKEv2 - more cryptographic calculations
 *
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2013-2014 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2017-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 Antony Antony <antony@phenome.org>
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

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "sysdep.h"
#include "constants.h"

#include "defs.h"
#include "log.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "crypto.h"
#include "demux.h"
#include "ikev2.h"
#include "ikev2_prf.h"
#include "ike_alg.h"
#include "kernel_alg.h"
#include "crypt_symkey.h"
#include "ikev2_prf.h"
#include "kernel.h"

void ikev2_derive_child_keys(struct ike_sa *ike, struct child_sa *child)
{
	struct logger *logger = child->sa.logger;

	chunk_t ikeymat, rkeymat;
	/* ??? note assumption that AH and ESP cannot be combined */
	struct ipsec_proto_info *ipi =
		child->sa.st_esp.protocol == &ip_protocol_esp ? &child->sa.st_esp :
		child->sa.st_ah.protocol == &ip_protocol_ah ? &child->sa.st_ah :
		NULL;

	passert(ipi != NULL);	/* ESP or AH must be present */

	/*
	 * Integrity seed (key).  AEAD, for instance has NULL (no)
	 * separate integrity.
	 */
	const struct integ_desc *integ = ipi->trans_attrs.ta_integ;
	size_t integ_key_size = (integ != NULL ? integ->integ_keymat_size : 0);
	/*
	 * If there is encryption, then ENCKEYLEN contains the
	 * required number of bits.
	 */
	size_t encrypt_key_size = BYTES_FOR_BITS(ipi->trans_attrs.enckeylen);
	/*
	 * Finally, some encryption algorithms such as AEAD and CTR
	 * require "salt" as part of the "starting variable".
	 */
	const struct encrypt_desc *encrypt = ipi->trans_attrs.ta_encrypt;
	size_t encrypt_salt_size = (encrypt != NULL ? encrypt->salt_size : 0);

	size_t keymat_len = integ_key_size + encrypt_key_size + encrypt_salt_size;

	ldbg(logger, "integ=%s: .key_size=%zu encrypt=%s: .key_size=%zu .salt_size=%zu keymat_len=%zu",
	    integ != NULL ? integ->common.fqn : "N/A",
	    integ_key_size,
	    encrypt != NULL ? encrypt->common.fqn : "N/A",
	    encrypt_key_size, encrypt_salt_size,
	    keymat_len);

	/*
	 *
	 * Keying material MUST be taken from the expanded KEYMAT in the
	 * following order:
	 *
	 *    All keys for SAs carrying data from the initiator to the responder
	 *    are taken before SAs going in the reverse direction.
	 *
	 *    If multiple IPsec protocols are negotiated, keying material is
	 *    taken in the order in which the protocol headers will appear in
	 *    the encapsulated packet.
	 *
	 *    If a single protocol has both encryption and authentication keys,
	 *    the encryption key is taken from the first octets of KEYMAT and
	 *    the authentication key is taken from the next octets.
	 *
	 *    For AES GCM (RFC 4106 Section 8,1) we need to add 4 bytes for
	 *    salt (AES_GCM_SALT_BYTES)
	 */
	PK11SymKey *shared = NULL;
	if (child->sa.st_pfs_kem != NULL) {
		ldbgf(DBG_CRYPT, child->sa.logger,
		      PRI_SO" %s add g^ir to child key %p",
		      pri_so(child->sa.st_serialno),
		      child->sa.st_state->name, child->sa.st_dh_shared_secret);
		shared = child->sa.st_dh_shared_secret;
	}

	PK11SymKey *keymat = ikev2_child_sa_keymat(child->sa.st_oakley.ta_prf,
						   ike->sa.st_skey_d_nss,
						   shared,
						   child->sa.st_ni,
						   child->sa.st_nr,
						   keymat_len * 2,
						   child->sa.logger);
	PK11SymKey *ikey = key_from_symkey_bytes("initiator to responder key",
						 keymat, 0, keymat_len,
						 HERE, child->sa.logger);
	ikeymat = chunk_from_symkey("initiator to responder keys", ikey,
				    child->sa.logger);
	symkey_delref(child->sa.logger, "ikey", &ikey);

	PK11SymKey *rkey = key_from_symkey_bytes("responder to initiator key",
						 keymat, keymat_len, keymat_len,
						 HERE, child->sa.logger);
	rkeymat = chunk_from_symkey("responder to initiator keys:", rkey,
				    child->sa.logger);
	symkey_delref(child->sa.logger, "rkey", &rkey);

	symkey_delref(child->sa.logger, "keymat", &keymat);

	/*
	 * The initiator stores outgoing initiator-to-responder keymat
	 * in PEER, and incoming responder-to-initiator keymat in
	 * OUR.
	 */
	switch (child->sa.st_sa_role) {
	case SA_RESPONDER:
		if (LDBGP(DBG_CRYPT, logger)) {
			    LDBG_log_hunk(logger, "inbound  keymat:", ikeymat);
			    LDBG_log_hunk(logger, "outbound keymat:", rkeymat);
		}
		ipi->inbound.keymat = ikeymat;
		ipi->outbound.keymat = rkeymat;
		break;
	case SA_INITIATOR:
		if (LDBGP(DBG_CRYPT, logger)) {
			LDBG_log_hunk(logger, "inbound  keymat:", rkeymat);
			LDBG_log_hunk(logger, "outbound keymat:", ikeymat);
		}
		ipi->outbound.keymat = ikeymat;
		ipi->inbound.keymat = rkeymat;
		break;
	default:
		bad_case(child->sa.st_sa_role);
	}
}
