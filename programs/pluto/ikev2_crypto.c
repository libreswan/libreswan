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
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "packet.h"
#include "crypto.h"
#include "demux.h"
#include "ikev2.h"
#include "ikev2_prf.h"
#include "ike_alg.h"
#include "kernel_alg.h"
#include "crypt_symkey.h"
#include "ikev2_prf.h"
#include "kernel.h"

void ikev2_derive_child_keys(struct child_sa *child)
{
	struct state *st = &child->sa;
	chunk_t ikeymat, rkeymat;
	/* ??? note assumption that AH and ESP cannot be combined */
	struct ipsec_proto_info *ipi =
		st->st_esp.present? &st->st_esp :
		st->st_ah.present? &st->st_ah :
		NULL;

	passert(ipi != NULL);	/* ESP or AH must be present */
	passert(st->st_esp.present != st->st_ah.present);	/* only one */

	/*
	 * Integrity seed (key).  AEAD, for instance has NULL (no)
	 * separate integrity.
	 */
	const struct integ_desc *integ = ipi->attrs.transattrs.ta_integ;
	size_t integ_key_size = (integ != NULL ? integ->integ_keymat_size : 0);
	/*
	 * If there is encryption, then ENCKEYLEN contains the
	 * required number of bits.
	 */
	size_t encrypt_key_size = BYTES_FOR_BITS(ipi->attrs.transattrs.enckeylen);
	/*
	 * Finally, some encryption algorithms such as AEAD and CTR
	 * require "salt" as part of the "starting variable".
	 */
	const struct encrypt_desc *encrypt = ipi->attrs.transattrs.ta_encrypt;
	size_t encrypt_salt_size = (encrypt != NULL ? encrypt->salt_size : 0);

	ipi->keymat_len = integ_key_size + encrypt_key_size + encrypt_salt_size;

	dbg("integ=%s: .key_size=%zu encrypt=%s: .key_size=%zu .salt_size=%zu keymat_len=%" PRIu16,
	    integ != NULL ? integ->common.fqn : "N/A",
	    integ_key_size,
	    encrypt != NULL ? encrypt->common.fqn : "N/A",
	    encrypt_key_size, encrypt_salt_size,
	    ipi->keymat_len);

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
	if (st->st_pfs_group != NULL) {
		DBGF(DBG_CRYPT, "#%lu %s add g^ir to child key %p",
		     st->st_serialno, st->st_state->name, st->st_dh_shared_secret);
		shared = st->st_dh_shared_secret;
	}

	PK11SymKey *keymat = ikev2_child_sa_keymat(st->st_oakley.ta_prf,
						   st->st_skey_d_nss,
						   shared,
						   st->st_ni,
						   st->st_nr,
						   ipi->keymat_len * 2,
						   st->st_logger);
	PK11SymKey *ikey = key_from_symkey_bytes(keymat, 0, ipi->keymat_len,
						 HERE, st->st_logger);
	ikeymat = chunk_from_symkey("initiator to responder keys", ikey,
				    st->st_logger);
	release_symkey(__func__, "ikey", &ikey);

	PK11SymKey *rkey = key_from_symkey_bytes(keymat, ipi->keymat_len,
						 ipi->keymat_len,
						 HERE, st->st_logger);
	rkeymat = chunk_from_symkey("responder to initiator keys:", rkey,
				    st->st_logger);
	release_symkey(__func__, "rkey", &rkey);

	release_symkey(__func__, "keymat", &keymat);

	/*
	 * The initiator stores outgoing initiator-to-responder keymat
	 * in PEER, and incoming responder-to-initiator keymat in
	 * OUR.
	 */
	switch (child->sa.st_sa_role) {
	case SA_RESPONDER:
		if (DBGP(DBG_PRIVATE) || DBGP(DBG_CRYPT)) {
			    DBG_dump_hunk("our  keymat", ikeymat);
			    DBG_dump_hunk("peer keymat", rkeymat);
		}
		ipi->our_keymat = ikeymat.ptr;
		ipi->peer_keymat = rkeymat.ptr;
		break;
	case SA_INITIATOR:
		if (DBGP(DBG_PRIVATE) || DBGP(DBG_CRYPT)) {
			DBG_dump_hunk("our  keymat", rkeymat);
			DBG_dump_hunk("peer keymat", ikeymat);
		}
		ipi->peer_keymat = ikeymat.ptr;
		ipi->our_keymat = rkeymat.ptr;
		break;
	default:
		bad_case(child->sa.st_sa_role);
	}
}
