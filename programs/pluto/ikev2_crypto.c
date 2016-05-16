/* IKEv2 - more cryptographic calculations
 *
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2013-2014 Paul Wouters <paul@libreswan.org>
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
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"
#include "libswan.h"

#include "defs.h"
#include "cookie.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "packet.h"
#include "md5.h"
#include "sha1.h"
#include "crypto.h" /* requires sha1.h and md5.h */
#include "demux.h"
#include "ikev2.h"
#include "ikev2_prf.h"
#include "ike_alg.h"
#include "alg_info.h"
#include "kernel_alg.h"
#include "crypt_symkey.h"
#include "crypt_dbg.h"
#include "ikev2_prf.h"
#include "kernel.h"

void ikev2_derive_child_keys(struct state *st, enum original_role role)
{
	chunk_t ikeymat, rkeymat;
	/* ??? note assumption that AH and ESP cannot be combined */
	struct ipsec_proto_info *ipi =
		st->st_esp.present? &st->st_esp :
		st->st_ah.present? &st->st_ah :
		NULL;
	struct esp_info *ei;

	passert(ipi != NULL);	/* ESP or AH must be present */
	passert(st->st_esp.present != st->st_ah.present);	/* only one */

	/* ??? there is no kernel_alg_ah_info */
	/* ??? will this work if the result of kernel_alg_esp_info
	 * is a pointer into its own static buffer (therefore ephemeral)?
	 */
	ei = kernel_alg_esp_info(
		ipi->attrs.transattrs.encrypt,
		ipi->attrs.transattrs.enckeylen,
		ipi->attrs.transattrs.integ_hash);

	passert(ei != NULL);
	ipi->attrs.transattrs.ei = ei;

	/* ipi->attrs.transattrs.integ_hasher->hash_key_size / BITS_PER_BYTE; */
	unsigned authkeylen = ikev1_auth_kernel_attrs(ei->auth, NULL);
	/* ??? no account is taken of AH */
	/* transid is same as esp_ealg_id */
	switch (ei->transid) {
	case IKEv2_ENCR_reserved:
		/* AH */
		ipi->keymat_len = authkeylen;
		break;

	case IKEv2_ENCR_AES_CTR:
		ipi->keymat_len = ei->enckeylen + authkeylen + AES_CTR_SALT_BYTES;;
		break;

	case IKEv2_ENCR_AES_GCM_8:
	case IKEv2_ENCR_AES_GCM_12:
	case IKEv2_ENCR_AES_GCM_16:
		/* aes_gcm does not use an integ (auth) algo - see RFC 4106 */
		ipi->keymat_len = ei->enckeylen + AES_GCM_SALT_BYTES;
		break;

	case IKEv2_ENCR_AES_CCM_8:
	case IKEv2_ENCR_AES_CCM_12:
	case IKEv2_ENCR_AES_CCM_16:
		/* aes_ccm does not use an integ (auth) algo - see RFC 4309 */
		ipi->keymat_len = ei->enckeylen + AES_CCM_SALT_BYTES;
		break;

	default:
		/* ordinary ESP */
		ipi->keymat_len = ei->enckeylen + authkeylen;
		break;
	}

	DBG(DBG_CONTROL,
		DBG_log("enckeylen=%" PRIu32 ", authkeylen=%u, keymat_len=%" PRIu16,
			ei->enckeylen, authkeylen, ipi->keymat_len));

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
	chunk_t ni;
	chunk_t nr;
	setchunk(ni, st->st_ni.ptr, st->st_ni.len);
	setchunk(nr, st->st_nr.ptr, st->st_nr.len);

	PK11SymKey *keymat = ikev2_child_sa_keymat(st->st_oakley.prf_hasher,
						   st->st_skey_d_nss,
						   NULL/*dh*/, ni, nr,
						   ipi->keymat_len * 2);
	PK11SymKey *ikey = key_from_symkey_bytes(keymat, 0, ipi->keymat_len);
	ikeymat = chunk_from_symkey("initiator keys", ikey);
	free_any_symkey("ikey:", &ikey);

	PK11SymKey *rkey = key_from_symkey_bytes(keymat, ipi->keymat_len,
						 ipi->keymat_len);
	rkeymat = chunk_from_symkey("responder keys:", rkey);
	free_any_symkey("rkey:", &rkey);

	free_any_symkey("keymat", &keymat);

	if (role != ORIGINAL_INITIATOR) {
		DBG(DBG_PRIVATE, {
			    DBG_dump_chunk("our  keymat", ikeymat);
			    DBG_dump_chunk("peer keymat", rkeymat);
		    });
		ipi->our_keymat = ikeymat.ptr;
		ipi->peer_keymat = rkeymat.ptr;
	} else {
		DBG(DBG_PRIVATE, {
			    DBG_dump_chunk("our  keymat", rkeymat);
			    DBG_dump_chunk("peer keymat", ikeymat);
		    });
		ipi->peer_keymat = ikeymat.ptr;
		ipi->our_keymat = rkeymat.ptr;
	}

}
