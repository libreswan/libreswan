/* IKEv2 message routines, for Libreswan
 *
 * Copyright (C) 2007-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2010,2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012-2017 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
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


#include "defs.h"

#include "ikev2_message.h"
#include "server.h"
#include "state.h"
#include "connections.h"
#include "lswlog.h"
#include "ike_alg.h"
#include "ike_alg_encrypt_ops.h"	/* XXX: oops */
#include "pluto_stats.h"
#include "demux.h"	/* for struct msg_digest */
#include "rnd.h"
#include "crypt_prf.h"
#include "send.h"	/* record_outbound_ike_message() */
#include "ip_info.h"
#include "iface.h"
#include "ip_protocol.h"
#include "ikev2_send.h"
#include "log.h"

/*
 * Determine the IKE version we will use for the IKE packet
 * Normally, this is "2.0", but in the future we might need to
 * change that. Version used is the minimum 2.x version both
 * sides support. So if we support 2.1, and they support 2.0,
 * we should sent 2.0 (not implemented until we hit 2.1 ourselves)
 * We also have some impair functions that modify the major/minor
 * version on purpose - for testing
 *
 * rcv_version: the received IKE version, 0 if we don't know
 *
 * top 4 bits are major version, lower 4 bits are minor version
 */
static uint8_t build_ikev2_version(void)
{
	/* TODO: if bumping, we should also set the Version flag in the ISAKMP header */
	return ((IKEv2_MAJOR_VERSION + (impair.major_version_bump ? 1 : 0))
			<< ISA_MAJ_SHIFT) |
	       (IKEv2_MINOR_VERSION + (impair.minor_version_bump ? 1 : 0));
}

uint8_t build_ikev2_critical(bool impaired)
{
	uint8_t octet = 0;
	if (impaired) {
		/* flip the expected bit */
		libreswan_log("IMPAIR: setting (should be off) critical payload bit");
		octet = ISAKMP_PAYLOAD_CRITICAL;
	} else {
		octet = ISAKMP_PAYLOAD_NONCRITICAL;
	}
	if (impair.send_bogus_payload_flag) {
		libreswan_log("IMPAIR: adding bogus bit to critical octet");
		octet |= ISAKMP_PAYLOAD_LIBRESWAN_BOGUS;
	}
	return octet;
}

/*
 * Open an IKEv2 message.
 *
 * Request: IKE, which must be non-NULL, is used to determine the IKE
 * SA Initiator / Responder role; MD must be NULL (after all a request
 * has no response).
 *
 * Response: If IKE is non-NULL then it is used to determine the IKE
 * SA Initiator / Responder role (NULL implies IKE SA Initiator); MD
 * must be non-NULL (the message being responded to).
 */

pb_stream open_v2_message(pb_stream *reply,
			  struct ike_sa *ike, struct msg_digest *md,
			  enum isakmp_xchg_types exchange_type)
{
	/* at least one, possibly both */
	passert(ike != NULL || md != NULL);

	struct isakmp_hdr hdr = {
		.isa_flags = impair.send_bogus_isakmp_flag ? ISAKMP_FLAGS_RESERVED_BIT6 : LEMPTY,
		.isa_version = build_ikev2_version(),
		.isa_xchg = exchange_type,
		.isa_length = 0, /* filled in when PBS is closed */
	};

	/*
	 * I (Initiator) flag
	 *
	 * If there is an IKE SA, the sa_role can be used.
	 *
	 * If there is no IKE SA, then, presumably, this is a response
	 * to an initial exchange and the flag should be clear.
	 *
	 * The other possability is that this is a response to an
	 * IKEv++ message, just assume this is the initial exchange
	 * and the I flag should be clear (see 1.5.  Informational
	 * Messages outside of an IKE SA).  The other option would be
	 * to flip MD's I bit, but since this is IKEv++, there may not
	 * even be an I bit.
	 */
	enum sa_role sa_role = (ike != NULL ? ike->sa.st_sa_role : SA_RESPONDER);
	if (sa_role == SA_INITIATOR) {
		hdr.isa_flags |= ISAKMP_FLAGS_v2_IKE_I;
	}

	/*
	 * R (Response) flag
	 *
	 * If there's no MD, then this must be a new exchange request
	 * - R(Responder) flag clear.
	 *
	 * If there is an MD, then this must be a response -
	 * R(Responder) flag set.
	 *
	 * Note that when MD!= NULL, v2_msg_role() can't be called (as
	 * a cross check) as this code used to force a response to a
	 * message that is close to bogus requests (1.5.
	 * Informational Messages outside of an IKE SA - where the
	 * response is forced.
	 */
	enum message_role message_role = (md != NULL ? MESSAGE_RESPONSE : MESSAGE_REQUEST);
	if (message_role == MESSAGE_RESPONSE) {
		hdr.isa_flags |= ISAKMP_FLAGS_v2_MSG_R;
	}

	/*
	 * SPI (aka cookies).
	 */
	if (ike != NULL) {
		/*
		 * Note that when the original initiator sends the
		 * IKE_SA_INIT request, the still zero SPIr will be
		 * copied.
		 */
		hdr.isa_ike_initiator_spi = ike->sa.st_ike_spis.initiator;
		hdr.isa_ike_responder_spi = ike->sa.st_ike_spis.responder;
	} else {
		/*
		 * Either error response notification to IKE_SA_INIT
		 * or "Informational Messages outside of an IKE SA".
		 * Use the IKE SPIs from the request.
		 */
		passert(md != NULL);
		hdr.isa_ike_initiator_spi = md->hdr.isa_ike_initiator_spi;
		hdr.isa_ike_responder_spi = md->hdr.isa_ike_responder_spi;
	}

	/*
	 * Message ID
	 */
	if (md != NULL) {
		/*
		 * Since there is a message digest (MD) it is assumed
		 * to contain a message request.  Presumably this open
		 * is for the message response - use the Message ID
		 * from the request.  A better choice would be
		 * .st_v2_msgid_windows.responder.recv+1, but it isn't
		 * clear if/when that value is updated and the IKE SA
		 * isn't always available.
		 */
		hdr.isa_msgid = md->hdr.isa_msgid;
	} else {
		/*
		 * If it isn't a response then use the IKE SA's
		 * .st_v2_msgid_windows.initiator.sent+1.  The field
		 * will be updated as part of finishing the state
		 * transition and sending the message.
		 */
		passert(ike != NULL);
		hdr.isa_msgid = ike->sa.st_v2_msgid_windows.initiator.sent + 1;
	}

	if (impair.bad_ike_auth_xchg) {
		libreswan_log("IMPAIR: Instead of replying with IKE_AUTH, forging an INFORMATIONAL reply");
		if ((hdr.isa_flags & ISAKMP_FLAGS_v2_MSG_R) && exchange_type == ISAKMP_v2_IKE_AUTH) {
			hdr.isa_xchg = ISAKMP_v2_INFORMATIONAL;
		}
	}

	struct pbs_out rbody;
	if (!pbs_out_struct(reply, &hdr, sizeof(hdr), &isakmp_hdr_desc, &rbody)) {
		return empty_pbs;
	}
	if (impair.add_unknown_v2_payload_to == exchange_type &&
	    !emit_v2UNKNOWN("request", exchange_type, &rbody)) {
		return empty_pbs;
	}

	return rbody;
}

/*
 * This code assumes that the encrypted part of an IKE message starts
 * with an Initialization Vector (IV) of enc_blocksize of random
 * octets.  The IV will subsequently be discarded after decryption.
 * This is true of Cipher Block Chaining mode (CBC).
 */
static bool emit_v2SK_iv(v2SK_payload_t *sk)
{
	/* compute location/size */
	sk->iv = chunk2(sk->pbs.cur, sk->ike->sa.st_oakley.ta_encrypt->wire_iv_size);
	/* make space */
	if (!out_zero(sk->iv.len, &sk->pbs, "IV")) {
		return false;
	}
	/* scribble on it */
	fill_rnd_chunk(sk->iv);
	return true;
}

v2SK_payload_t open_v2SK_payload(struct logger *logger,
				 pb_stream *container,
				 struct ike_sa *ike)
{
	static const v2SK_payload_t empty_sk;
	v2SK_payload_t sk = {
		.logger = logger,
		.ike = ike,
		.payload = {
		    .ptr = container->cur,
		    .len = 0,	/* computed at end; set here to silence GCC 6.10 */
		}
	};

	/* emit Encryption Payload header */

	struct ikev2_generic e = {
		.isag_length = 0, /* filled in later */
		.isag_critical = build_ikev2_critical(false),
	};
	if (!out_struct(&e, &ikev2_sk_desc, container, &sk.pbs)) {
		log_message(RC_LOG, logger,
			    "error initializing SK header for encrypted %s message",
			    container->name);
		return empty_sk;
	}

	/* emit IV and save location */

	if (!emit_v2SK_iv(&sk)) {
		log_message(RC_LOG, logger,
			    "error initializing IV for encrypted %s message",
			    container->name);
		return empty_sk;
	}

	/* save cleartext start */

	sk.cleartext.ptr = sk.pbs.cur;
	passert(sk.iv.ptr <= sk.cleartext.ptr);
	passert(sk.pbs.container->name == container->name);

	return sk;
}

bool close_v2SK_payload(v2SK_payload_t *sk)
{
	/* save cleartext end */

	sk->cleartext.len = sk->pbs.cur - sk->cleartext.ptr;

	/* emit padding + pad-length */

	size_t padding;
	if (sk->ike->sa.st_oakley.ta_encrypt->pad_to_blocksize) {
		const size_t blocksize = sk->ike->sa.st_oakley.ta_encrypt->enc_blocksize;
		padding = pad_up(sk->pbs.cur - sk->cleartext.ptr, blocksize);
		if (padding == 0) {
			padding = blocksize;
		}
	} else {
		padding = 1;
	}
	dbg("adding %zd bytes of padding (including 1 byte padding-length)",
	    padding);
	for (unsigned i = 0; i < padding; i++) {
		if (!out_repeated_byte(i, 1, &sk->pbs, "padding and length")) {
			libreswan_log("error initializing padding for encrypted %s payload",
				      sk->pbs.container->name);
			return false;
		}
	}

	/* emit space for integrity checksum data; save location  */

	size_t integ_size = (encrypt_desc_is_aead(sk->ike->sa.st_oakley.ta_encrypt)
			     ? sk->ike->sa.st_oakley.ta_encrypt->aead_tag_size
			     : sk->ike->sa.st_oakley.ta_integ->integ_output_size);
	if (integ_size == 0) {
		PEXPECT_LOG("error initializing integrity checksum for encrypted %s payload",
			    sk->pbs.container->name);
		return false;
	}
	sk->integrity = chunk2(sk->pbs.cur, integ_size);
	if (!out_zero(integ_size, &sk->pbs, "length of truncated HMAC/KEY")) {
		return false;
	}

	/* close the SK payload */

	sk->payload.len = sk->pbs.cur - sk->payload.ptr;
	close_output_pbs(&sk->pbs);

	return true;
}

/*
 * Form the encryption IV (a.k.a. starting variable) from the salt
 * (a.k.a. nonce) wire-iv and a counter set to 1.
 *
 * note: no iv is longer than MAX_CBC_BLOCK_SIZE
 */
static void construct_enc_iv(const char *name,
			     u_char enc_iv[],
			     u_char *wire_iv, chunk_t salt,
			     const struct encrypt_desc *encrypter)
{
	DBG(DBG_CRYPT, DBG_log("construct_enc_iv: %s: salt-size=%zd wire-IV-size=%zd block-size %zd",
			       name, encrypter->salt_size, encrypter->wire_iv_size,
			       encrypter->enc_blocksize));
	passert(salt.len == encrypter->salt_size);
	passert(encrypter->enc_blocksize <= MAX_CBC_BLOCK_SIZE);
	passert(encrypter->enc_blocksize >= encrypter->salt_size + encrypter->wire_iv_size);
	size_t counter_size = encrypter->enc_blocksize - encrypter->salt_size - encrypter->wire_iv_size;
	DBG(DBG_CRYPT, DBG_log("construct_enc_iv: %s: computed counter-size=%zd",
			       name, counter_size));

	memcpy(enc_iv, salt.ptr, salt.len);
	memcpy(enc_iv + salt.len, wire_iv, encrypter->wire_iv_size);
	if (counter_size > 0) {
		memset(enc_iv + encrypter->enc_blocksize - counter_size, 0,
		       counter_size - 1);
		enc_iv[encrypter->enc_blocksize - 1] = 1;
	}
	DBG(DBG_CRYPT, DBG_dump(name, enc_iv, encrypter->enc_blocksize));
}


stf_status encrypt_v2SK_payload(v2SK_payload_t *sk)
{
	struct ike_sa *ike = sk->ike;
	uint8_t *auth_start = sk->pbs.container->start;
	uint8_t *wire_iv_start = sk->iv.ptr;
	uint8_t *enc_start = sk->cleartext.ptr;
	uint8_t *integ_start = sk->integrity.ptr;
	size_t integ_size = sk->integrity.len;

	passert(auth_start <= wire_iv_start);
	passert(wire_iv_start <= enc_start);
	passert(enc_start <= integ_start);

	chunk_t salt;
	PK11SymKey *cipherkey;
	PK11SymKey *authkey;
	/* encrypt with our end's key */
	switch (ike->sa.st_sa_role) {
	case SA_INITIATOR:
		cipherkey = ike->sa.st_skey_ei_nss;
		authkey = ike->sa.st_skey_ai_nss;
		salt = ike->sa.st_skey_initiator_salt;
		break;
	case SA_RESPONDER:
		cipherkey = ike->sa.st_skey_er_nss;
		authkey = ike->sa.st_skey_ar_nss;
		salt = ike->sa.st_skey_responder_salt;
		break;
	default:
		bad_case(ike->sa.st_sa_role);
	}

	/* size of plain or cipher text.  */
	size_t enc_size = integ_start - enc_start;

	/* encrypt and authenticate the block */
	if (encrypt_desc_is_aead(ike->sa.st_oakley.ta_encrypt)) {
		/*
		 * Additional Authenticated Data - AAD - size.
		 * RFC5282 says: The Initialization Vector and Ciphertext
		 * fields [...] MUST NOT be included in the associated
		 * data.
		 */
		size_t wire_iv_size = ike->sa.st_oakley.ta_encrypt->wire_iv_size;
		pexpect(integ_size == ike->sa.st_oakley.ta_encrypt->aead_tag_size);
		unsigned char *aad_start = auth_start;
		size_t aad_size = enc_start - aad_start - wire_iv_size;

		DBG(DBG_CRYPT,
		    DBG_dump_hunk("Salt before authenticated encryption:", salt);
		    DBG_dump("IV before authenticated encryption:",
			     wire_iv_start, wire_iv_size);
		    DBG_dump("AAD before authenticated encryption:",
			     aad_start, aad_size);
		    DBG_dump("data before authenticated encryption:",
			     enc_start, enc_size);
		    DBG_dump("integ before authenticated encryption:",
			     integ_start, integ_size));
		if (!ike->sa.st_oakley.ta_encrypt->encrypt_ops
		    ->do_aead(ike->sa.st_oakley.ta_encrypt,
			      salt.ptr, salt.len,
			      wire_iv_start, wire_iv_size,
			      aad_start, aad_size,
			      enc_start, enc_size, integ_size,
			      cipherkey, TRUE)) {
			return STF_FAIL;
		}
		DBG(DBG_CRYPT,
		    DBG_dump("data after authenticated encryption:",
			     enc_start, enc_size);
		    DBG_dump("integ after authenticated encryption:",
			     integ_start, integ_size));
	} else {
		/* note: no iv is longer than MAX_CBC_BLOCK_SIZE */
		unsigned char enc_iv[MAX_CBC_BLOCK_SIZE];
		construct_enc_iv("encryption IV/starting-variable", enc_iv,
				 wire_iv_start, salt,
				 ike->sa.st_oakley.ta_encrypt);

		DBG(DBG_CRYPT,
		    DBG_dump("data before encryption:", enc_start, enc_size));

		/* now, encrypt */
		ike->sa.st_oakley.ta_encrypt->encrypt_ops
			->do_crypt(ike->sa.st_oakley.ta_encrypt,
				   enc_start, enc_size,
				   cipherkey,
				   enc_iv, TRUE);

		DBG(DBG_CRYPT,
		    DBG_dump("data after encryption:", enc_start, enc_size));
		/* note: saved_iv's updated value is discarded */

		/* okay, authenticate from beginning of IV */
		struct crypt_prf *ctx = crypt_prf_init_symkey("integ", ike->sa.st_oakley.ta_integ->prf,
							      "authkey", authkey);
		crypt_prf_update_bytes(ctx, "message", auth_start, integ_start - auth_start);
		passert(integ_size == ike->sa.st_oakley.ta_integ->integ_output_size);
		struct crypt_mac mac = crypt_prf_final_mac(&ctx, ike->sa.st_oakley.ta_integ);
		memcpy_hunk(integ_start, mac, integ_size);

		DBG(DBG_CRYPT, {
			    DBG_dump("data being hmac:", auth_start,
				     integ_start - auth_start);
			    DBG_dump("out calculated auth:", integ_start, integ_size);
		    });
	}

	return STF_OK;
}

/*
 * ikev2_decrypt_msg: decode the payload.
 * The result is stored in-place.
 * Calls ikev2_process_payloads to decode the payloads within.
 *
 * This code assumes that the encrypted part of an IKE message starts
 * with an Initialization Vector (IV) of WIRE_IV_SIZE random octets.
 * We will discard the IV after decryption.
 *
 * The (optional) salt, wire-iv, and (optional) 1 are combined to form
 * the actual starting-variable (a.k.a. IV).
 */

static bool ikev2_verify_and_decrypt_sk_payload(struct ike_sa *ike,
						struct msg_digest *md,
						chunk_t *chunk,
						unsigned int iv)
{
	if (!ike->sa.hidden_variables.st_skeyid_calculated) {
		endpoint_buf b;
		PEXPECT_LOG("received encrypted packet from %s  but no exponents for state #%lu to decrypt it",
			    str_endpoint(&md->sender, &b),
			    ike->sa.st_serialno);
		return false;
	}

	u_char *wire_iv_start = chunk->ptr + iv;
	size_t wire_iv_size = ike->sa.st_oakley.ta_encrypt->wire_iv_size;
	size_t integ_size = (encrypt_desc_is_aead(ike->sa.st_oakley.ta_encrypt)
			     ? ike->sa.st_oakley.ta_encrypt->aead_tag_size
			     : ike->sa.st_oakley.ta_integ->integ_output_size);

	/*
	 * check to see if length is plausible:
	 * - wire-IV
	 * - encoded data (possibly empty)
	 * - at least one padding-length byte
	 * - truncated integrity digest / tag
	 */
	u_char *payload_end = chunk->ptr + chunk->len;
	if (payload_end < (wire_iv_start + wire_iv_size + 1 + integ_size)) {
		libreswan_log("encrypted payload impossibly short (%tu)",
			      payload_end - wire_iv_start);
		return false;
	}

	u_char *auth_start = chunk->ptr;
	u_char *enc_start = wire_iv_start + wire_iv_size;
	u_char *integ_start = payload_end - integ_size;
	size_t enc_size = integ_start - enc_start;

	/*
	 * Check that the payload is block-size aligned.
	 *
	 * Per rfc7296 "the recipient MUST accept any length that
	 * results in proper alignment".
	 *
	 * Do this before the payload's integrity has been verified as
	 * block-alignment requirements aren't exactly secret
	 * (originally this was being done between integrity and
	 * decrypt).
	 */
	size_t enc_blocksize = ike->sa.st_oakley.ta_encrypt->enc_blocksize;
	bool pad_to_blocksize = ike->sa.st_oakley.ta_encrypt->pad_to_blocksize;
	if (pad_to_blocksize) {
		if (enc_size % enc_blocksize != 0) {
			libreswan_log("discarding invalid packet: %zu octet payload length is not a multiple of encryption block-size (%zu)",
				      enc_size, enc_blocksize);
			return false;
		}
	}

	chunk_t salt;
	PK11SymKey *cipherkey;
	PK11SymKey *authkey;
	switch (ike->sa.st_sa_role) {
	case SA_INITIATOR:
		/* need responders key */
		cipherkey = ike->sa.st_skey_er_nss;
		authkey = ike->sa.st_skey_ar_nss;
		salt = ike->sa.st_skey_responder_salt;
		break;
	case SA_RESPONDER:
		/* need initiators key */
		cipherkey = ike->sa.st_skey_ei_nss;
		authkey = ike->sa.st_skey_ai_nss;
		salt = ike->sa.st_skey_initiator_salt;
		break;
	default:
		bad_case(ike->sa.st_sa_role);
	}

	/* authenticate and decrypt the block. */
	if (encrypt_desc_is_aead(ike->sa.st_oakley.ta_encrypt)) {
		/*
		 * Additional Authenticated Data - AAD - size.
		 * RFC5282 says: The Initialization Vector and Ciphertext
		 * fields [...] MUST NOT be included in the associated
		 * data.
		 */
		unsigned char *aad_start = auth_start;
		size_t aad_size = enc_start - auth_start - wire_iv_size;

		DBG(DBG_CRYPT,
		    DBG_dump_hunk("Salt before authenticated decryption:", salt);
		    DBG_dump("IV before authenticated decryption:",
			     wire_iv_start, wire_iv_size);
		    DBG_dump("AAD before authenticated decryption:",
			     aad_start, aad_size);
		    DBG_dump("data before authenticated decryption:",
			     enc_start, enc_size);
		    DBG_dump("integ before authenticated decryption:",
			     integ_start, integ_size));
		if (!ike->sa.st_oakley.ta_encrypt->encrypt_ops
		    ->do_aead(ike->sa.st_oakley.ta_encrypt,
			      salt.ptr, salt.len,
			      wire_iv_start, wire_iv_size,
			      aad_start, aad_size,
			      enc_start, enc_size, integ_size,
			      cipherkey, FALSE)) {
			return false;
		}
		DBG(DBG_CRYPT,
		    DBG_dump("data after authenticated decryption:",
			     enc_start, enc_size + integ_size));
	} else {
		/*
		 * check authenticator.  The last INTEG_SIZE bytes are
		 * the truncated digest.
		 */
		struct crypt_prf *ctx = crypt_prf_init_symkey("auth", ike->sa.st_oakley.ta_integ->prf,
							      "authkey", authkey);
		crypt_prf_update_bytes(ctx, "message", auth_start, integ_start - auth_start);
		struct crypt_mac td = crypt_prf_final_mac(&ctx, ike->sa.st_oakley.ta_integ);

		if (!hunk_memeq(td, integ_start, integ_size)) {
			libreswan_log("failed to match authenticator");
			return false;
		}

		dbg("authenticator matched");

		/* decrypt */

		/* note: no iv is longer than MAX_CBC_BLOCK_SIZE */
		unsigned char enc_iv[MAX_CBC_BLOCK_SIZE];
		construct_enc_iv("decryption IV/starting-variable", enc_iv,
				 wire_iv_start, salt,
				 ike->sa.st_oakley.ta_encrypt);

		DBG(DBG_CRYPT,
		    DBG_dump("payload before decryption:", enc_start, enc_size));
		ike->sa.st_oakley.ta_encrypt->encrypt_ops
			->do_crypt(ike->sa.st_oakley.ta_encrypt,
				   enc_start, enc_size,
				   cipherkey,
				   enc_iv, FALSE);
		DBG(DBG_CRYPT,
		    DBG_dump("payload after decryption:", enc_start, enc_size));
	}

	/*
	 * Check the padding.
	 *
	 * Per rfc7296 "The sender SHOULD set the Pad Length to the
	 * minimum value that makes the combination of the payloads,
	 * the Padding, and the Pad Length a multiple of the block
	 * size, but the recipient MUST accept any length that results
	 * in proper alignment."
	 *
	 * Notice the "should".  RACOON, for instance, sends extra
	 * blocks of padding that contain random bytes.
	 */
	uint8_t padlen = enc_start[enc_size - 1] + 1;
	if (padlen > enc_size) {
		libreswan_log("discarding invalid packet: padding-length %u (octet 0x%02x) is larger than %zu octet payload length",
			      padlen, padlen - 1, enc_size);
		return false;
	}
	if (pad_to_blocksize) {
		if (padlen > enc_blocksize) {
			/* probably racoon */
			DBG(DBG_CRYPT,
			    DBG_log("payload contains %zu blocks of extra padding (padding-length: %d (octet 0x%2x), encryption block-size: %zu)",
				    (padlen - 1) / enc_blocksize,
				    padlen, padlen - 1, enc_blocksize));
		}
	} else {
		if (padlen > 1) {
			DBG(DBG_CRYPT,
			    DBG_log("payload contains %u octets of extra padding (padding-length: %u (octet 0x%2x))",
				    padlen - 1, padlen, padlen - 1));
		}
	}

	/*
	 * Don't check the contents of the pad octets; racoon, for
	 * instance, sets them to random values.
	 */
	DBG(DBG_CRYPT, DBG_log("stripping %u octets as pad", padlen));
	*chunk = chunk2(enc_start, enc_size - padlen);

	return true;
}

/*
 * Since the fragmented packet is intended for ST (either an IKE or
 * CHILD SA), ST contains the fragments.
 */
static bool ikev2_reassemble_fragments(struct state *st,
				       struct msg_digest *md)
{
	if (md->chain[ISAKMP_NEXT_v2SK] != NULL) {
		PEXPECT_LOG("state #%lu has both SK ans SKF payloads",
			    st->st_serialno);
		return false;
	}

	if (md->digest_roof >= elemsof(md->digest)) {
		libreswan_log("packet contains too many payloads; discarded");
		return false;
	}

	struct v2_incomming_fragments **frags = &st->st_v2_incomming[v2_msg_role(md)];
	passert(*frags != NULL);

	chunk_t plain[MAX_IKE_FRAGMENTS + 1];
	passert(elemsof(plain) == elemsof((*frags)->frags));
	unsigned int size = 0;
	for (unsigned i = 1; i <= (*frags)->total; i++) {
		struct v2_incomming_fragment *frag = &(*frags)->frags[i];
		/*
		 * Point PLAIN at the encrypted fragment and then
		 * decrypt in-place.  After the decryption, PLAIN will
		 * have been adjusted to just point at the data.
		 */
		plain[i] = frag->cipher;
		if (!ikev2_verify_and_decrypt_sk_payload(ike_sa(st, HERE), md,
							 &plain[i], frag->iv)) {
			loglog(RC_LOG_SERIOUS, "fragment %u of %u invalid",
			       i, (*frags)->total);
			free_v2_incomming_fragments(frags);
			return false;
		}
		size += plain[i].len;
	}

	/*
	 * All the fragments have been disassembled, re-assemble them
	 * into the .raw_packet buffer.
	 */
	pexpect(md->raw_packet.ptr == NULL); /* empty */
	md->raw_packet = alloc_chunk(size, "IKEv2 fragments buffer");
	unsigned int offset = 0;
	for (unsigned i = 1; i <= (*frags)->total; i++) {
		passert(offset + plain[i].len <= size);
		memcpy(md->raw_packet.ptr + offset, plain[i].ptr,
		       plain[i].len);
		offset += plain[i].len;
	}

	/*
	 * Fake up enough of an SK payload_digest to fool the caller
	 * and then use that to scribble all over the SKF
	 * payload_digest (remembering to also update the SK and SKF
	 * chains).
	 */
	struct payload_digest sk = {
		.pbs = same_chunk_as_in_pbs(md->raw_packet, "decrypted SFK payloads"),
		.payload_type = ISAKMP_NEXT_v2SK,
		.payload.generic.isag_np = (*frags)->first_np,
	};
	struct payload_digest *skf = md->chain[ISAKMP_NEXT_v2SKF];
	md->chain[ISAKMP_NEXT_v2SKF] = NULL;
	md->chain[ISAKMP_NEXT_v2SK] = skf;
	*skf = sk; /* scribble */

	free_v2_incomming_fragments(frags);

	return true;
}

/*
 * Decrypt the, possibly fragmented message intended for ST.
 *
 * Since the message fragments are stored in the recipient's ST
 * (either IKE or CHILD SA), it, and not the IKE SA is needed.
 */
bool ikev2_decrypt_msg(struct state *st, struct msg_digest *md)
{
	bool ok;
	if (md->chain[ISAKMP_NEXT_v2SKF] != NULL) {
		/*
		 * ST points at the state (parent or child) that has
		 * all the fragments.
		 */
		ok = ikev2_reassemble_fragments(st, md);
	} else {
		pb_stream *e_pbs = &md->chain[ISAKMP_NEXT_v2SK]->pbs;
		/*
		 * If so impaired, clone the encrypted message before
		 * it gets decrypted in-place (but only once).
		 */
		if (impair.replay_encrypted && !md->fake_clone) {
			libreswan_log("IMPAIR: cloning incoming encrypted message and scheduling its replay");
			schedule_md_event("replay encrypted message",
					  clone_raw_md(md, "copy of encrypted message"));
		}
		if (impair.corrupt_encrypted && !md->fake_clone) {
			libreswan_log("IMPAIR: corrupting incoming encrypted message's SK payload's first byte");
			*e_pbs->cur = ~(*e_pbs->cur);
		}

		chunk_t c = chunk2(md->packet_pbs.start,
				  e_pbs->roof - md->packet_pbs.start);
		ok = ikev2_verify_and_decrypt_sk_payload(ike_sa(st, HERE), md, &c,
							 e_pbs->cur - md->packet_pbs.start);
		md->chain[ISAKMP_NEXT_v2SK]->pbs = same_chunk_as_in_pbs(c, "decrypted SK payload");
	}

	dbg("#%lu ikev2 %s decrypt %s",
	    st->st_serialno,
	    enum_name(&ikev2_exchange_names, md->hdr.isa_xchg),
	    ok ? "success" : "failed");

	return ok;
}

/*
 * IKEv2 fragments:
 *
 *                        1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   | Next Payload  |C|  RESERVED   |         Payload Length        |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |        Fragment Number        |        Total Fragments        |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                     Initialization Vector                     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   ~                      Encrypted content                        ~
 *   +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |               |             Padding (0-255 octets)            |
 *   +-+-+-+-+-+-+-+-+                               +-+-+-+-+-+-+-+-+
 *   |                                               |  Pad Length   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   ~                    Integrity Checksum Data                    ~
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *

 *
 */

static bool record_outbound_fragment(struct logger *logger,
				     struct ike_sa *ike,
				     const struct isakmp_hdr *hdr,
				     enum next_payload_types_ikev2 skf_np,
				     struct v2_outgoing_fragment **fragp,
				     chunk_t *fragment,	/* read-only */
				     unsigned int number, unsigned int total,
				     const char *desc)
{
	/* make sure HDR is at start of a clean buffer */
	unsigned char frag_buffer[PMAX(MIN_MAX_UDP_DATA_v4, MIN_MAX_UDP_DATA_v6)];
	struct pbs_out frag_stream = open_pbs_out("reply frag packet",
						  frag_buffer, sizeof(frag_buffer),
						  logger);

	/* HDR out */

	pb_stream rbody;
	if (!out_struct(hdr, &isakmp_hdr_desc, &frag_stream,
			&rbody))
		return false;

	/*
	 * Fake up an SK payload description sufficient to fool the
	 * encryption code.
	 *
	 * While things are close, they are not identical - an SKF
	 * payload header has extra fields and, for the first
	 * fragment, forces the Next Payload.
	 */

	v2SK_payload_t skf = {
		.ike = ike,
		.payload = {
		    .ptr = rbody.cur,
		    .len = 0 /* computed at end; set here to silence GCC 4.8.5 */
		}
	};

	/*
	 * emit SKF header, save location.
	 *
	 * In the first fragment, .NP is set to the SK payload's next
	 * payload type.
	 */

	const struct ikev2_skf e = {
		.isaskf_np = skf_np, /* needed */
		.isaskf_critical = build_ikev2_critical(false),
		.isaskf_number = number,
		.isaskf_total = total,
	};
	if (!out_struct(&e, &ikev2_skf_desc, &rbody, &skf.pbs))
		return false;

	/* emit IV and save location */

	if (!emit_v2SK_iv(&skf)) {
		log_message(RC_LOG, logger,
			    "error initializing IV for encrypted %s message",
			    desc);
		return false;
	}

	/* save cleartext start */

	skf.cleartext.ptr = skf.pbs.cur;

	/* output the fragment */

	if (!pbs_out_hunk(*fragment, &skf.pbs,
			  "cleartext fragment"))
		return false;

	if (!close_v2SK_payload(&skf)) {
		return false;
	}

	close_output_pbs(&rbody);
	close_output_pbs(&frag_stream);

	stf_status ret = encrypt_v2SK_payload(&skf);
	if (ret != STF_OK) {
		log_message(RC_LOG, logger, "error encrypting fragment %u", number);
		return false;
	}

	dbg("recording fragment %u", number);
	record_v2_outgoing_fragment(&frag_stream, desc, fragp);
	return true;
}

static bool record_outbound_fragments(const pb_stream *rbody,
				      v2SK_payload_t *sk,
				      const char *desc,
				      struct v2_outgoing_fragment **frags)
{
	free_v2_outgoing_fragments(frags);

	/*
	 * fragment contents:
	 * - sometimes:	NON_ESP_MARKER (RFC3948) (NON_ESP_MARKER_SIZE) (4)
	 * - always:	isakmp header (NSIZEOF_isakmp_hdr) (28)
	 * - always:	ikev2_skf header (NSIZEOF_ikev2_skf) (8)
	 * - variable:	IV (no IV is longer than SHA2_512_DIGEST_SIZE) (64 or less)
	 * - variable:	fragment's data
	 * - variable:	padding (no padding is longer than MAX_CBC_BLOCK_SIZE) (16 or less)
	 */

	/*
	 * XXX: this math seems very contrived, can the fragment()
	 * function above be left to do the computation on-the-fly?
	 */

	unsigned int len = endpoint_type(&sk->ike->sa.st_remote_endpoint)->ikev2_max_fragment_size;

	/*
	 * If we are doing NAT, so that the other end doesn't mistake
	 * this message for ESP, each message needs a non-ESP_Marker
	 * prefix.
	 */
	if (sk->ike->sa.st_interface != NULL && sk->ike->sa.st_interface->esp_encapsulation_enabled)
		len -= NON_ESP_MARKER_SIZE;

	len -= NSIZEOF_isakmp_hdr + NSIZEOF_ikev2_skf;

	len -= (encrypt_desc_is_aead(sk->ike->sa.st_oakley.ta_encrypt)
		? sk->ike->sa.st_oakley.ta_encrypt->aead_tag_size
		: sk->ike->sa.st_oakley.ta_integ->integ_output_size);

	if (sk->ike->sa.st_oakley.ta_encrypt->pad_to_blocksize)
		len &= ~(sk->ike->sa.st_oakley.ta_encrypt->enc_blocksize - 1);

	len -= 2;	/* ??? what's this? */

	passert(sk->cleartext.len != 0);

	unsigned int nfrags = (sk->cleartext.len + len - 1) / len;

	if (nfrags > MAX_IKE_FRAGMENTS) {
		log_message(RC_LOG_SERIOUS, sk->logger,
			    "fragmenting this %zu byte message into %u byte chunks leads to too many frags",
			    sk->cleartext.len, len);
		return false;
	}

	/*
	 * Extract the hdr from the original unfragmented message.
	 * Set it up for auto-update of it's next payload field chain.
	 */
	struct isakmp_hdr hdr;
	{
		pb_stream pbs;
		init_pbs(&pbs, rbody->start, pbs_offset(rbody), "sk hdr");
		if (!in_struct(&hdr, &isakmp_hdr_desc, &pbs, NULL)) {
			return false;
		}
	}
	hdr.isa_np = ISAKMP_NEXT_v2NONE; /* clear NP */

	/*
	 * Extract the SK's next payload field from the original
	 * unfragmented message.  This is used as the first SKF's NP
	 * field, the rest have NP=NONE(0).
	 */
	enum next_payload_types_ikev2 skf_np;
	{
		pb_stream pbs = same_chunk_as_in_pbs(sk->payload, "sk");
		struct ikev2_generic e;
		if (!in_struct(&e, &ikev2_sk_desc, &pbs, NULL)) {
			return false;
		}
		skf_np = e.isag_np;
	}

	unsigned int number = 1;
	unsigned int offset = 0;

	struct v2_outgoing_fragment **frag = frags;
	while (true) {
		passert(*frag == NULL);
		chunk_t fragment = chunk2(sk->cleartext.ptr + offset,
					  PMIN(sk->cleartext.len - offset, len));
		if (!record_outbound_fragment(sk->logger, sk->ike, &hdr, skf_np, frag,
					      &fragment, number, nfrags, desc)) {
			return false;
		}
		frag = &(*frag)->next;

		offset += fragment.len;
		number++;
		skf_np = ISAKMP_NEXT_v2NONE;

		if (offset >= sk->cleartext.len) {
			break;
		}
	}

	return true;
}

/*
 * Record the message ready for sending.  If needed, first fragment
 * it.
 *
 * ST is where to save the outgoing message.  XXX: Currently it is
 * always the parent.  But that breaks when trying to juggle multiple
 * children trying to exchange messages.
 */

stf_status record_v2SK_message(pb_stream *msg,
			       v2SK_payload_t *sk,
			       const char *what,
			       enum message_role message)
{
	size_t len = pbs_offset(msg);

	/*
	 * If we are doing NAT, so that the other end doesn't mistake
	 * this message for ESP, each message needs a non-ESP_Marker
	 * prefix.
	 */
	if (!pexpect(sk->ike->sa.st_interface != NULL) &&
	    sk->ike->sa.st_interface->esp_encapsulation_enabled)
		len += NON_ESP_MARKER_SIZE;

	/* IPv4 and IPv6 have different fragment sizes */
	if (sk->ike->sa.st_interface->protocol == &ip_protocol_udp &&
	    LIN(POLICY_IKE_FRAG_ALLOW, sk->ike->sa.st_connection->policy) &&
	    sk->ike->sa.st_seen_fragmentation_supported &&
	    len >= endpoint_type(&sk->ike->sa.st_remote_endpoint)->ikev2_max_fragment_size) {
		struct v2_outgoing_fragment **frags = &sk->ike->sa.st_v2_outgoing[message];
		if (!record_outbound_fragments(msg, sk, what, frags)) {
			dbg("record outbound fragments failed");
			return STF_INTERNAL_ERROR;
		}
	} else {
		if (encrypt_v2SK_payload(sk) != STF_OK) {
			log_message(RC_LOG, sk->logger,
				    "error encrypting %s message", what);
			return STF_INTERNAL_ERROR;
		}
		dbg("recording outgoing fragment failed");
		record_v2_message(sk->ike, msg, what, message);
	}
	return STF_OK;
}

struct ikev2_id build_v2_id_payload(const struct end *end, shunk_t *body,
				    const char *what, struct logger *logger)
{
	struct ikev2_id id_header = {
		.isai_type = id_to_payload(&end->id, &end->host_addr, body),
		.isai_critical = build_ikev2_critical(false),
	};
	if (impair.send_nonzero_reserved_id) {
		log_message(RC_LOG, logger, "IMPAIR: setting reserved byte 3 of %s to 0x%02x",
			    what, ISAKMP_PAYLOAD_LIBRESWAN_BOGUS);
		id_header.isai_res3 = ISAKMP_PAYLOAD_LIBRESWAN_BOGUS;
	}
	return id_header;
}
