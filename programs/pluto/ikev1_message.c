/* IKEv1 message contents, for libreswan
 *
 * Copyright (C) 2019 Andrew Cagney
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

#include "shunk.h"
#include "id.h"

#include "connections.h"
#include "packet.h"
#include "ikev1_message.h"
#include "diag.h"
#include "lswlog.h"
#include "unpack.h"
#include "demux.h"
#include "crypt_ke.h"
#include "crypt_cipher.h"
#include "crypt_hash.h"

struct isakmp_ipsec_id build_v1_id_payload(const struct host_end *end, shunk_t *body)
{
	struct isakmp_ipsec_id id_hd = {
		.isaiid_idtype = id_to_payload(&end->id, &end->addr, body),
	};
	return id_hd;
}

bool out_raw(const void *bytes, size_t len, struct pbs_out *outs, const char *name)
{
	if (!pbs_out_raw(outs, bytes, len, name)) {
		/* already logged */
		return false;
	}
	return true;
}

bool ikev1_justship_nonce(chunk_t *n, struct pbs_out *outs,
			  const char *name)
{
	return ikev1_out_generic_chunk(&isakmp_nonce_desc, outs, *n, name);
}

bool ikev1_ship_nonce(chunk_t *n, chunk_t *nonce,
		      struct pbs_out *outs, const char *name)
{
	unpack_nonce(n, nonce);
	return ikev1_justship_nonce(n, outs, name);
}

v1_notification_t accept_v1_nonce(struct logger *logger,
				  struct msg_digest *md, chunk_t *dest,
				  const char *name)
{
	struct pbs_in *nonce_pbs = &md->chain[ISAKMP_NEXT_NONCE]->pbs;
	size_t len = pbs_left(nonce_pbs);

	if (len < IKEv1_MINIMUM_NONCE_SIZE || IKEv1_MAXIMUM_NONCE_SIZE < len) {
		llog(RC_LOG, logger, "%s length not between %d and %d",
			    name, IKEv1_MINIMUM_NONCE_SIZE, IKEv1_MAXIMUM_NONCE_SIZE);
		return v1N_PAYLOAD_MALFORMED; /* ??? */
	}
	replace_chunk(dest, pbs_in_left(nonce_pbs), "nonce");
	passert(len == dest->len);
	return v1N_NOTHING_WRONG;
}

/*
 * package up the calculate KE value, and emit it as a KE payload.
 * used by IKEv1: main, aggressive, and quick (in PFS mode).
 */
bool ikev1_justship_KE(struct logger *logger, chunk_t *g, struct pbs_out *outs)
{
	switch (impair.ke_payload) {
	case IMPAIR_EMIT_NO:
		return ikev1_out_generic_chunk(&isakmp_keyex_desc, outs, *g,
					       "keyex value");
	case IMPAIR_EMIT_OMIT:
		llog(RC_LOG, logger, "IMPAIR: sending no KE (g^x) payload");
		return true;
	case IMPAIR_EMIT_EMPTY:
		llog(RC_LOG, logger, "IMPAIR: sending empty KE (g^x)");
		return ikev1_out_generic_chunk(&isakmp_keyex_desc, outs,
					       EMPTY_CHUNK, "empty KE");
	default:
	{
		struct pbs_out z;
		uint8_t byte = impair.ke_payload - IMPAIR_EMIT_ROOF;
		llog(RC_LOG, logger, "IMPAIR: sending bogus KE (g^x) == %u value to break DH calculations", byte);
		/* Only used to test sending/receiving bogus g^x */
		return ikev1_out_generic(&isakmp_keyex_desc, outs, &z) &&
			pbs_out_repeated_byte(&z, byte, g->len, "fake g^x") &&
			(close_output_pbs(&z), true);
	}
	}
}

bool ikev1_ship_KE(struct state *st, struct dh_local_secret *local_secret,
		   chunk_t *g, struct pbs_out *outs)
{
	unpack_KE_from_helper(st, local_secret, g);
	return ikev1_justship_KE(st->logger, g, outs);
}

/*
 * In IKEv1, some implementations (including freeswan/openswan/libreswan)
 * interpreted the RFC that the whole IKE message must padded to a multiple
 * of 4 octets, but other implementations (i.e. Checkpoint in Aggressive Mode)
 * drop padded IKE packets. Some of the text on this topic can be found in the
 * IKEv1 RFC 2408 section 3.6 Transform Payload.
 *
 * The ikepad= option can be set to yes or no on a per-connection basis,
 * and defaults to yes.
 *
 * In IKEv2, there is no padding specified in the RFC and some implementations
 * will reject IKEv2 messages that are padded. As there are no known IKEv2
 * clients that REQUIRE padding, padding is never done for IKEv2. If IKEv2
 * clients are discovered in the wild, we will revisit this - please contact
 * the libreswan developers if you find such an implementation.
 * Therefore the ikepad= option has no effect on IKEv2 connections.
 *
 * @param pbs PB Stream
 */

static bool emit_v1_message_padding(struct pbs_out *pbs, const struct ike_sa *ike)
{
	size_t padding = pad_up(pbs_out_all(pbs).len, 4);
	if (padding == 0) {
		ldbg(pbs->logger, "no IKEv1 message padding required");
	} else if (!ike->sa.st_connection->config->ikepad) {
		ldbg(pbs->logger, "IKEv1 message padding of %zu bytes skipped by policy",
		     padding);
	} else {
		ldbg(pbs->logger, "padding IKEv1 message with %zu bytes", padding);
		if (!pbs_out_zero(pbs, padding, "message padding")) {
			/* already logged */
			return false; /*fatal*/
		}
	}
	return true;
}

bool close_v1_message(struct pbs_out *pbs, const struct ike_sa *ike)
{
	if (pbad(ike == NULL)) {
		return false;
	}

	if (!emit_v1_message_padding(pbs, ike)) {
		/* already logged */
		return false; /*fatal*/
	}

	close_output_pbs(pbs);
	return true;
}

/*
 * encrypt message, sans fixed part of header
 * IV is fetched from st->st_new_iv and stored into st->st_iv.
 * The theory is that there will be no "backing out", so we commit to IV.
 * We also close the pbs.
 */

bool close_and_encrypt_v1_message(struct ike_sa *ike,
				  struct pbs_out *pbs,
				  struct crypt_mac *iv)
{
	struct logger *logger = pbs->logger;
	const struct encrypt_desc *e = ike->sa.st_oakley.ta_encrypt;

	/*
	 * Pad the message (header and body) to message alignment
	 * which is normally 4-bytes.
	 */

	if (!emit_v1_message_padding(pbs, ike)) {
		/* already logged */
		return false; /*fatal*/
	}

	/*
	 * Next pad the encrypted part of the payload so it is
	 * alligned with the encryption's blocksize.
	 *
	 * Since the header is isn't encrypted, this doesn't include
	 * the header.  See the description associated with the
	 * definition of struct isakmp_hdr in packet.h.
	 *
	 * The alignment is probably 16-bytes, but can be 1-byte!
	 */
	shunk_t message = pbs_out_all(pbs);
	shunk_t unpadded_encrypt = hunk_slice(message, sizeof(struct isakmp_hdr), message.len);
	size_t encrypt_padding = pad_up(unpadded_encrypt.len, e->enc_blocksize);
	if (encrypt_padding != 0) {
		if (!pbs_out_zero(pbs, encrypt_padding, "encryption padding")) {
			/* already logged */
			return false; /*fatal*/
		}
	}

	/*
	 * Now mark out the block that will be encrypted.
	 *
	 * Hack to get at writeable buffer!  IKEv2 does something
	 * vaguely similar.
	 */
	chunk_t padded_message = chunk2(pbs->start, pbs_out_all(pbs).len);
	chunk_t padded_encrypt = hunk_slice(padded_message,
					    sizeof(struct isakmp_hdr),
					    padded_message.len);

	/*
	 * Finally, re-pad the entire message (header and body) to
	 * message alignment.
	 *
	 * This should be a no-op?
	 *
	 * XXX: note the double padding (triple if you count the code
	 * paths that call ikev1_close_message() before encrypting.
	 */

	if (!emit_v1_message_padding(pbs, ike)) {
		/* already logged */
		return false; /*fatal*/
	}

	close_output_pbs(pbs);

	/* XXX: not ldbg(pbs->logger) as can be NULL */
	dbg("encrypt unpadded %zu padding %zu padded %zu bytes",
	    unpadded_encrypt.len, encrypt_padding, padded_encrypt.len);
	if (LDBGP(DBG_CRYPT, logger)) {
		LDBG_log(logger, "encrypting:");
		LDBG_hunk(logger, padded_encrypt);
		LDBG_log(logger, "IV:");
		LDBG_hunk(logger, *iv);
	}

	/*
	 * The IV is always truncated down to .enc_blocksize.
	 */
	PASSERT(logger, iv->len == e->enc_blocksize);

	cipher_ikev1(e, ENCRYPT, padded_encrypt,
		     iv, ike->sa.st_enc_key_nss,
		     logger);

	if (LDBGP(DBG_CRYPT, logger)) {
		LDBG_log(logger, "next IV:");
		LDBG_hunk(logger, *iv);
	}

	return true;
}

/*
 * Compute Phase 2 IV.
 *
 * Uses Phase 1 IV from st_iv; puts result in st_new_iv.
 */

struct crypt_mac new_phase2_iv(const struct ike_sa *ike,
			       const msgid_t msgid,
			       const char *why, where_t where)
{
	struct logger *logger = ike->sa.logger;
	const struct encrypt_desc *e = ike->sa.st_oakley.ta_encrypt;

	pdbg(logger, "phase2_iv: %s "PRI_WHERE, why, pri_where(where));

	const struct hash_desc *h = ike->sa.st_oakley.ta_prf->hasher;
	PASSERT_WHERE(logger, where, h != NULL);
	struct crypt_hash *ctx = crypt_hash_init("Phase 2 IV", h, logger);

	/*
	 * Start with the Phase 1 IV.
	 *
	 * This is the output block from the last encrypt/decrypt
	 * operation.  Hence, it is .enc_blocksize long.
	 */
	PASSERT_WHERE(logger, where, ike->sa.st_v1_phase_1_iv.len == e->enc_blocksize);
	crypt_hash_digest_hunk(ctx, "Phase 1 IV", ike->sa.st_v1_phase_1_iv);

	/* plus the MSGID in network order */
	PASSERT_WHERE(logger, where, sizeof(msgid_t) == sizeof(uint32_t));
	PASSERT_WHERE(logger, where, msgid > 0); /* i.e., not Phase 1! */
	msgid_t raw_msgid = htonl(msgid);
	crypt_hash_digest_thing(ctx, "Message ID", raw_msgid);

	/* save in new */
	struct crypt_mac iv = crypt_hash_final_mac(&ctx);

	/*
	 * The Phase 2 IV.
	 *
	 * Again, this is the size of an encryption block, ready for
	 * feeding into the encryption algorithm.
	 */
	PASSERT_WHERE(ike->sa.logger, where, iv.len >= e->enc_blocksize);
	iv.len = e->enc_blocksize;   /* truncate */

	return iv;
}

void update_v1_phase_1_iv(struct ike_sa *ike, struct crypt_mac iv, where_t where)
{
	LDBGP_JAMBUF(DBG_BASE, ike->sa.logger, buf) {
		jam_string(buf, "updating Phase 1 IV .st_v1_phase_1_iv from ");
		jam_hex_hunk(buf, ike->sa.st_v1_phase_1_iv);
		jam_string(buf, " to ");
		jam_hex_hunk(buf, iv);
		jam_string(buf, " ");
		jam_where(buf, where);
	}

	/*
	 * The Phase 1 IV, is always truncated down to the
	 * .enc_blocksize.
	 */
	const struct encrypt_desc *e = ike->sa.st_oakley.ta_encrypt;
	PASSERT_WHERE(ike->sa.logger, where, iv.len == e->enc_blocksize);

	ike->sa.st_v1_phase_1_iv = iv;
}
