/* Support of X.509 certificates and CRLs for libreswan
 *
 * Copyright (C) 2000 Andreas Hess, Patric Lichtsteiner, Roger Wegmann
 * Copyright (C) 2001 Marco Bertossa, Andreas Schleiss
 * Copyright (C) 2002 Mario Strasser
 * Copyright (C) 2000-2004 Andreas Steffen, Zuercher Hochschule Winterthur
 * Copyright (C) 2006-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009 Gilles Espinasse <g.esp@free.fr>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 Kim B. Heino <b@bbbs.net>
 * Copyright (C) 2018-2019,2022 Andrew Cagney
 * Copyright (C) 2018 Sahana Prasad <sahana.prasad07@gmail.com>
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

#include "lswnss.h"
#include "asn1.h"
#include "crypt_hash.h"
#include "ike_alg_hash.h"

#include "defs.h"

#include "ikev2_certreq.h"
#include "demux.h"
#include "state.h"
#include "connections.h"
#include "log.h"
#include "pluto_x509.h"

/*
 * https://www.rfc-editor.org/rfc/rfc4945#section-3.2.6
 *
 *   When in-band exchange of certificate keying materials is desired,
 *   implementations MUST inform the peer of this by sending at least one
 *   CERTREQ.  In other words, an implementation that does not send any
 *   CERTREQs during an exchange SHOULD NOT expect to receive any CERT
 *   payloads.
 *
 * i.e., the absence of CERTREQ is a hint to not send certs
 *
 * https://datatracker.ietf.org/doc/html/rfc7296#section-3.7
 * 3.7.  Certificate Request Payload
 *
 *   The Certificate Encoding field has the same values as those
 *   defined in Section 3.6.  The Certification Authority field
 *   contains an indicator of trusted authorities for this certificate
 *   type.  The Certification Authority value is a concatenated list
 *   of SHA-1 hashes of the public keys of trusted Certification
 *   Authorities (CAs).  Each is encoded as the SHA-1 hash of the
 *   Subject Public Key Info element (see Section 4.1.2.7 of [PKIX])
 *   from each Trust Anchor certificate.  The 20-octet hashes are
 *   concatenated and included with no other formatting.
 *
 * The code below hashes the .derPublicKey field; correct?
 */

void process_v2CERTREQ_payload(struct ike_sa *ike, struct msg_digest *md)
{
	/* XXX: there should only be one! */
	struct payload_digest *p = md->chain[ISAKMP_NEXT_v2CERTREQ];
	if (p == NULL) {
		ldbg(ike->sa.st_logger, "no CERTREQ");
		return;
	}

	if (p->next != NULL) {
		ldbg(ike->sa.st_logger, "ignoring duplicate CERTREQ");
		/* stumble on */
	}

	const struct ikev2_certreq *const cr = &p->payload.v2certreq;
	switch (cr->isacertreq_enc) {
	case CERT_X509_SIGNATURE:
	{
		struct pbs_in pbs = p->pbs;
		unsigned count = 0;
		/*
		 * https://www.rfc-editor.org/rfc/rfc4945#section-3.2.7.2
		 * 3.2.7.2.  Empty Certification Authority Field
		 *
		 * i.e., during IKE_SA_INIT, the responder has no clue
		 * as to the initiator's true identity and hence no
		 * clue as to which cert chain to ask for.  As a
		 * work-around allow empty CERTREQ payloads.
		 */
		while (pbs_in_remaining(&pbs) > 0) {
			ckaid_t hash = { .len = SHA1_DIGEST_SIZE, /*see RFC*/};
			diag_t d = pbs_in_raw(&pbs, hash.ptr, hash.len, "Certification Authority hash");
			if (d != NULL) {
				llog_diag(RC_LOG_SERIOUS, ike->sa.st_logger, &d,
					  "ignoring CERTREQ payload: ");
				return;
			}
			count++;
		}
		ldbg(ike->sa.st_logger, "found %d CERTREQ Certification Authority hashes", count);
		/* both are non-zero */
		ike->sa.st_v2_ike_seen_certreq = (count == 0 ? SEEN_EMPTY_v2CERTREQ : SEEN_FULL_v2CERTREQ);
		break;
	}
	default:
	{
		enum_buf b;
		llog_sa(RC_LOG_SERIOUS, ike,
			"ignoring CERTREQ payload of unsupported type %s",
			str_enum(&ikev2_cert_type_names, cr->isacertreq_enc, &b));
	}
	}
}

#if 0
/*
 * returns the concatenated SHA-1 hashes of each public key in the chain
 */
static chunk_t ikev2_hash_ca_keys(x509cert_t *ca_chain)
{
	unsigned char combined_hash[SHA1_DIGEST_SIZE * 8 /*max path len*/];
	x509cert_t *ca;
	chunk_t result = EMPTY_CHUNK;
	size_t sz = 0;

	zero(&combined_hash);

	for (ca = ca_chain; ca != NULL; ca = ca->next) {
		unsigned char sighash[SHA1_DIGEST_SIZE];
		SHA1_CTX ctx_sha1;

		SHA1Init(&ctx_sha1);
		SHA1Update(&ctx_sha1, ca->signature.ptr, ca->signature.len);
		SHA1Final(sighash, &ctx_sha1);

		if (DBGP(DBG_CRYPT)) {
			DBG_dump("SHA-1 of CA signature",
				 sighash, SHA1_DIGEST_SIZE);
		}

		memcpy(combined_hash + sz, sighash, SHA1_DIGEST_SIZE);
		sz += SHA1_DIGEST_SIZE;
	}
	passert(sz <= sizeof(combined_hash));
	result = clone_bytes_as_chunk(combined_hash, sz, "combined CERTREQ hash");
	if (DBGP(DBG_CRYPT)) {
		DBG_dump_hunk("Combined CERTREQ hashes", result);
	}
	return result;
}
#endif

/*
 * Instead of ikev2_hash_ca_keys use this for now. A single key
 * hash.
 */
static chunk_t ikev2_hash_nss_cert_key(CERTCertificate *cert,
				       struct logger *logger)
{
	unsigned char sighash[SHA1_DIGEST_SIZE];
	zero(&sighash);

	/*
	 * TODO: This should use SHA1 even if USE_SHA1 is disabled for
	 * IKE/IPsec.
	 */
	struct crypt_hash *ctx = crypt_hash_init("SHA-1 of Certificate Public Key",
						 &ike_alg_hash_sha1, logger);
	crypt_hash_digest_bytes(ctx, "pubkey",
				cert->derPublicKey.data,
				cert->derPublicKey.len);
	crypt_hash_final_bytes(&ctx, sighash, sizeof(sighash));
	chunk_t result = clone_bytes_as_chunk(sighash, SHA1_DIGEST_SIZE, "pkey hash");

	return result;
}

static bool build_and_emit_v2CERTREQ(enum ike_cert_type type,
				     chunk_t ca, struct pbs_out *outs)
{
	/*
	 * CERT_GetDefaultCertDB() simply returns the contents of a
	 * static variable set by NSS_Initialize().  It doesn't check
	 * the value and doesn't set PR error.  Short of calling
	 * CERT_SetDefaultCertDB(NULL), the value can never be NULL.
	 */
	CERTCertDBHandle *handle = CERT_GetDefaultCertDB();
	passert(handle != NULL);

	pb_stream cr_pbs;
	struct ikev2_certreq cr_hd = {
		.isacertreq_critical =  ISAKMP_PAYLOAD_NONCRITICAL,
		.isacertreq_enc = type,
	};

	/* build CR header */
	if (!out_struct(&cr_hd, &ikev2_certificate_req_desc, outs, &cr_pbs))
		return false;
	/*
	 * The Certificate Encoding field has the same values as those defined
	 * in Section 3.6.  The Certification Authority field contains an
	 * indicator of trusted authorities for this certificate type.  The
	 * Certification Authority value is a concatenated list of SHA-1 hashes
	 * of the public keys of trusted Certification Authorities (CAs).  Each
	 * is encoded as the SHA-1 hash of the Subject Public Key Info element
	 * (see section 4.1.2.7 of [PKIX]) from each Trust Anchor certificate.
	 * The 20-octet hashes are concatenated and included with no other
	 * formatting.
	 *
	 * How are multiple trusted CAs chosen?
	 */

	if (ca.ptr != NULL) {
		SECItem caname = same_shunk_as_dercert_secitem(ASN1(ca));

		CERTCertificate *cacert =
			CERT_FindCertByName(handle, &caname);

		if (cacert != NULL && CERT_IsCACert(cacert, NULL)) {
			dbg("located CA cert %s for CERTREQ", cacert->subjectName);
			/*
			 * build CR body containing the concatenated SHA-1 hashes of the
			 * CA's public key. This function currently only uses a single CA
			 * and should support more in the future
			 * */
			chunk_t cr_full_hash = ikev2_hash_nss_cert_key(cacert,
								       outs->outs_logger);

			if (!out_hunk(cr_full_hash, &cr_pbs, "CA cert public key hash")) {
				free_chunk_content(&cr_full_hash);
				return false;
			}
			free_chunk_content(&cr_full_hash);
		} else {
			LSWDBGP(DBG_BASE, buf) {
				jam(buf, "NSS: locating CA cert \'");
				jam_dn(buf, ASN1(ca), jam_sanitized_bytes);
				jam(buf, "\' for CERTREQ using CERT_FindCertByName() failed: ");
				jam_nss_error_code(buf, PR_GetError());
			}
		}
	}
	/*
	 * can it be empty?
	 * this function's returns need fixing
	 * */
	close_output_pbs(&cr_pbs);
	return true;
}

stf_status emit_v2CERTREQ(struct ike_sa *ike, struct msg_digest *md,
			  struct pbs_out *outpbs)
{
	if (ike->sa.st_connection->kind == CK_PERMANENT) {
		dbg("connection->kind is CK_PERMANENT so send CERTREQ");

		if (!build_and_emit_v2CERTREQ(CERT_X509_SIGNATURE,
					      ike->sa.st_connection->remote->config->host.ca,
					      outpbs))
			return STF_INTERNAL_ERROR;
	} else {
		dbg("connection->kind is not CK_PERMANENT (instance), so collect CAs");

		generalName_t *gn = collect_rw_ca_candidates(md);

		if (gn != NULL) {
			dbg("connection is RW, lookup CA candidates");

			for (generalName_t *ca = gn; ca != NULL; ca = ca->next) {
				if (!build_and_emit_v2CERTREQ(CERT_X509_SIGNATURE,
							      ca->name, outpbs)) {
					free_generalNames(gn, false);
					return STF_INTERNAL_ERROR;
				}
			}
			free_generalNames(gn, false);
		} else {
			dbg("not a roadwarrior instance, sending empty CA in CERTREQ");
			if (!build_and_emit_v2CERTREQ(CERT_X509_SIGNATURE,
						       EMPTY_CHUNK, outpbs)) {
				return STF_INTERNAL_ERROR;
			}
		}
	}
	return STF_OK;
}

bool need_v2CERTREQ_in_IKE_SA_INIT_response(const struct ike_sa *ike)
{
	struct authby authby = ike->sa.st_connection->remote->config->host.authby;
	return (authby_has_digsig(authby) && !remote_has_preloaded_pubkey(&ike->sa));
}

bool need_v2CERTREQ_in_IKE_AUTH_request(const struct ike_sa *ike)
{
	dbg("IKEv2 CERTREQ: send a cert request?");

	const struct connection *c = ike->sa.st_connection;

	if (!authby_has_digsig(c->remote->config->host.authby)) {
		dbg("IKEv2 CERTREQ: responder has no auth method requiring them to send back their cert");
		return false;
	}

	if (remote_has_preloaded_pubkey(&ike->sa)) {
		dbg("IKEv2 CERTREQ: public key already known");
		return false;
	}

	if (c->remote->config->host.ca.ptr == NULL ||
	    c->remote->config->host.ca.len < 1) {
		dbg("IKEv2 CERTREQ: no CA DN known to send");
		return false;
	}

	dbg("IKEv2 CERTREQ: OK to send a certificate request");

	return true;
}
