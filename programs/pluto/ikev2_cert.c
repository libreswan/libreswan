/* Support for IKEv2 CERT/CERTREQ payloads, for libreswan
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
 * Copyright (C) 2018-2022 Andrew Cagney
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
#include "crypt_hash.h"
#include "ike_alg_hash.h"

#include "defs.h"

#include "ikev2_cert.h"
#include "state.h"
#include "connections.h"
#include "nss_cert_verify.h"
#include "ikev2_message.h"
#include "log.h"
#include "pluto_x509.h"		/* for collect_rw_candidates()+remote_has_preloaded_pubkey() */

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
	lset_t authby = ike->sa.st_connection->remote->config->host.policy_authby;
	return ((authby & POLICY_AUTHBY_DIGSIG_MASK) &&
		!remote_has_preloaded_pubkey(&ike->sa));
}

bool need_v2CERTREQ_in_IKE_AUTH_request(const struct ike_sa *ike)
{
	dbg("IKEv2 CERTREQ: send a cert request?");

	const struct connection *c = ike->sa.st_connection;

	if ((c->remote->config->host.policy_authby & POLICY_AUTHBY_DIGSIG_MASK) == LEMPTY) {
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

/* Send v2 CERT and possible CERTREQ (which should be separated eventually) */
stf_status emit_v2CERT(const struct connection *c, struct pbs_out *outpbs)
{
	const struct cert *mycert = c->local->config->host.cert.nss_cert != NULL ? &c->local->config->host.cert : NULL;
	bool send_authcerts = c->send_ca != CA_SEND_NONE;
	bool send_full_chain = send_authcerts && c->send_ca == CA_SEND_ALL;

	if (impair.send_pkcs7_thingie) {
		llog(RC_LOG, outpbs->outs_logger, "IMPAIR: sending cert as PKCS7 blob");
		passert(mycert != NULL);
		SECItem *pkcs7 = nss_pkcs7_blob(mycert, send_full_chain);
		if (!pexpect(pkcs7 != NULL)) {
			return STF_INTERNAL_ERROR;
		}
		struct ikev2_cert pkcs7_hdr = {
			.isac_critical = build_ikev2_critical(false, outpbs->outs_logger),
			.isac_enc = CERT_PKCS7_WRAPPED_X509,
		};
		pb_stream cert_pbs;
		if (!out_struct(&pkcs7_hdr, &ikev2_certificate_desc,
				outpbs, &cert_pbs) ||
		    !out_hunk(same_secitem_as_chunk(*pkcs7), &cert_pbs, "PKCS7")) {
			SECITEM_FreeItem(pkcs7, PR_TRUE);
			return STF_INTERNAL_ERROR;
		}
		close_output_pbs(&cert_pbs);
		SECITEM_FreeItem(pkcs7, PR_TRUE);
		return STF_OK;
	}

	/*****
	 * From here on, if send_authcerts, we are obligated to:
	 * free_auth_chain(auth_chain, chain_len);
	 *****/

	chunk_t auth_chain[MAX_CA_PATH_LEN] = { { NULL, 0 } };
	int chain_len = 0;

	if (send_authcerts) {
		chain_len = get_auth_chain(auth_chain, MAX_CA_PATH_LEN,
					   mycert,
					   send_full_chain ? true : false);
	}

	const struct ikev2_cert certhdr = {
		.isac_critical = build_ikev2_critical(false, outpbs->outs_logger),
		.isac_enc = cert_ike_type(mycert),
	};

	/*   send own (Initiator CERT) */
	{
		pb_stream cert_pbs;

		dbg("sending [CERT] of certificate: %s", cert_nickname(mycert));

		if (!out_struct(&certhdr, &ikev2_certificate_desc,
				outpbs, &cert_pbs) ||
		    !out_hunk(cert_der(mycert), &cert_pbs, "CERT")) {
			free_auth_chain(auth_chain, chain_len);
			return STF_INTERNAL_ERROR;
		}

		close_output_pbs(&cert_pbs);
	}

	/* send optional chain CERTs */
	{
		for (int i = 0; i < chain_len ; i++) {
			pb_stream cert_pbs;

			dbg("sending an authcert");

			if (!out_struct(&certhdr, &ikev2_certificate_desc,
				outpbs, &cert_pbs) ||
			    !out_hunk(auth_chain[i], &cert_pbs, "CERT"))
			{
				free_auth_chain(auth_chain, chain_len);
				return STF_INTERNAL_ERROR;
			}
			close_output_pbs(&cert_pbs);
		}
	}
	free_auth_chain(auth_chain, chain_len);
	return STF_OK;
}

/*
 * For IKEv2, returns TRUE if we should be sending a cert
 */
bool ikev2_send_cert_decision(const struct ike_sa *ike)
{
	const struct connection *c = ike->sa.st_connection;
	const struct end *this = &c->spd.this;

	dbg("IKEv2 CERT: send a certificate?");

	bool sendit = false;

	if (ike->sa.st_peer_wants_null) {
		/* XXX: only ever true on responder */
		/* ??? should we log something?  All others do. */
	} else if ((c->local->config->host.policy_authby & POLICY_AUTHBY_DIGSIG_MASK) == LEMPTY) {
		policy_buf pb;
		dbg("IKEv2 CERT: local policy_authby does not have RSA or ECDSA: %s",
		    str_policy(c->policy & POLICY_AUTHBY_MASK, &pb));
	} else if (this->config->host.cert.nss_cert == NULL) {
		dbg("IKEv2 CERT: no certificate to send");
	} else if (c->local->config->host.sendcert == CERT_SENDIFASKED &&
		   ike->sa.st_requested_ca != NULL) {
		dbg("IKEv2 CERT: OK to send requested certificate");
		sendit = true;
	} else if (c->local->config->host.sendcert == CERT_ALWAYSSEND) {
		dbg("IKEv2 CERT: OK to send a certificate (always)");
		sendit = true;
	} else {
		dbg("IKEv2 CERT: no cert requested or we don't want to send");
	}
	return sendit;
}
