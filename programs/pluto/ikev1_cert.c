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
 * Copyright (C) 2018-2019 Andrew Cagney <cagney@gnu.org>
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

#include "defs.h"
#include "root_certs.h"

#include "x509_ocsp.h"
#include "ikev1_cert.h"
#include "log.h"
#include "demux.h"
#include "state.h"
#include "connections.h"
#include "secrets.h"
#include "nss_cert_verify.h"
#include "fetch.h"		/* for oscb_enable et.al. */
#include "pluto_x509.h"		/* for find_crl_fetch_dn() */
#include "crl_queue.h"		/* for submit_crl_fetch_request() */

/*
 * Decode the CERT payload of Phase 1.
 */
/* todo:
 * https://tools.ietf.org/html/rfc4945
 *  3.3.4. PKCS #7 Wrapped X.509 Certificate
 *
 *  This type defines a particular encoding, not a particular certificate
 *  type.  Implementations SHOULD NOT generate CERTs that contain this
 *  Certificate Type.  Implementations SHOULD accept CERTs that contain
 *  this Certificate Type because several implementations are known to
 *  generate them.  Note that those implementations sometimes include
 *  entire certificate hierarchies inside a single CERT PKCS #7 payload,
 *  which violates the requirement specified in ISAKMP that this payload
 *  contain a single certificate.
 */

/*
 * Decode the certs.  If something nasty happens, such as an expired
 * cert, return false.
 *
 * Only log failures, success is left to v2_verify_certs().
 */

bool v1_decode_certs(struct msg_digest *md)
{
	struct state *st = md->v1_st;
	passert(st->st_ike_version == IKEv1);

	/*
	 * At least one set of certs have been processed; and at least
	 * once.
	 *
	 * The way this code is called is broken (see functions
	 * ikev1_decode_peer_id*() and oakley_auth()):
	 *
	 * - it is repeatedly called to decode the same cert payload
	 * (causing a cert payload the be decoded multiple times)
	 *
	 * - it is called to decode cert payloads that aren't there
	 * (for instance the first aggressive request)
	 */
	st->st_remote_certs.processed = true;

	struct payload_digest *cert_payloads = md->chain[ISAKMP_NEXT_CERT];
	if (cert_payloads == NULL) {
		return true;
	}

	if (st->st_remote_certs.verified != NULL) {
		dbg("hacking around a redundant call to v1_process_certs() - releasing verified");
		release_certs(&st->st_remote_certs.verified);
	}
	if (st->st_remote_certs.pubkey_db != NULL) {
		dbg("hacking around a redundant call to v1_process_certs() - releasing pubkey_db");
		free_public_keys(&st->st_remote_certs.pubkey_db);
	}

	if (!pexpect(st->st_remote_certs.verified == NULL)) {
		/*
		 * Since the MITM has already failed their first
		 * attempt at proving their credentials, there's no
		 * point in giving them a second chance.
		 *
		 * Happens because code rejecting the first
		 * authentication attempt leaves the state as-is
		 * instead of zombifying (where the notification is
		 * recorded and then sent, and then the state
		 * transitions to zombie where it can linger while
		 * dealing with duplicate packets) or deleting it.
		 */
		return false;
	}

	statetime_t start = statetime_start(st);
	struct connection *c = st->st_connection;

	struct root_certs *root_certs = root_certs_addref(&global_logger); /* must-release */
	struct verified_certs certs = find_and_verify_certs(st->logger, st->st_ike_version,
							    cert_payloads,
							    root_certs,
							    &c->remote->host.id);
	root_certs_delref(&root_certs, GLOBAL_LOGGER);

	/* either something went wrong, or there were no certs */
	if (certs.cert_chain == NULL) {
#if defined(USE_LIBCURL) || defined(USE_LDAP)
		if (certs.crl_update_needed && deltasecs(crl_check_interval) > 0) {
			/*
			 * When a strict crl check fails, the certs
			 * are deleted and CRL_NEEDED is set.
			 *
			 * When a non-strict crl check fails, it is
			 * left to the crl fetch job to do a refresh.
			 *
			 * Trigger a refresh.
			 */
			chunk_t fdn = empty_chunk;
			if (find_crl_fetch_dn(&fdn, c)) {
				/* FDN contains issuer_dn */
				submit_crl_fetch_request(ASN1(fdn), st->logger);
			}
		}
#endif
		if (certs.harmless) {
			/* For instance, no CA, unknown certs, ... */
			return true;
		} else {
			log_state(RC_LOG, st,
				    "X509: certificate rejected for this connection");
			/* For instance, revoked */
			return false;
		}
	}

	pexpect(st->st_remote_certs.pubkey_db == NULL);
	st->st_remote_certs.pubkey_db = certs.pubkey_db;
	certs.pubkey_db = NULL;

	pexpect(st->st_remote_certs.verified == NULL);
	st->st_remote_certs.verified = certs.cert_chain;
	certs.cert_chain = NULL;

	statetime_stop(&start, "%s()", __func__);
	return true;
}

/*
 * Decode the CR payload of Phase 1.
 *
 *  https://tools.ietf.org/html/rfc4945
 *  3.2.4. PKCS #7 wrapped X.509 certificate
 *
 *  This ID type defines a particular encoding (not a particular
 *  certificate type); some current implementations may ignore CERTREQs
 *  they receive that contain this ID type, and the editors are unaware
 *  of any implementations that generate such CERTREQ messages.
 *  Therefore, the use of this type is deprecated.  Implementations
 *  SHOULD NOT require CERTREQs that contain this Certificate Type.
 *  Implementations that receive CERTREQs that contain this ID type MAY
 *  treat such payloads as synonymous with "X.509 Certificate -
 *  Signature".
 */

static void decode_v1_certificate_request(struct ike_sa *ike,
					  enum ike_cert_type cert_type,
					  const struct pbs_in *pbs)
{
	switch (cert_type) {
	case CERT_X509_SIGNATURE:
	{
		asn1_t ca_name = pbs_in_left(pbs);

		if (DBGP(DBG_BASE)) {
			DBG_dump_hunk("CR", ca_name);
		}

		if (ca_name.len > 0) {
			err_t e = asn1_ok(ca_name);
			if (e != NULL) {
				llog(RC_LOG, ike->sa.logger,
				     "ignoring CERTREQ payload that is not ASN1: %s", e);
				return;
			}

			generalName_t *gn = alloc_thing(generalName_t, "generalName");
			gn->name = clone_hunk(ca_name, "ca name");
			gn->kind = GN_DIRECTORY_NAME;
			gn->next = ike->sa.st_v1_requested_ca;
			ike->sa.st_v1_requested_ca = gn;
		}

		if (LDBGP(DBG_BASE, ike->sa.logger)) {
			dn_buf buf;
			LDBG_log(ike->sa.logger, "requested CA: '%s'",
				 str_dn_or_null(ca_name, "%any", &buf));
		}
		break;
	}
	default:
	{
		enum_buf b;
		llog(RC_LOG, ike->sa.logger,
		     "ignoring CERTREQ payload of unsupported type %s",
		     str_enum(&ikev2_cert_type_names, cert_type, &b));
	}
	}
}

void decode_v1_certificate_requests(struct ike_sa *ike, struct msg_digest *md)
{
	for (struct payload_digest *p = md->chain[ISAKMP_NEXT_CR]; p != NULL; p = p->next) {
		const struct isakmp_cr *const cr = &p->payload.cr;
		decode_v1_certificate_request(ike, cr->isacr_type, &p->pbs);
	}
}

bool ikev1_ship_CERT(enum ike_cert_type type, shunk_t cert, struct pbs_out *outs)
{
	struct pbs_out cert_pbs;
	struct isakmp_cert cert_hd = {
		.isacert_type = type,
		.isacert_reserved = 0,
		.isacert_length = 0, /* XXX unused on sending ? */
	};

	if (!out_struct(&cert_hd, &isakmp_ipsec_certificate_desc, outs,
				&cert_pbs) ||
	    !out_hunk(cert, &cert_pbs, "CERT"))
		return false;

	close_output_pbs(&cert_pbs);
	return true;
}

bool ikev1_build_and_ship_CR(enum ike_cert_type type,
			     chunk_t ca, struct pbs_out *outs)
{
	struct pbs_out cr_pbs;
	struct isakmp_cr cr_hd = {
		.isacr_type = type,
	};

	if (!out_struct(&cr_hd, &isakmp_ipsec_cert_req_desc, outs, &cr_pbs) ||
	    (ca.ptr != NULL && !out_hunk(ca, &cr_pbs, "CA")))
		return false;

	close_output_pbs(&cr_pbs);
	return true;
}

bool ikev1_ship_chain(chunk_t *chain, int n, struct pbs_out *outs,
		      uint8_t type)
{
	for (int i = 0; i < n; i++) {
		if (!ikev1_ship_CERT(type, HUNK_AS_SHUNK(chain[i]), outs))
			return false;
	}

	return true;
}
