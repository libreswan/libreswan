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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <time.h>
#include <limits.h>
#include <sys/types.h>


#include "sysdep.h"
#include "lswconf.h"
#include "lswnss.h"
#include "constants.h"
#include "lswlog.h"

#include "defs.h"
#include "log.h"
#include "id.h"
#include "asn1.h"
#include "packet.h"
#include "demux.h"
#include "ipsec_doi.h"
#include "oid.h"
#include "x509.h"
#include "certs.h"
#include "keys.h"
#include "packet.h"
#include "demux.h"      /* needs packet.h */
#include "connections.h"
#include "state.h"
#include "whack.h"
#include "fetch.h"
#include "hostpair.h" /* for find_host_pair_connections */
#include "secrets.h"
#include "ip_address.h"
#include "ikev2_message.h"	/* for build_ikev2_critical() */
#include "ike_alg_hash.h"
#include "certs.h"
#include "root_certs.h"
#include "iface.h"

/* new NSS code */
#include "pluto_x509.h"
#include "nss_cert_load.h"
#include "nss_cert_verify.h"
#include "nss_err.h"

/* NSS */
#include <prtime.h>
#include <nss.h>
#include <keyhi.h>
#include <cert.h>
#include <certdb.h>
#include <secoid.h>
#include <secerr.h>
#include <secder.h>
#include <ocsp.h>
#include "crypt_hash.h"
#include "crl_queue.h"
#include "ip_info.h"

bool crl_strict = FALSE;
bool ocsp_strict = FALSE;
bool ocsp_enable = FALSE;
bool ocsp_post = FALSE;
char *curl_iface = NULL;
long curl_timeout = -1;

SECItem same_chunk_as_dercert_secitem(chunk_t chunk)
{
	return same_chunk_as_secitem(chunk, siDERCertBuffer);
}

chunk_t get_dercert_from_nss_cert(CERTCertificate *cert)
{
	return same_secitem_as_chunk(cert->derCert);
}

static const char *dntoasi(dn_buf *dst, SECItem si)
{
	return str_dn(same_secitem_as_chunk(si), dst);
}

static realtime_t get_nss_cert_notafter(CERTCertificate *cert)
{
	PRTime notBefore, notAfter;

	if (CERT_GetCertTimes(cert, &notBefore, &notAfter) != SECSuccess)
		return realtime(-1);
	else
		return realtime(notAfter / PR_USEC_PER_SEC);
}

/*
 * does our CA match one of the requested CAs?
 */
bool match_requested_ca(const generalName_t *requested_ca, chunk_t our_ca,
			int *our_pathlen)
{
	/* if no ca is requested than any ca will match */
	if (requested_ca == NULL) {
		*our_pathlen = 0;
		return TRUE;
	}

	*our_pathlen = MAX_CA_PATH_LEN + 1;

	while (requested_ca != NULL) {
		int pathlen;

		if (trusted_ca_nss(our_ca, requested_ca->name, &pathlen) &&
		    pathlen < *our_pathlen)
			*our_pathlen = pathlen;
		requested_ca = requested_ca->next;
	}

	return *our_pathlen <= MAX_CA_PATH_LEN;
}

static void same_nss_gn_as_pluto_gn(CERTGeneralName *nss_gn,
				    generalName_t *pluto_gn)
{
	switch (nss_gn->type) {
	case certOtherName:
		pluto_gn->name = same_secitem_as_chunk(nss_gn->name.OthName.name);
		pluto_gn->kind = GN_OTHER_NAME;
		break;

	case certRFC822Name:
		pluto_gn->name = same_secitem_as_chunk(nss_gn->name.other);
		pluto_gn->kind = GN_RFC822_NAME;
		break;

	case certDNSName:
		pluto_gn->name = same_secitem_as_chunk(nss_gn->name.other);
		pluto_gn->kind = GN_DNS_NAME;
		break;

	case certX400Address:
		pluto_gn->name = same_secitem_as_chunk(nss_gn->name.other);
		pluto_gn->kind = GN_X400_ADDRESS;
		break;

	case certEDIPartyName:
		pluto_gn->name = same_secitem_as_chunk(nss_gn->name.other);
		pluto_gn->kind = GN_EDI_PARTY_NAME;
		break;

	case certURI:
		pluto_gn->name = same_secitem_as_chunk(nss_gn->name.other);
		pluto_gn->kind = GN_URI;
		break;

	case certIPAddress:
		pluto_gn->name = same_secitem_as_chunk(nss_gn->name.other);
		pluto_gn->kind = GN_IP_ADDRESS;
		break;

	case certRegisterID:
		pluto_gn->name = same_secitem_as_chunk(nss_gn->name.other);
		pluto_gn->kind = GN_REGISTERED_ID;
		break;

	case certDirectoryName:
		pluto_gn->name = same_secitem_as_chunk(nss_gn->derDirectoryName);
		pluto_gn->kind = GN_DIRECTORY_NAME;
		break;

	default:
		bad_case(nss_gn->type);
	}
}

/*
 * Checks if CA a is trusted by CA b
 * This very well could end up being condensed into
 * an NSS call or two. TBD.
 */
bool trusted_ca_nss(chunk_t a, chunk_t b, int *pathlen)
{
	if (DBGP(DBG_BASE)) {
		if (a.ptr != NULL) {
			dn_buf abuf;
	    		DBG_log("%s: trustee A = '%s'", __func__,
				str_dn(a, &abuf));
		}
		if (b.ptr != NULL) {
			dn_buf bbuf;
	    		DBG_log("%s: trustor B = '%s'", __func__,
				str_dn(b, &bbuf));
		}
	}

	/* no CA b specified => any CA a is accepted */
	if (b.ptr == NULL) {
		*pathlen = (a.ptr == NULL) ? 0 : MAX_CA_PATH_LEN;
		return TRUE;
	}

	/* no CA a specified => trust cannot be established */
	if (a.ptr == NULL) {
		*pathlen = MAX_CA_PATH_LEN;
		return FALSE;
	}

	*pathlen = 0;

	/* CA a equals CA b => we have a match */
	if (same_dn(a, b)) {
		return TRUE;
	}

	/*
	 * CERT_GetDefaultCertDB() simply returns the contents of a
	 * static variable set by NSS_Initialize().  It doesn't check
	 * the value and doesn't set PR error.  Short of calling
	 * CERT_SetDefaultCertDB(NULL), the value can never be NULL.
	 */
	CERTCertDBHandle *handle = CERT_GetDefaultCertDB();
	passert(handle != NULL);

	/* CA a might be a subordinate CA of b */

	bool match = FALSE;
	CERTCertificate *cacert = NULL;

	while ((*pathlen)++ < MAX_CA_PATH_LEN) {
		SECItem a_dn = same_chunk_as_dercert_secitem(a);
		cacert = CERT_FindCertByName(handle, &a_dn);

		/* cacert not found or self-signed root cacert => exit */
		if (cacert == NULL || CERT_IsRootDERCert(&cacert->derCert)) {
			break;
		}

		/* does the issuer of CA a match CA b? */
		chunk_t i_dn = same_secitem_as_chunk(cacert->derIssuer);
		match = same_dn(i_dn, b);

		if (match) {
			/* we have a match: exit the loop */
			dbg("%s: A is a subordinate of B", __func__);
			break;
		}

		/* go one level up in the CA chain */
		a = i_dn;
		CERT_DestroyCertificate(cacert);
		cacert = NULL;
	}

	dbg("%s: returning %s at pathlen %d",
	    __func__, match ? "trusted" : "untrusted", *pathlen);

	if (cacert != NULL) {
		CERT_DestroyCertificate(cacert);
	}
	return match;
}

/*
 * choose either subject DN or a subjectAltName as connection end ID
 */
void select_nss_cert_id(CERTCertificate *cert, struct id *end_id)
{
	if (end_id->kind == ID_FROMCERT) {
		dbg("setting ID to ID_DER_ASN1_DN: \'%s\'", cert->subjectName);
		end_id->name = clone_secitem_as_chunk(cert->derSubject, "cert id");
		end_id->kind = ID_DER_ASN1_DN;
	}
}

generalName_t *gndp_from_nss_cert(CERTCertificate *cert)
{
	SECItem crlval;

	if (cert == NULL)
		return NULL;

	if (CERT_FindCertExtension(cert, SEC_OID_X509_CRL_DIST_POINTS,
						       &crlval) != SECSuccess) {
		LSWDBGP(DBG_BASE, buf) {
			jam_string(buf, "NSS: finding CRL distribution points using CERT_FindCertExtension() failed: ");
			jam_nss_error(buf);
		}
		return NULL;
	}

	CERTCrlDistributionPoints *dps = CERT_DecodeCRLDistributionPoints(cert->arena,
						    &crlval);
	if (dps == NULL) {
		LSWDBGP(DBG_BASE, buf) {
			jam(buf, "NSS: decoding CRL distribution points using CERT_DecodeCRLDistributionPoints() failed: ");
			jam_nss_error(buf);
		}
		return NULL;
	}

	CRLDistributionPoint **points = dps->distPoints;
	generalName_t *gndp_list = NULL;

	/* Certificate can have multiple distribution points */
	for (; points != NULL && *points != NULL; points++) {
		CRLDistributionPoint *point = *points;

		if (point->distPointType == generalName &&
			point->distPoint.fullName != NULL) {
			CERTGeneralName *first_name, *name;

			/* Each point is a linked list. */
			first_name = name = point->distPoint.fullName;
			do {
				if (name->type == certURI) {
					/* Add single point to return list */
					generalName_t *gndp =
						alloc_thing(generalName_t,
							    "gndp_from_nss_cert: general name");
					same_nss_gn_as_pluto_gn(name, gndp);
					gndp->next = gndp_list;
					gndp_list = gndp;
				}
				name = CERT_GetNextGeneralName(name);
			} while (name != NULL && name != first_name);
		}
	}

	return gndp_list;
}

generalName_t *collect_rw_ca_candidates(struct msg_digest *md)
{
	generalName_t *top = NULL;
	struct connection *d = find_host_pair_connections(&md->iface->local_endpoint, NULL);

	for (; d != NULL; d = d->hp_next) {
		if (NEVER_NEGOTIATE(d->policy))
			continue;

		/* we require a road warrior connection */
		if (d->kind == CK_TEMPLATE &&
		    !(d->policy & POLICY_OPPORTUNISTIC) &&
		    d->spd.that.ca.ptr != NULL) {
			generalName_t *gn;

			for (gn = top; ; gn = gn->next) {
				if (gn == NULL) {
					gn = alloc_thing(generalName_t, "generalName");
					gn->kind = GN_DIRECTORY_NAME;
					gn->name = d->spd.that.ca;
					gn->next = top;
					top = gn;
					break;
				}
				if (same_dn(gn->name,
						      d->spd.that.ca)) {
					break;
				}
			}
		}
	}
	return top;
}

/*
 *  Converts a X.500 generalName into an ID
 */
static void gntoid(struct id *id, const generalName_t *gn)
{
	*id  = empty_id;

	switch (gn->kind) {
	case GN_DNS_NAME:	/* ID type: ID_FQDN */
		id->kind = ID_FQDN;
		id->name = gn->name;
		break;
	case GN_IP_ADDRESS:	/* ID type: ID_IPV4_ADDR */
	{
		const struct ip_info *afi = &ipv4_info;
		err_t ugh = NULL;

		id->kind = afi->id_addr;
		ugh = hunk_to_address(gn->name, afi, &id->ip_addr);
		if (ugh != NULL) {
			libreswan_log(
				"Warning: gntoid() failed to initaddr(): %s",
				ugh);
		}
	}
	break;
	case GN_RFC822_NAME:	/* ID type: ID_USER_FQDN */
		id->kind = ID_USER_FQDN;
		id->name = gn->name;
		break;
	case GN_DIRECTORY_NAME:
		id->kind = ID_DER_ASN1_DN;
		id->name = gn->name;
		break;
	default:
		id->kind = ID_NONE;
		id->name = EMPTY_CHUNK;
	}
}

/*
 * Convert all CERTCertificate general names to a list of pluto generalName_t
 * Results go in *gn_out.
 */
static void get_pluto_gn_from_nss_cert(CERTCertificate *cert, generalName_t **gn_out, PRArenaPool *arena)
{
	generalName_t *pgn_list = NULL;
	CERTGeneralName *first_nss_gn = CERT_GetCertificateNames(cert, arena);

	if (first_nss_gn != NULL) {
		CERTGeneralName *cur_nss_gn = first_nss_gn;

		do {
			generalName_t *pluto_gn =
				alloc_thing(generalName_t,
					    "get_pluto_gn_from_nss_cert: converted gn");
			dbg("%s: allocated pluto_gn %p", __func__, pluto_gn);
			same_nss_gn_as_pluto_gn(cur_nss_gn, pluto_gn);
			pluto_gn->next = pgn_list;
			pgn_list = pluto_gn;
			/*
			 * CERT_GetNextGeneralName just loops around, does not end at NULL.
			 */
			cur_nss_gn = CERT_GetNextGeneralName(cur_nss_gn);
		} while (cur_nss_gn != first_nss_gn);
	}

	*gn_out = pgn_list;
}

static void replace_public_key(struct pubkey_list **pubkey_db,
			       struct pubkey *pk)
{
	/* ??? clang 3.5 thinks pk might be NULL */
	delete_public_keys(pubkey_db, &pk->id, pk->type);
	install_public_key(pk, pubkey_db);
}

static struct pubkey *create_cert_pubkey(const struct id *id,
					 CERTCertificate *cert,
					 struct logger *logger)
{
	/*
	 * Try to convert CERT to an internal PUBKEY object.  If
	 * someone, in parallel, deletes the underlying cert from the
	 * NSS DB, then this will fail.
	 */
	struct pubkey *pk = allocate_pubkey_nss(cert, logger);
	if (pk == NULL) {
		dbg("failed to allocate/extract pubkey from cert '%s'", cert->nickname);
		return NULL;
	}
	pk->id = *id;
	pk->until_time = get_nss_cert_notafter(cert);
	pk->issuer = same_secitem_as_chunk(cert->derIssuer);
	return pk;
}

static struct pubkey *create_cert_subjectdn_pubkey(CERTCertificate *cert,
						   struct logger *logger)
{
	struct id id = {
		.kind = ID_DER_ASN1_DN,
		.name = same_secitem_as_chunk(cert->derSubject),
	};
	return create_cert_pubkey(&id, cert, logger);
}

static void add_cert_san_pubkeys(struct pubkey_list **pubkey_db,
				 CERTCertificate *cert,
				 struct logger *logger)
{
	PRArenaPool *arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);

	generalName_t *gnt;
	get_pluto_gn_from_nss_cert(cert, &gnt, arena);

	for (generalName_t *gn = gnt; gn != NULL; gn = gn->next) {
		struct id id;

		gntoid(&id, gn);
		if (id.kind != ID_NONE) {
			struct pubkey *pk = create_cert_pubkey(&id, cert, logger);
			if (pk != NULL) {
				replace_public_key(pubkey_db, pk);
			}
		}
	}

	free_generalNames(gnt, FALSE);
	if (arena != NULL) {
		PORT_FreeArena(arena, PR_FALSE);
	}
}

/*
 * Adds pubkey entries from a certificate.
 * An entry with the ID_DER_ASN1_DN subject is always added
 * with subjectAltNames
 * @keyid provides an id for a secondary entry
 */
bool add_pubkey_from_nss_cert(struct pubkey_list **pubkey_db,
			      const struct id *keyid, CERTCertificate *cert,
			      struct logger *logger)
{
	struct pubkey *pk = create_cert_subjectdn_pubkey(cert, logger);
	if (pk == NULL) {
		dbg("failed to create subjectdn_pubkey from cert");
		return false;
	}

	replace_public_key(pubkey_db, pk);
	add_cert_san_pubkeys(pubkey_db, cert, logger);

	if (keyid != NULL && keyid->kind != ID_DER_ASN1_DN &&
			     keyid->kind != ID_NONE &&
			     keyid->kind != ID_FROMCERT)
	{
		struct pubkey *pk2 = create_cert_pubkey(keyid, cert, logger);
		if (pk2 != NULL) {
			replace_public_key(pubkey_db, pk2);
		}
	}
	return true;
}

/*
 * Free the chunks cloned into chain by get_auth_chain(). It is assumed that
 * the chain array itself is local to the IKEv1 main routines.
 */
void free_auth_chain(chunk_t *chain, int chain_len)
{
	for (int i = 0; i < chain_len; i++) {
		free_chunk_content(&chain[i]);
	}
}

int get_auth_chain(chunk_t *out_chain, int chain_max, CERTCertificate *end_cert,
						     bool full_chain)
{
	if (end_cert == NULL)
		return 0;

	/*
	 * CERT_GetDefaultCertDB() simply returns the contents of a
	 * static variable set by NSS_Initialize().  It doesn't check
	 * the value and doesn't set PR error.  Short of calling
	 * CERT_SetDefaultCertDB(NULL), the value can never be NULL.
	 */
	CERTCertDBHandle *handle = CERT_GetDefaultCertDB();
	passert(handle != NULL);

	if (!full_chain) {
		/*
		 * just the issuer unless it's a root
		 */
		CERTCertificate *is = CERT_FindCertByName(handle,
					&end_cert->derIssuer);
		if (is == NULL || is->isRoot)
			return 0;

		out_chain[0] = clone_secitem_as_chunk(is->derCert, "derCert");
		CERT_DestroyCertificate(is);
		return 1;
	}

	CERTCertificateList *chain =
		CERT_CertChainFromCert(end_cert, certUsageAnyCA, PR_FALSE);

	if (chain == NULL)
		return 0;

	if (chain->len < 1)
		return 0;

	int n = chain->len < chain_max ? chain->len : chain_max;
	int i, j;

	/* only non-root CAs in the resulting chain */
	for (i = 0, j = 0; i < n; i++) {
		if (!CERT_IsRootDERCert(&chain->certs[i]) &&
				CERT_IsCADERCert(&chain->certs[i], NULL))  {
			out_chain[j++] = clone_secitem_as_chunk(chain->certs[i], "cert");
		}
	}

	CERT_DestroyCertificateList(chain);

	return j;
}

#if defined(LIBCURL) || defined(LIBLDAP)
/*
 * Do our best to find the CA for the fetch request
 * However, this might be overkill, and only spd.this.ca should be used
 */
bool find_fetch_dn(SECItem *dn, struct connection *c,
		   CERTCertificate *cert)
{
	if (dn == NULL) {
		dbg("%s invalid use", __func__);
		return FALSE;
	}

	if (cert != NULL) {
		*dn = cert->derIssuer;
		return TRUE;
	}

	if (c->spd.that.ca.ptr != NULL && c->spd.that.ca.len > 0) {
		*dn = same_chunk_as_dercert_secitem(c->spd.that.ca);
		return TRUE;
	}

	if (c->spd.that.cert.u.nss_cert != NULL) {
		*dn = c->spd.that.cert.u.nss_cert->derIssuer;
		return TRUE;
	}

	if (c->spd.this.ca.ptr != NULL && c->spd.this.ca.len > 0) {
		*dn = same_chunk_as_dercert_secitem(c->spd.this.ca);
		return TRUE;
	}

	return FALSE;
}
#endif

/*
 * If peer_id->kind is ID_FROMCERT, there is a guaranteed match,
 * and it will be updated to an id of kind ID_DER_ASN1_DN
 * with the name taken from the cert's derSubject.
 *
 * "certs" is a list, a certificate chain.
 * We only deal with the head and it must be an endpoint cert.
 */
bool match_certs_id(const struct certs *certs,
		struct id *peer_id /*ID_FROMCERT => updated*/)
{
	CERTCertificate *end_cert = certs->cert;

	if (CERT_IsCACert(end_cert, NULL)) {
		loglog(RC_LOG_SERIOUS,
		       "cannot use CA certificate for endpoint");
		return false;
	}

	switch (peer_id->kind) {
	case ID_IPV4_ADDR:
	case ID_IPV6_ADDR:
	case ID_FQDN:
	case ID_USER_FQDN:
	{
		/* simple match */
		/* this logs errors; no need for duplication */
		return cert_VerifySubjectAltName(end_cert, peer_id);
	}

	case ID_FROMCERT:
	{
		chunk_t end_cert_der_subject = same_secitem_as_chunk(end_cert->derSubject);
		/* adopt ID from CERT (the CERT has been verified) */
		if (DBGP(DBG_BASE)) {
			id_buf idb;
			dn_buf dnb;
			DBG_log("ID_DER_ASN1_DN '%s' does not need further ID verification; stomping on peer_id with '%s'",
				str_id(peer_id, &idb), str_dn(end_cert_der_subject, &dnb));
		}
		/* replace peer_id */
		struct id id = {
			.kind = ID_DER_ASN1_DN,
			/* safe as duplicate_id() will clone this */
			.name = end_cert_der_subject,
		};
		duplicate_id(peer_id, &id);
		return true;
	}

	case ID_DER_ASN1_DN:
	{
		chunk_t end_cert_der_subject = same_secitem_as_chunk(end_cert->derSubject);
		if (DBGP(DBG_BASE)) {
			/*
			 * Dump .derSubject as an RFC 1485 string.
			 * Include both our (str_dn()) and NSS's
			 * (.subjectName) representations; does the
			 * latter need sanitizing?
			 */
			dn_buf dnb;
			id_buf idb;
			DBG_log("comparing ID_DER_ASN1_DN '%s' to certificate derSubject='%s' (subjectName='%s')",
				str_id(peer_id, &idb),
				str_dn(end_cert_der_subject, &dnb),
				end_cert->subjectName);
		}

		int wildcards;  /* value ignored */
		bool m = match_dn_any_order_wild(end_cert_der_subject, peer_id->name, &wildcards);
		if (!m) {
			/*
			 * XXX: can these two errors be merged?  The
			 * latter refers to a public key but this is
			 * all about certificates.
			 */
			id_buf idb;
			loglog(RC_LOG_SERIOUS, "ID_DER_ASN1_DN '%s' does not match expected '%s'",
			       end_cert->subjectName, str_id(peer_id, &idb));
		} else if (DBGP(DBG_BASE)) {
			id_buf idb;
			DBG_log("ID_DER_ASN1_DN '%s' matched our ID '%s'",
				end_cert->subjectName,
				str_id(peer_id, &idb));
		}
		return m;
	}

	default:
		loglog(RC_LOG_SERIOUS, "unhandled ID type %s; cannot match peer's certificate with expected peer ID",
		       enum_show(&ike_idtype_names, peer_id->kind));
		return false;
	}
}

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
	struct state *st = md->st;
	passert(st->st_ike_version == IKEv1);

	/*
	 * At least one set of certs have been processed; and at least
	 * once.
	 *
	 * The way this code is called is broken (see functions
	 * ikev1_decode_peer_id() and oakley_id_and_auth()):
	 *
	 * - it is repeatedly called to decode the same cert payload
	 * (causing a cert payload the be decoded multiple times)
	 *
	 * - it is called to decode cert payloads that aren't there
         * (for instance the first aggressive request)
	 */
	st->st_remote_certs.processed = true;

	/* if we already verified ID, no need to do it again */
	if (st->st_peer_alt_id) {
		dbg("Peer ID was already confirmed");
		return true;
	}

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

	const struct rev_opts rev_opts = {
		.ocsp = ocsp_enable,
		.ocsp_strict = ocsp_strict,
		.ocsp_post = ocsp_post,
		.crl_strict = crl_strict,
	};

	struct root_certs *root_certs = root_certs_addref(HERE); /* must-release */
	struct verified_certs certs = find_and_verify_certs(st->st_logger, st->st_ike_version,
							    cert_payloads, &rev_opts,
							    root_certs, &c->spd.that.id);
	root_certs_delref(&root_certs, HERE);

	/* either something went wrong, or there were no certs */
	if (certs.cert_chain == NULL) {
#if defined(LIBCURL) || defined(LIBLDAP)
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
			SECItem fdn = { siBuffer, NULL, 0 };
			if (find_fetch_dn(&fdn, c, NULL)) {
				add_crl_fetch_requests(crl_fetch_request(&fdn, NULL, NULL));
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

bool v1_verify_certs(struct msg_digest *md)
{
	struct state *st = md->st;
	struct ike_sa *ike = ike_sa(st, HERE);
	struct connection *c = st->st_connection;
	passert(st->st_ike_version == IKEv1);

	/* if we already verified ID, no need to do it again */
	if (st->st_peer_alt_id) {
		dbg("Peer ID was already confirmed");
		return true;
	}

	struct payload_digest *cert_payloads = md->chain[ISAKMP_NEXT_CERT];
	if (cert_payloads == NULL) {
		return true;
	}

	struct certs *certs = ike->sa.st_remote_certs.verified;
	if (certs == NULL) {
		return true;
	}

	/* end cert is at the front */
	CERTCertificate *end_cert = certs->cert;
	log_state(RC_LOG, st,
		  "certificate verified OK: %s", end_cert->subjectName);

	if (LIN(POLICY_ALLOW_NO_SAN, c->policy)) {
		dbg("SAN ID matching skipped due to policy (require-id-on-certificate=no)");
	} else {
		if (!match_certs_id(certs, &c->spd.that.id /*ID_FROMCERT => updated*/)) {
			libreswan_log("Peer CERT payload SubjectAltName does not match peer ID for this connection");
			return false;
		}
		dbg("SAN ID matched, updating that.cert");
	}

	st->st_peer_alt_id = true;
	if (c->spd.that.cert.ty == CERT_X509_SIGNATURE &&
	    c->spd.that.cert.u.nss_cert != NULL) {
		CERT_DestroyCertificate(c->spd.that.cert.u.nss_cert);
	}
	c->spd.that.cert.u.nss_cert = CERT_DupCertificate(certs->cert);
	c->spd.that.cert.ty = CERT_X509_SIGNATURE;
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
void ikev1_decode_cr(struct msg_digest *md)
{
	for (struct payload_digest *p = md->chain[ISAKMP_NEXT_CR];
	     p != NULL; p = p->next) {
		chunk_t ca_name = {
			.len = pbs_left(&p->pbs),
			.ptr = pbs_left(&p->pbs) > 0 ? p->pbs.cur : NULL
		};

		if (DBGP(DBG_BASE)) {
			DBG_dump_hunk("CR", ca_name);
		}

		const struct isakmp_cr *const cr = &p->payload.cr;

		if (cr->isacr_type == CERT_X509_SIGNATURE) {
			if (ca_name.len > 0) {
				if (!is_asn1(ca_name))
					continue;

				generalName_t *gn = alloc_thing(generalName_t, "generalName");

				gn->name = clone_hunk(ca_name, "ca name");
				gn->kind = GN_DIRECTORY_NAME;
				gn->next = md->st->st_requested_ca;
				md->st->st_requested_ca = gn;
			}

			if (DBGP(DBG_BASE)) {
				dn_buf buf;
				DBG_log("requested CA: '%s'",
					str_dn_or_null(ca_name, "%any", &buf));
			}
		} else {
			loglog(RC_LOG_SERIOUS,
				"ignoring %s certificate request payload",
				enum_show(&ike_cert_type_names,
					cr->isacr_type));
		}
	}
}

/*
 * Decode the IKEv2 CR payload of Phase 1.
 *
 * This needs to handle the SHA-1 hashes instead. However, receiving CRs
 * does nothing ATM.
 */
void ikev2_decode_cr(struct msg_digest *md)
{
	for (struct payload_digest *p = md->chain[ISAKMP_NEXT_v2CERTREQ];
	     p != NULL; p = p->next) {
		const struct ikev2_certreq *const cr = &p->payload.v2certreq;
		switch (cr->isacertreq_enc) {
		case CERT_X509_SIGNATURE:
		{
			chunk_t ca_name = {
				.len = pbs_left(&p->pbs),
				.ptr = pbs_left(&p->pbs) > 0 ? p->pbs.cur : NULL
			};
			if (DBGP(DBG_BASE)) {
				DBG_dump_hunk("CERT_X509_SIGNATURE CR:", ca_name);
			}

			if (ca_name.len > 0) {
				if (!is_asn1(ca_name))
					continue;

				generalName_t *gn =
					alloc_thing(generalName_t, "generalName");
				gn->name = clone_hunk(ca_name, "ca name");
				gn->kind = GN_DIRECTORY_NAME;
				gn->next = md->st->st_requested_ca;
				md->st->st_requested_ca = gn;
			}

			if (DBGP(DBG_BASE)) {
				dn_buf buf;
				DBG_log("requested CA: '%s'",
					str_dn_or_null(ca_name, "%any", &buf));
			}
			break;
		}
		default:
			loglog(RC_LOG_SERIOUS,
				"ignoring CERTREQ payload of unsupported type %s",
				enum_show(&ikev2_cert_type_names,
					cr->isacertreq_enc));
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

		DBG(DBG_CRYPT, DBG_dump("SHA-1 of CA signature",
							sighash,
							SHA1_DIGEST_SIZE));

		memcpy(combined_hash + sz, sighash, SHA1_DIGEST_SIZE);
		sz += SHA1_DIGEST_SIZE;
	}
	passert(sz <= sizeof(combined_hash));
	result = clone_bytes_as_chunk(combined_hash, sz, "combined CERTREQ hash");
	DBG(DBG_CRYPT, DBG_dump_hunk("Combined CERTREQ hashes", result));
	return result;
}
#endif

/* instead of ikev2_hash_ca_keys use this for now. A single key hash. */
static chunk_t ikev2_hash_nss_cert_key(CERTCertificate *cert)
{
	unsigned char sighash[SHA1_DIGEST_SIZE];
	zero(&sighash);

/* TODO: This should use SHA1 even if USE_SHA1 is disabled for IKE/IPsec */
	struct crypt_hash *ctx = crypt_hash_init("SHA-1 of Certificate Public Key",
						 &ike_alg_hash_sha1);
	crypt_hash_digest_bytes(ctx, "pubkey",
				cert->derPublicKey.data,
				cert->derPublicKey.len);
	crypt_hash_final_bytes(&ctx, sighash, sizeof(sighash));
	chunk_t result = clone_bytes_as_chunk(sighash, SHA1_DIGEST_SIZE, "pkey hash");

	return result;
}

bool ikev1_ship_CERT(uint8_t type, chunk_t cert, pb_stream *outs)
{
	pb_stream cert_pbs;
	struct isakmp_cert cert_hd = {
		.isacert_type = type,
		.isacert_reserved = 0,
		.isacert_length = 0, /* XXX unused on sending ? */
	};

	if (!out_struct(&cert_hd, &isakmp_ipsec_certificate_desc, outs,
				&cert_pbs) ||
	    !pbs_out_hunk(cert, &cert_pbs, "CERT"))
		return FALSE;

	close_output_pbs(&cert_pbs);
	return TRUE;
}

bool ikev1_build_and_ship_CR(enum ike_cert_type type,
			     chunk_t ca, pb_stream *outs)
{
	pb_stream cr_pbs;
	struct isakmp_cr cr_hd = {
		.isacr_type = type,
	};

	if (!out_struct(&cr_hd, &isakmp_ipsec_cert_req_desc, outs, &cr_pbs) ||
	    (ca.ptr != NULL && !pbs_out_hunk(ca, &cr_pbs, "CA")))
		return FALSE;

	close_output_pbs(&cr_pbs);
	return TRUE;
}

bool ikev2_build_and_ship_CR(enum ike_cert_type type,
			     chunk_t ca,
			     pb_stream *outs)
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
		return FALSE;
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
		SECItem caname = same_chunk_as_dercert_secitem(ca);

		CERTCertificate *cacert =
			CERT_FindCertByName(handle, &caname);

		if (cacert != NULL && CERT_IsCACert(cacert, NULL)) {
			dbg("located CA cert %s for CERTREQ", cacert->subjectName);
			/*
			 * build CR body containing the concatenated SHA-1 hashes of the
			 * CA's public key. This function currently only uses a single CA
			 * and should support more in the future
			 * */
			chunk_t cr_full_hash = ikev2_hash_nss_cert_key(cacert);

			if (!pbs_out_hunk(cr_full_hash, &cr_pbs, "CA cert public key hash")) {
				free_chunk_content(&cr_full_hash);
				return FALSE;
			}
			free_chunk_content(&cr_full_hash);
		} else {
			LSWDBGP(DBG_BASE, buf) {
				jam(buf, "NSS: locating CA cert \'");
				jam_dn(buf, ca, jam_sanitized_bytes);
				jam(buf, "\' for CERTREQ using CERT_FindCertByName() failed: ");
				jam_nss_error(buf);
			}
		}
	}
	/*
	 * can it be empty?
	 * this function's returns need fixing
	 * */
	close_output_pbs(&cr_pbs);
	return TRUE;
}

/*
 * For IKEv2, returns TRUE if we should be sending a cert
 */
bool ikev2_send_cert_decision(const struct state *st)
{
	const struct connection *c = st->st_connection;
	const struct end *this = &c->spd.this;

	dbg("IKEv2 CERT: send a certificate?");

	bool sendit = FALSE;

	if (st->st_peer_wants_null) {
		/* ??? should we log something?  All others do. */
	} else if (LDISJOINT(c->policy, POLICY_ECDSA | POLICY_RSASIG)) {
		dbg("IKEv2 CERT: policy does not have RSASIG or ECDSA: %s",
		    prettypolicy(c->policy & POLICY_ID_AUTH_MASK));
	} else if (this->cert.ty == CERT_NONE || this->cert.u.nss_cert == NULL) {
		dbg("IKEv2 CERT: no certificate to send");
	} else if (this->sendcert == CERT_SENDIFASKED &&
		   st->hidden_variables.st_got_certrequest) {
		dbg("IKEv2 CERT: OK to send requested certificate");
		sendit = TRUE;
	} else if (this->sendcert == CERT_ALWAYSSEND) {
		dbg("IKEv2 CERT: OK to send a certificate (always)");
		sendit = TRUE;
	} else {
		dbg("IKEv2 CERT: no cert requested or we don't want to send");
	}
	return sendit;
}

stf_status ikev2_send_certreq(struct state *st, struct msg_digest *md,
			      pb_stream *outpbs)
{
	if (st->st_connection->kind == CK_PERMANENT) {
		dbg("connection->kind is CK_PERMANENT so send CERTREQ");

		if (!ikev2_build_and_ship_CR(CERT_X509_SIGNATURE,
					     st->st_connection->spd.that.ca,
					     outpbs))
			return STF_INTERNAL_ERROR;
	} else {
		dbg("connection->kind is not CK_PERMANENT (instance), so collect CAs");

		generalName_t *gn = collect_rw_ca_candidates(md);

		if (gn != NULL) {
			dbg("connection is RW, lookup CA candidates");

			for (generalName_t *ca = gn; ca != NULL; ca = ca->next) {
				if (!ikev2_build_and_ship_CR(CERT_X509_SIGNATURE,
							     ca->name, outpbs)) {
					free_generalNames(gn, FALSE);
					return STF_INTERNAL_ERROR;
				}
			}
			free_generalNames(gn, FALSE);
		} else {
			dbg("not a roadwarrior instance, sending empty CA in CERTREQ");
			if (!ikev2_build_and_ship_CR(CERT_X509_SIGNATURE,
					       EMPTY_CHUNK,
					       outpbs))
				return STF_INTERNAL_ERROR;
		}
	}
	return STF_OK;
}

bool ikev2_send_certreq_INIT_decision(const struct state *st,
				      enum sa_role role)
{
	dbg("IKEv2 CERTREQ: send a cert request?");

	if (role != SA_INITIATOR) {
		dbg("IKEv2 CERTREQ: not the original initiator");
		return FALSE;
	}

	const struct connection *c = st->st_connection;

	if ((c->policy & POLICY_ID_AUTH_MASK) == POLICY_PSK || (c->policy & POLICY_ID_AUTH_MASK) == POLICY_AUTH_NULL) {
		dbg("IKEv2 CERTREQ: authby=secret and authby=null do not require CERTREQ");
		return FALSE;
	}

	if (has_preloaded_public_key(st)) {
		dbg("IKEv2 CERTREQ: public key already known");
		return FALSE;
	}

	if (c->spd.that.ca.ptr == NULL || c->spd.that.ca.len < 1) {
		dbg("IKEv2 CERTREQ: no CA DN known to send");
		return FALSE;
	}

	dbg("IKEv2 CERTREQ: OK to send a certificate request");

	return TRUE;
}

/* Send v2 CERT and possible CERTREQ (which should be separated eventually)  */
stf_status ikev2_send_cert(const struct state *st, pb_stream *outpbs)
{
	const cert_t mycert = st->st_connection->spd.this.cert;
	bool send_authcerts = st->st_connection->send_ca != CA_SEND_NONE;
	bool send_full_chain = send_authcerts && st->st_connection->send_ca == CA_SEND_ALL;

	if (impair.send_pkcs7_thingie) {
		libreswan_log("IMPAIR: sending cert as PKCS7 blob");
		SECItem *pkcs7 = nss_pkcs7_blob(mycert.u.nss_cert,
						send_full_chain);
		if (!pexpect(pkcs7 != NULL)) {
			return STF_INTERNAL_ERROR;
		}
		struct ikev2_cert pkcs7_hdr = {
			.isac_critical = build_ikev2_critical(false),
			.isac_enc = CERT_PKCS7_WRAPPED_X509,
		};
		pb_stream cert_pbs;
		if (!out_struct(&pkcs7_hdr, &ikev2_certificate_desc,
				outpbs, &cert_pbs) ||
		    !pbs_out_hunk(same_secitem_as_chunk(*pkcs7), &cert_pbs, "PKCS7")) {
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
					mycert.u.nss_cert,
					send_full_chain ? TRUE : FALSE);
	}

#if 0
	if (chain_len == 0)
		send_authcerts = FALSE;

 need to make that function v2 aware and move it

	doi_log_cert_thinking(st->st_oakley.auth,
		mycert.ty,
		st->st_connection->spd.this.sendcert,
		st->hidden_variables.st_got_certrequest,
		send_cert,
		send_authcerts);
#endif

	const struct ikev2_cert certhdr = {
		.isac_critical = build_ikev2_critical(false),
		.isac_enc = mycert.ty,
	};

	/*   send own (Initiator CERT) */
	{
		pb_stream cert_pbs;

		dbg("sending [CERT] of certificate: %s", mycert.u.nss_cert->subjectName);

		if (!out_struct(&certhdr, &ikev2_certificate_desc,
				outpbs, &cert_pbs) ||
		    !pbs_out_hunk(get_dercert_from_nss_cert(mycert.u.nss_cert),
							&cert_pbs, "CERT")) {
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
			    !pbs_out_hunk(auth_chain[i], &cert_pbs, "CERT"))
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

static bool cert_has_private_key(CERTCertificate *cert)
{
	if (cert == NULL)
		return FALSE;

	SECKEYPrivateKey *k = PK11_FindKeyByAnyCert(cert,
			lsw_return_nss_password_file_info());

	if (k == NULL)
		return FALSE;

	SECKEY_DestroyPrivateKey(k);
	return TRUE;
}

static bool cert_time_to_str(char *buf, size_t buflen,
					CERTCertificate *cert,
					bool notbefore)
{
	PRTime notBefore_tm, notAfter_tm;

	if (CERT_GetCertTimes(cert, &notBefore_tm, &notAfter_tm) != SECSuccess)
		return FALSE;

	PRTime ptime = notbefore ? notBefore_tm : notAfter_tm;

	PRExplodedTime printtime;

	PR_ExplodeTime(ptime, PR_GMTParameters, &printtime);

	if (!PR_FormatTime(buf, buflen, "%a %b %d %H:%M:%S %Y", &printtime))
		return FALSE;

	return TRUE;
}

static bool crl_time_to_str(char *buf, size_t buflen, SECItem *t)
{
	PRExplodedTime printtime;
	PRTime time;

	if (DER_DecodeTimeChoice(&time, t) != SECSuccess)
		return FALSE;

	PR_ExplodeTime(time, PR_GMTParameters, &printtime);

	if (!PR_FormatTime(buf, buflen, "%a %b %d %H:%M:%S %Y", &printtime))
		return FALSE;

	return TRUE;
}

static bool cert_detail_notbefore_to_str(char *buf, size_t buflen,
					CERTCertificate *cert)
{
	return cert_time_to_str(buf, buflen, cert, TRUE);
}

static bool cert_detail_notafter_to_str(char *buf, size_t buflen,
					CERTCertificate *cert)
{
	return cert_time_to_str(buf, buflen, cert, FALSE);
}

static int certsntoa(CERTCertificate *cert, char *dst, size_t dstlen)
{
	return datatot(cert->serialNumber.data, cert->serialNumber.len,
			'x', dst, dstlen);
}

static void cert_detail_to_whacklog(const struct fd *whackfd,
				    CERTCertificate *cert)
{
	bool is_CA = CERT_IsCACert(cert, NULL);
	bool is_root = cert->isRoot;
	SECKEYPublicKey *pub_k = SECKEY_ExtractPublicKey(&cert->subjectPublicKeyInfo);

	char sn[128];
	char *print_sn = certsntoa(cert, sn, sizeof(sn)) != 0 ? sn : "(NULL)";

	bool has_priv = cert_has_private_key(cert);

	if (!pexpect(pub_k != NULL))
		return;

	KeyType pub_k_t = SECKEY_GetPublicKeyType(pub_k);


	whack_comment(whackfd, " ");

	whack_comment(whackfd, "%s%s certificate \"%s\" - SN: %s",
		is_root ? "Root " : "",
		is_CA ? "CA" : "End",
		cert->nickname, print_sn);

	{
		dn_buf sbuf;

		whack_comment(whackfd, "  subject: %s",
			dntoasi(&sbuf, cert->derSubject));
	}

	{
		dn_buf ibuf;

		whack_comment(whackfd, "  issuer: %s",
			dntoasi(&ibuf, cert->derIssuer));
	}

	{
		char before[256];
		if (cert_detail_notbefore_to_str(before, sizeof(before), cert))
			whack_comment(whackfd, "  not before: %s", before);
	}

	{
		char after[256];
		if (cert_detail_notafter_to_str(after, sizeof(after), cert))
			whack_comment(whackfd, "  not after: %s", after);
	}

	whack_comment(whackfd, "  %d bit%s%s",
		SECKEY_PublicKeyStrengthInBits(pub_k),
		pub_k_t == rsaKey ? " RSA" : "(other)",
		has_priv ? ": has private key" : "");
}

typedef enum {
	CERT_TYPE_END,
	CERT_TYPE_CA,
} show_cert_t;

static bool is_cert_of_type(CERTCertificate *cert, show_cert_t type)
{
	return CERT_IsCACert(cert, NULL) == (type == CERT_TYPE_CA);
}

static void crl_detail_to_whacklog(const struct fd *whackfd, CERTCrl *crl)
{
	whack_comment(whackfd, " ");

	{
		dn_buf ibuf;

		whack_comment(whackfd, "issuer: %s",
			dntoasi(&ibuf, crl->derName));
	}

	{
		int entries = 0;

		if (crl->entries != NULL) {
			while (crl->entries[entries] != NULL)
				entries++;
		}
		whack_comment(whackfd, "revoked certs: %d", entries);
	}

	{
		char lu[256];

		if (crl_time_to_str(lu, sizeof(lu), &crl->lastUpdate))
			whack_comment(whackfd, "updates: this %s", lu);
	}

	{
		char nu[256];

		if (crl_time_to_str(nu, sizeof(nu), &crl->nextUpdate))
			whack_comment(whackfd, "         next %s", nu);
	}
}

static void crl_detail_list(const struct fd *whackfd)
{
	/*
	 * CERT_GetDefaultCertDB() simply returns the contents of a
	 * static variable set by NSS_Initialize().  It doesn't check
	 * the value and doesn't set PR error.  Short of calling
	 * CERT_SetDefaultCertDB(NULL), the value can never be NULL.
	 */
	CERTCertDBHandle *handle = CERT_GetDefaultCertDB();
	passert(handle != NULL);

	whack_comment(whackfd, " ");
	whack_comment(whackfd, "List of CRLs:");

	CERTCrlHeadNode *crl_list = NULL;

	if (SEC_LookupCrls(handle, &crl_list, SEC_CRL_TYPE) != SECSuccess)
		return;

	for (CERTCrlNode *crl_node = crl_list->first; crl_node != NULL;
	     crl_node = crl_node->next) {
		if (crl_node->crl != NULL) {
			crl_detail_to_whacklog(whackfd, &crl_node->crl->crl);
		}
	}
	dbg("releasing crl list in %s", __func__);
	PORT_FreeArena(crl_list->arena, PR_FALSE);
}

CERTCertList *get_all_certificates(void)
{
	PK11SlotInfo *slot = PK11_GetInternalKeySlot();

	if (slot == NULL)
		return NULL;

	if (PK11_NeedLogin(slot)) {
		SECStatus rv = PK11_Authenticate(
			slot, PR_TRUE, lsw_return_nss_password_file_info());
		if (rv != SECSuccess)
			return NULL;
	}

	return PK11_ListCertsInSlot(slot);
}

static void cert_detail_list(const struct fd *whackfd, show_cert_t type)
{
	char *tstr;

	switch (type) {
	case CERT_TYPE_END:
		tstr = "End";
		break;
	case CERT_TYPE_CA:
		tstr = "CA";
		break;
	default:
		bad_case(type);
	}

	whack_comment(whackfd, " ");
	whack_comment(whackfd, "List of X.509 %s Certificates:", tstr);

	CERTCertList *certs = get_all_certificates();

	if (certs == NULL)
		return;

	for (CERTCertListNode *node = CERT_LIST_HEAD(certs);
	     !CERT_LIST_END(node, certs); node = CERT_LIST_NEXT(node)) {
		if (is_cert_of_type(node->cert, type))
			cert_detail_to_whacklog(whackfd, node->cert);
	}

	CERT_DestroyCertList(certs);
}

void list_crls(const struct fd *whackfd)
{
	crl_detail_list(whackfd);
}

void list_certs(const struct fd *whackfd)
{
	cert_detail_list(whackfd, CERT_TYPE_END);
}

/*
 * Either the underlying cert's nickname, or NULL.
 */
const char *cert_nickname(const cert_t *cert)
{
	return cert->ty == CERT_X509_SIGNATURE &&
		cert->u.nss_cert != NULL ?
			cert->u.nss_cert->nickname : NULL;
}

void list_authcerts(const struct fd *whackfd)
{
	cert_detail_list(whackfd, CERT_TYPE_CA);
}

void clear_ocsp_cache(void)
{
	dbg("calling NSS to clear OCSP cache");
	(void)CERT_ClearOCSPCache();
}
