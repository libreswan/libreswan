/* Support of X.509 certificates and CRLs
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
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 Kim B. Heino <b@bbbs.net>
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <time.h>
#include <limits.h>
#include <sys/types.h>

#include <libreswan.h>

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
#include "md5.h"
#include "sha1.h"
#include "whack.h"
#include "fetch.h"
#include "hostpair.h" /* for find_host_pair_connections */
#include "secrets.h"

/* new NSS code */
#include "pluto_x509.h"
#include "nss_cert_load.h"
#include "nss_cert_vfy.h"
#include "nss_crl_import.h"
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

bool strict_crl_policy = FALSE;
bool strict_ocsp_policy = FALSE;
bool ocsp_enable = FALSE;
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

static int dntoasi(char *dst, size_t dstlen, SECItem si)
{
	chunk_t ch = same_secitem_as_chunk(si);

	return dntoa(dst, dstlen, ch);
}

bool cert_key_is_rsa(CERTCertificate *cert)
{
	bool ret = FALSE;
	SECKEYPublicKey *pk = SECKEY_ExtractPublicKey(
					&cert->subjectPublicKeyInfo);

	if (pk != NULL) {
		ret = SECKEY_GetPublicKeyType(pk) == rsaKey;
		SECKEY_DestroyPublicKey(pk);
	}

	return ret;
}

static realtime_t get_nss_cert_notafter(CERTCertificate *cert)
{
	realtime_t ret;
	PRTime notBefore, notAfter;

	if (CERT_GetCertTimes(cert, &notBefore, &notAfter) != SECSuccess)
		ret.real_secs = -1;
	else
		ret.real_secs = notAfter / PR_USEC_PER_SEC;

	return ret;
}
/*
 * does our CA match one of the requested CAs?
 */
bool match_requested_ca(generalName_t *requested_ca, chunk_t our_ca,
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

static void convert_nss_gn_to_pluto_gn(CERTGeneralName *nss_gn,
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
 * an NSS call or two. TBD
 */
bool trusted_ca_nss(chunk_t a, chunk_t b, int *pathlen)
{
	bool match = FALSE;
	CERTCertDBHandle *handle;
	CERTCertificate *cacert = NULL;
	char abuf[ASN1_BUF_LEN], bbuf[ASN1_BUF_LEN];

	dntoa(abuf, ASN1_BUF_LEN, a);
	dntoa(bbuf, ASN1_BUF_LEN, b);

	DBG(DBG_X509 | DBG_CONTROLMORE,
	    DBG_log("%s: trustee A = '%s'", __FUNCTION__, abuf));
	DBG(DBG_X509 | DBG_CONTROLMORE,
	    DBG_log("%s: trustor B = '%s'", __FUNCTION__, bbuf));

	/* no CA b specified -> any CA a is accepted */
	if (b.ptr == NULL) {
		*pathlen = (a.ptr == NULL) ? 0 : MAX_CA_PATH_LEN;
		return TRUE;
	}

	/* no CA a specified -> trust cannot be established */
	if (a.ptr == NULL) {
		*pathlen = MAX_CA_PATH_LEN;
		return FALSE;
	}

	*pathlen = 0;

	/* CA a equals CA b -> we have a match */
	if (same_dn_any_order(a, b)) {
		return TRUE;
	}

	handle = CERT_GetDefaultCertDB();
	if (handle == NULL) {
		libreswan_log("trusted_ca_nss handle failure");
		return FALSE;
	}

	/* CA a might be a subordinate CA of b */
	while ((*pathlen)++ < MAX_CA_PATH_LEN) {
		SECItem a_dn = same_chunk_as_dercert_secitem(a);
		chunk_t i_dn = empty_chunk;

		cacert = CERT_FindCertByName(handle, &a_dn);

		/* cacert not found or self-signed root cacert-> exit */
		if (cacert == NULL || CERT_IsRootDERCert(&cacert->derCert)) {
			break;
		}

		/* does the issuer of CA a match CA b? */
		i_dn = same_secitem_as_chunk(cacert->derIssuer);
		match = same_dn_any_order(i_dn, b);

		/* we have a match and exit the loop */
		if (match) {
			DBG(DBG_X509 | DBG_CONTROLMORE,
			    DBG_log("%s: A is a subordinate of B",
				    __FUNCTION__));
			break;
		}

		/* go one level up in the CA chain */
		a = i_dn;
		CERT_DestroyCertificate(cacert);
		cacert = NULL;
	}

	DBG(DBG_X509 | DBG_CONTROLMORE,
		DBG_log("%s: returning %s at pathlen %d", __FUNCTION__,
			match ? "trusted":"untrusted", *pathlen));

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
	bool use_dn = FALSE;	/* ID is subject DN */

	/* check for cert email addr first */
	if (end_id->kind == ID_USER_FQDN) {
		char email[IDTOA_BUF];

		idtoa(end_id, email, IDTOA_BUF);
		if (cert->emailAddr == NULL || !streq(cert->emailAddr, email)) {
			DBG(DBG_X509,
			    DBG_log("no email \'%s\' for cert, using ASN1 subjectName",
						email));
			use_dn = TRUE;
		}
	}

	if (end_id->kind == ID_DER_ASN1_DN) {
		chunk_t certdn = same_secitem_as_chunk(cert->derSubject);

		if (!same_dn_any_order(end_id->name, certdn)) {
			char idb[IDTOA_BUF];

			idtoa(end_id, idb, IDTOA_BUF);
			DBG(DBG_X509,
			    DBG_log("no subject \'%s\' for cert, using ASN1 subjectName \'%s\'",
						idb, cert->subjectName));
			use_dn = TRUE;
		}
	}

	if (end_id->kind == ID_FROMCERT || end_id->kind == ID_NONE || use_dn) {
		DBG(DBG_X509,
		    DBG_log("setting ID to ID_DER_ASN1_DN: \'%s\'",
			    cert->subjectName));
		end_id->name = same_secitem_as_chunk(cert->derSubject);
		end_id->kind = ID_DER_ASN1_DN;
	}
}

static char *make_crl_uri_str(chunk_t *uri)
{
	if (uri == NULL || uri->ptr == NULL || uri->len < 1)
		return NULL;

	char *uri_str = alloc_bytes(uri->len + 1, "uri str");

	memcpy(uri_str, uri->ptr, uri->len);
	uri_str[uri->len] = '\0';

	return uri_str;
}

static void dbg_crl_import_err(int err)
{
	DBG(DBG_X509,
	    DBG_log("CRL import error: %s",
		    nss_err_str((PRInt32)err)));
}

bool insert_crl_nss(chunk_t *blob, chunk_t *crl_uri, char *nss_uri)
{
	bool ret;
	char *uri_str;
	int r;

	if (blob == NULL || blob->ptr == NULL || blob->len < 1)
		return FALSE;

	/* for CRL use the name passed to helper for the uri */
	if (nss_uri == NULL && crl_uri != NULL) {
		uri_str = make_crl_uri_str(crl_uri);
		if (uri_str == NULL) {
			DBG(DBG_X509,
			    DBG_log("no CRL URI available"));
			return FALSE;
		}
	} else {
		uri_str = nss_uri;
	}

	if (uri_str == NULL)
		return FALSE;

	r = send_crl_to_import(blob->ptr, blob->len, uri_str);
	if (r == -1) {
		libreswan_log("_import_crl internal error");
		ret = FALSE;
	} else if (r != 0) {
		dbg_crl_import_err(r);
		ret = FALSE;
	} else {
		DBG(DBG_X509, DBG_log("CRL imported"));
		ret = TRUE;
	}

	if (nss_uri == NULL && crl_uri != NULL)
		pfree(uri_str);

	freeanychunk(*blob);
	return ret;
}

generalName_t *gndp_from_nss_cert(CERTCertificate *cert)
{
	SECItem crlval;

	if (cert == NULL)
		return NULL;

	if (CERT_FindCertExtension(cert, SEC_OID_X509_CRL_DIST_POINTS,
						       &crlval) != SECSuccess) {
		DBG(DBG_X509,
		    DBG_log("could not find CRL URI ext %d", PORT_GetError()));
		return NULL;
	}

	CERTCrlDistributionPoints *dps = CERT_DecodeCRLDistributionPoints(cert->arena,
						    &crlval);
	if (dps == NULL) {
		DBG(DBG_X509,
		    DBG_log("could not decode distribution points ext %d",
							       PORT_GetError()));
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
					generalName_t *gndp;

					/* Add single point to return list */
					gndp = alloc_thing(generalName_t,
							"converted gn");
					convert_nss_gn_to_pluto_gn(name, gndp);
					gndp->next = gndp_list;
					gndp_list = gndp;
				}
				name = CERT_GetNextGeneralName(name);
			} while (name != NULL && name != first_name);
		}
	}

	return gndp_list;
}

static char *find_dercrl_uri(chunk_t *dercrl)
{
	/* these are used by out so must be initialized */
	CERTCertificate *cacert = NULL;
	CERTSignedCrl *crl = NULL;
	char *uri = NULL;

	SECItem crlval;

	PLArenaPool *arena = PORT_NewArena(SEC_ASN1_DEFAULT_ARENA_SIZE);

	SECItem crl_si = same_chunk_as_dercert_secitem(*dercrl);

	CERTCertDBHandle *handle = CERT_GetDefaultCertDB();

	if (handle == NULL) {
		DBG(DBG_X509,
		    DBG_log("could not get db handle %d", PORT_GetError()));
		goto out;
	}
	/*
	 * arena gets owned/freed by crl
	 */
	crl = CERT_DecodeDERCrl(arena, &crl_si, SEC_CRL_TYPE);
	if (crl == NULL) {
		DBG(DBG_X509,
		    DBG_log("could not decode crl %d", PORT_GetError()));
		goto out;
	}

	cacert = CERT_FindCertByName(handle, &crl->crl.derName);
	if (cacert == NULL) {
		DBG(DBG_X509,
		    DBG_log("could not find cert by crl.derName %d",
							       PORT_GetError()));
		goto out;
	}

	DBG(DBG_X509,
	DBG_log("crl issuer found %s : nick %s", cacert->nickname,
						 cacert->subjectName));

	if (CERT_FindCertExtension(cacert, SEC_OID_X509_CRL_DIST_POINTS,
						       &crlval) != SECSuccess) {
		DBG(DBG_X509,
		    DBG_log("could not find CRL URI ext %d", PORT_GetError()));

		goto out;
	}

	CERTCrlDistributionPoints *dps =
		CERT_DecodeCRLDistributionPoints(cacert->arena, &crlval);

	if (dps == NULL) {
		DBG(DBG_X509,
		    DBG_log("could not decode distribution points ext %d",
							       PORT_GetError()));
		goto out;
	}

	/*
	 * MR - do only the first distribution point. Could support more
	 * in the future
	 *
	 * XXX Duplicate code with gndp_from_nss_cert().
	 * XXX See also comment in gndp_from_nss_cert() about multiple points.
	 */
	CRLDistributionPoint *point = dps->distPoints[0];

	if (point != NULL && point->distPointType == generalName &&
			     point->distPoint.fullName != NULL) {
		CERTGeneralName *dp_gn = point->distPoint.fullName;
		/*
		 * XXX - name or OthName.name? Needs a look
		 */
		SECItem *name = &dp_gn->name.other;

		if (dp_gn->type == certURI && name->data != NULL &&
					      name->len > 0) {
			chunk_t uri_chunk = same_secitem_as_chunk(*name);
			uri = make_crl_uri_str(&uri_chunk);
			if (uri != NULL) {
				DBG(DBG_X509, DBG_log("using URI:%s from CA %s", uri,
							   cacert->subjectName));
			}
		}
	}

out:
	if (cacert != NULL)
		CERT_DestroyCertificate(cacert);

	if (crl != NULL)
		SEC_DestroyCrl(crl);

	return uri;
}

/*
 * Filter for scandir(3): eliminate the directory entries starting with ".".
 */
static int filter_dotfiles(
#ifdef SCANDIR_HAS_CONST
	const
#endif
	struct dirent *entry)
{
	return entry->d_name[0] != '.';

}

/*
 *  Loads CRLs
 */
void load_crls(void)
{
	char buf[PATH_MAX];
	const struct lsw_conf_options *oco = lsw_init_options();

	/* legacy CRL reading - will go away soon */
	/* change directory to specified path */

	char *save_dir = getcwd(buf, PATH_MAX);

	if (chdir(oco->crls_dir) == -1) {
		DBG(DBG_X509, DBG_log("Could not change to legacy CRL directory '%s': %d %s",
			      oco->crls_dir, errno, strerror(errno)));
	} else {
		struct dirent **filelist;

		DBG(DBG_X509,
		    DBG_log("Changing to directory '%s'", oco->crls_dir));

		int n = scandir(oco->crls_dir, &filelist, (void *) filter_dotfiles,
			    alphasort);

		if (n < 0) {
			int e = errno;

			libreswan_log(
				"Scanning directory '%s' failed - (%d %s)",
				oco->crls_dir, e, strerror(e));
		}
		while (n > 0) {
			n--;
			chunk_t blob = empty_chunk;
			char *filename = filelist[n]->d_name;

			if (load_coded_file(filename, "crl", &blob)) {
				/* get uri from the CA */
				char *uri = find_dercrl_uri(&blob);

				if (uri != NULL) {
					(void)insert_crl_nss(&blob,
							    NULL,
							    uri);
					pfree(uri);
				}
			}
			free(filelist[n]);	/* was malloced by scandir(3) */
		}
		free(filelist);	/* was malloced by scandir(3) */
	}
	/* restore directory path */
	if (chdir(save_dir) == -1) {
		int e = errno;

		libreswan_log(
			"Changing back to directory '%s' failed - (%d %s)",
			save_dir, e, strerror(e));
	}
}

generalName_t *collect_rw_ca_candidates(struct msg_digest *md)
{
	generalName_t *top = NULL;
	struct connection *d = find_host_pair_connections(
		&md->iface->ip_addr, pluto_port,
		(ip_address *)NULL, md->sender_port);

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
				if (same_dn_any_order(gn->name,
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
		const struct af_info *afi = &af_inet4_info;
		err_t ugh = NULL;

		id->kind = afi->id_addr;
		ugh = initaddr(gn->name.ptr, gn->name.len, afi->af,
			&id->ip_addr);
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
		id->name = empty_chunk;
	}
}

/*
 * Convert all CERTCertificate general names to a list of pluto generalName_t
 * Results go in *gn_out.
 */
static void get_pluto_gn_from_nss_cert(CERTCertificate *cert, generalName_t **gn_out)
{
	generalName_t *pgn_list = NULL;
	CERTGeneralName *first_nss_gn = CERT_GetCertificateNames(cert, cert->arena);;

	if (first_nss_gn != NULL) {
		CERTGeneralName *cur_nss_gn = first_nss_gn;

		do {
			generalName_t *pluto_gn = alloc_thing(generalName_t, "converted gn");

			DBG(DBG_X509, DBG_log("%s: allocated pluto_gn %p",
						__FUNCTION__, pluto_gn));
			convert_nss_gn_to_pluto_gn(cur_nss_gn, pluto_gn);
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

static void replace_public_key(struct pubkey *pk)
{
	/* ??? clang 3.5 thinks pk might be NULL */
	delete_public_keys(&pluto_pubkeys, &pk->id, pk->alg);
	install_public_key(pk, &pluto_pubkeys);
}

static void create_cert_pubkey(struct pubkey **pkp,
				      const struct id *id,
				      CERTCertificate *cert)
{
	struct pubkey *pk = allocate_RSA_public_key_nss(cert);

	passert(pk != NULL);
	pk->id = *id;
	pk->dns_auth_level = DAL_LOCAL;
	pk->until_time = get_nss_cert_notafter(cert);
	pk->issuer = same_secitem_as_chunk(cert->derIssuer);
	*pkp = pk;
}

static void create_cert_subjectdn_pubkey(struct pubkey **pkp,
				       CERTCertificate *cert)
{
	struct id id;

	id.kind = ID_DER_ASN1_DN;
	id.name = same_secitem_as_chunk(cert->derSubject);
	create_cert_pubkey(pkp, &id, cert);
}

static void add_cert_san_pubkeys(CERTCertificate *cert)
{
	generalName_t *gn = NULL;
	generalName_t *gnt;

	get_pluto_gn_from_nss_cert(cert, &gn);

	for (gnt = gn; gn != NULL; gn = gn->next) {
		struct id id;
		struct pubkey *pk = NULL;

		gntoid(&id, gn);
		if (id.kind != ID_NONE) {
			create_cert_pubkey(&pk, &id, cert);
			replace_public_key(pk);
		}
	}

	free_generalNames(gnt, FALSE);
}

/*
 * Adds pubkey entries from a certificate.
 * An entry with the ID_DER_ASN1_DN subject is always added
 * with subjectAltNames
 * @keyid provides an id for a secondary entry
 */
void add_rsa_pubkey_from_cert(const struct id *keyid, CERTCertificate *cert)
{
	struct pubkey *pk = NULL;

	if (!cert_key_is_rsa(cert)) {
		libreswan_log("cert key is not rsa type!");
		return;
	}

	create_cert_subjectdn_pubkey(&pk, cert);
	replace_public_key(pk);

	add_cert_san_pubkeys(cert);

	if (keyid != NULL && keyid->kind != ID_DER_ASN1_DN &&
			     keyid->kind != ID_NONE &&
			     keyid->kind != ID_FROMCERT)
	{
		struct pubkey *pk2 = NULL;

		create_cert_pubkey(&pk2, keyid, cert);
		replace_public_key(pk2);
	}
}

int get_auth_chain(chunk_t *out_chain, int chain_max, CERTCertificate *end_cert,
						     bool full_chain)
{
	if (end_cert == NULL)
		return 0;

	if (!full_chain) {
		/*
		 * just the issuer unless it's a root
		 */
		CERTCertificate *is = CERT_FindCertByName(CERT_GetDefaultCertDB(),
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

#define CRL_CHECK_ENABLED() (deltasecs(crl_check_interval) > 0)

#if defined(LIBCURL) || defined(LDAP_VER)
/*
 * Do our best to find the CA for the fetch request
 * However, this might be overkill, and only spd.this.ca should be used
 */
static bool find_fetch_dn(SECItem *dn, struct connection *c,
				       CERTCertificate *cert)
{
	if (dn == NULL) {
		DBG(DBG_X509, DBG_log("%s invalid use",__FUNCTION__));
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

/* returns FALSE for a REVOKED cert or internal failure. returns
 * TRUE for a good cert or a failed verify (for continuing with
 * connection refining)
 */
static bool pluto_process_certs(struct state *st, chunk_t *certs,
						  int num_certs)
{
	struct connection *c = st->st_connection;
#if defined(LIBCURL) || defined(LDAP_VER)
	SECItem fdn = { siBuffer, NULL, 0 };
#endif
	bool cont = TRUE;
	bool rev_opts[RO_SZ];

	rev_opts[RO_OCSP] = ocsp_enable;
	rev_opts[RO_OCSP_S] = strict_ocsp_policy;
	rev_opts[RO_CRL_S] = strict_crl_policy;

	CERTCertificate *end_cert = NULL;

	int ret = verify_and_cache_chain(certs, num_certs, &end_cert,
						       rev_opts);

	if (ret == -1) {
		libreswan_log("cert verify failed with internal error");
		return FALSE;
	}

	if ((ret & VERIFY_RET_OK) && end_cert != NULL) {
		libreswan_log("certificate %s OK", end_cert->subjectName);
		c->spd.that.cert.u.nss_cert = end_cert;
		c->spd.that.cert.ty = CERT_X509_SIGNATURE;
		add_rsa_pubkey_from_cert(&c->spd.that.id, end_cert);
	} else if (ret & VERIFY_RET_REVOKED) {
		libreswan_log("certificate revoked!");
		cont = FALSE;
	}
#if defined(LIBCURL) || defined(LDAP_VER)
	if ((ret & VERIFY_RET_CRL_NEED) && CRL_CHECK_ENABLED()) {
		generalName_t *end_cert_dp = NULL;

		if ((ret & VERIFY_RET_OK) && end_cert != NULL) {
			end_cert_dp = gndp_from_nss_cert(end_cert);
		}
		if (find_fetch_dn(&fdn, c, end_cert)) {
			add_crl_fetch_request_nss(&fdn, end_cert_dp);
			wake_fetch_thread(__FUNCTION__);
		}
	}
#endif

	return cont;
}

/*
 * Decode the CERT payload of Phase 1.
 */
/* todo:
 * http://tools.ietf.org/html/rfc4945
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
 *
 */
bool ikev1_decode_cert(struct msg_digest *md)
{
	struct state *st = md->st;
	struct payload_digest *p;
	chunk_t der_list[32] = { {NULL, 0} };
	bool ret = TRUE;
	int der_num = 0;

	for (p = md->chain[ISAKMP_NEXT_CERT]; p != NULL; p = p->next) {
		struct isakmp_cert *const cert = &p->payload.cert;

		if (cert->isacert_type == CERT_X509_SIGNATURE) {
			chunk_t blob;

			clonetochunk(blob, p->pbs.cur, pbs_left(&p->pbs), "cert chain blob");
			der_list[der_num++] = blob;
		} else {
			loglog(RC_LOG_SERIOUS, "ignoring %s certificate payload",
			   enum_show(&ike_cert_type_names, cert->isacert_type));
		}
	}

	if (der_num > 0) {
		if (!pluto_process_certs(st, der_list, der_num)) {
			libreswan_log("Peer public key is not available for this exchange");
			ret = FALSE;
		}

		while (der_num-- > 0)
			freeanychunk(der_list[der_num]);
	}

	return ret;
}

/* Decode IKEV2 CERT Payload */

bool ikev2_decode_cert(struct msg_digest *md)
{
	struct state *st = md->st;
	struct payload_digest *p;
	chunk_t der_list[32] = { {NULL, 0} };
	bool ret = TRUE;
	int der_num = 0;

	for (p = md->chain[ISAKMP_NEXT_v2CERT]; p != NULL; p = p->next) {
		struct ikev2_cert *const v2cert = &p->payload.v2cert;

		if (v2cert->isac_enc == CERT_X509_SIGNATURE) {
			chunk_t blob;
			clonetochunk(blob, p->pbs.cur, pbs_left(&p->pbs), "cert chain blob");
			der_list[der_num++] = blob;
		} else {
			loglog(RC_LOG_SERIOUS, "ignoring %s certificate payload",
				enum_show(&ikev2_cert_type_names,
						v2cert->isac_enc));
		}
	}

	if (der_num > 0) {
		if (!pluto_process_certs(st, der_list, der_num)) {
			libreswan_log("Peer public key is not available for this exchange");
			ret = FALSE;
		}

		while (der_num-- > 0)
			freeanychunk(der_list[der_num]);
	}

	return ret;
}

/*
 * Decode the CR payload of Phase 1.
 *
 *  http://tools.ietf.org/html/rfc4945
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
	struct payload_digest *p;
	struct state *st = md->st;
	generalName_t *requested_ca = st->st_requested_ca;

	for (p = md->chain[ISAKMP_NEXT_CR]; p != NULL; p = p->next) {
		struct isakmp_cr *const cr = &p->payload.cr;
		chunk_t ca_name;

		ca_name.len = pbs_left(&p->pbs);
		ca_name.ptr = (ca_name.len > 0) ? p->pbs.cur : NULL;

		DBG_cond_dump_chunk(DBG_X509, "CR", ca_name);

		if (cr->isacr_type == CERT_X509_SIGNATURE) {

			if (ca_name.len > 0) {
				generalName_t *gn;

				if (!is_asn1(ca_name))
					continue;

				gn = alloc_thing(generalName_t, "generalName");
				clonetochunk(gn->name, ca_name.ptr, ca_name.len,
					"ca name");
				gn->kind = GN_DIRECTORY_NAME;
				gn->next = requested_ca;
				requested_ca = gn;
			}

			DBG(DBG_X509 | DBG_CONTROL, {
					char buf[IDTOA_BUF];
					dntoa_or_null(buf, IDTOA_BUF, ca_name,
						"%any");
					DBG_log("requested CA: '%s'", buf);
				});
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
	struct payload_digest *p;
	struct state *st = md->st;

	generalName_t *requested_ca = st->st_requested_ca;

	for (p = md->chain[ISAKMP_NEXT_v2CERTREQ]; p != NULL; p = p->next) {
		struct ikev2_certreq *const cr = &p->payload.v2certreq;
		chunk_t ca_name;

		switch (cr->isacertreq_enc) {
		case CERT_X509_SIGNATURE:

			ca_name.len = pbs_left(&p->pbs);
			ca_name.ptr = (ca_name.len > 0) ? p->pbs.cur : NULL;
			DBG_cond_dump_chunk(DBG_X509, "CERT_X509_SIGNATURE CR:", ca_name);

			if (ca_name.len > 0) {
				generalName_t *gn;

				if (!is_asn1(ca_name))
					continue;

				gn = alloc_thing(generalName_t, "generalName");
				clonetochunk(ca_name, ca_name.ptr, ca_name.len,
					"ca name");
				gn->kind = GN_DIRECTORY_NAME;
				gn->name = ca_name;
				gn->next = requested_ca;
				requested_ca = gn;
			}

			DBG(DBG_X509, {
					char buf[IDTOA_BUF];
					dntoa_or_null(buf, IDTOA_BUF, ca_name,
						"%any");
					DBG_log("requested CA: '%s'", buf);
				});
			break;
#ifdef USE_GSSAPI
		case CERT_KERBEROS_TOKENS:
			if ((st->st_connection->policy & POLICY_GSSAPI) == LEMPTY) {
				DBG(DBG_CONTROL, DBG_log("Ignoring CERTREQ payload of type GSS token for non-kerberos connection"));
				continue;
			}
			libreswan_log("CERTREQ: GSS Token received: need to handle it");
			break;
#endif
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
	chunk_t result = empty_chunk;
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
	clonetochunk(result, combined_hash, sz, "combined CERTREQ hash");
	DBG(DBG_CRYPT, DBG_dump_chunk("Combined CERTREQ hashes", result));
	return result;
}
#endif

/* instead of ikev2_hash_ca_keys use this for now. a single key hash */
static chunk_t ikev2_hash_nss_cert_key(CERTCertificate *cert)
{
	unsigned char sighash[SHA1_DIGEST_SIZE];
	SHA1_CTX ctx_sha1;
	chunk_t result = empty_chunk;

	zero(&sighash);

	SHA1Init(&ctx_sha1);
	SHA1Update(&ctx_sha1, (unsigned char *)cert->derPublicKey.data,
					       cert->derPublicKey.len);
	SHA1Final(sighash, &ctx_sha1);

	DBG(DBG_CRYPT, DBG_dump("SHA-1 of Certificate Public Key",
						sighash,
						SHA1_DIGEST_SIZE));

	clonetochunk(result, sighash, SHA1_DIGEST_SIZE, "pkey hash");

	return result;
}

bool ikev1_ship_CERT(u_int8_t type, chunk_t cert, pb_stream *outs, u_int8_t np)
{
	pb_stream cert_pbs;
	struct isakmp_cert cert_hd;

	cert_hd.isacert_np = np;
	cert_hd.isacert_type = type;

	if (!out_struct(&cert_hd, &isakmp_ipsec_certificate_desc, outs,
				&cert_pbs))
		return FALSE;

	if (!out_chunk(cert, &cert_pbs, "CERT"))
		return FALSE;

	close_output_pbs(&cert_pbs);
	return TRUE;
}

bool ikev1_build_and_ship_CR(enum ike_cert_type type,
			     chunk_t ca,
			     pb_stream *outs,
			     enum next_payload_types_ikev1 np)
{
	pb_stream cr_pbs;
	struct isakmp_cr cr_hd;

	cr_hd.isacr_np = np;
	cr_hd.isacr_type = type;

	/* build CR header */
	if (!out_struct(&cr_hd, &isakmp_ipsec_cert_req_desc, outs, &cr_pbs))
		return FALSE;

	if (ca.ptr != NULL) {
		/* build CR body containing the distinguished name of the CA */
		if (!out_chunk(ca, &cr_pbs, "CA"))
			return FALSE;
	}
	close_output_pbs(&cr_pbs);
	return TRUE;
}

bool ikev2_build_and_ship_CR(enum ike_cert_type type,
			     chunk_t ca,
			     pb_stream *outs,
			     enum next_payload_types_ikev2 np)
{
	pb_stream cr_pbs;
	struct ikev2_certreq cr_hd;

	cr_hd.isacertreq_critical =  ISAKMP_PAYLOAD_NONCRITICAL;
	cr_hd.isacertreq_np = np;
	cr_hd.isacertreq_enc = type;

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
		char cbuf[ASN1_BUF_LEN];

		dntoa(cbuf, ASN1_BUF_LEN, ca);

		SECItem caname = same_chunk_as_dercert_secitem(ca);

		CERTCertificate *cacert =
			CERT_FindCertByName(CERT_GetDefaultCertDB(), &caname);

		if (cacert != NULL && CERT_IsCACert(cacert, NULL)) {
			DBG(DBG_X509, DBG_log("located CA cert %s for CERTREQ",
							  cacert->subjectName));
			/*
			 * build CR body containing the concatenated SHA-1 hashes of the
			 * CA's public key. This function currently only uses a single CA
			 * and should support more in the future
			 * */
			chunk_t cr_full_hash = ikev2_hash_nss_cert_key(cacert);

			if (!out_chunk(cr_full_hash, &cr_pbs, "CA cert public key hash")) {
				freeanychunk(cr_full_hash);
				return FALSE;
			}
			freeanychunk(cr_full_hash);
		} else {
			DBG(DBG_X509, DBG_log("could not locate CA cert %s for CERTREQ : NSS [%d]",
						cbuf, PORT_GetError()));
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
bool ikev2_send_cert_decision(struct state *st)
{
	struct connection *c = st->st_connection;
	cert_t cert = c->spd.this.cert;

	DBG(DBG_X509, DBG_log("IKEv2 CERT: send a certificate?"));

	if (!(c->policy & POLICY_RSASIG)) {
		DBG(DBG_X509,
			DBG_log("IKEv2 CERT: policy does not have RSASIG %s",
						      prettypolicy(c->policy)));
		return FALSE;
	}

	if (cert.ty == CERT_NONE || cert.u.nss_cert == NULL) {
		DBG(DBG_X509,
			DBG_log("IKEv2 CERT: no certificate to send"));
		return FALSE;
	}

	if ((c->spd.this.sendcert != cert_sendifasked ||
	      !st->hidden_variables.st_got_certrequest) &&
			c->spd.this.sendcert != cert_alwayssend)
	{
		DBG(DBG_X509,
			DBG_log("IKEv2 CERT: no cert requested or told not to send"));
		return FALSE;
	}

	DBG(DBG_X509, DBG_log("IKEv2 CERT: OK to send a certificate"));

	return TRUE;
}

stf_status ikev2_send_certreq(struct state *st, struct msg_digest *md,
				     enum original_role role UNUSED,
				     enum next_payload_types_ikev2 np,
				     pb_stream *outpbs)
{
#ifdef USE_GSSAPI
	if (st->st_connection->policy & POLICY_GSSAPI) {
		chunk_t token;

		/* XXX placeholder code */
		token.ptr = alloc_bytes(10, "fake GSS token");
		token.len = 10;

		if (!ikev2_build_and_ship_CR(CERT_KERBEROS_TOKENS,
			token, outpbs, np)) {
			return STF_INTERNAL_ERROR;
		} else {
			return STF_OK;
		}
	}
#endif

	if (st->st_connection->kind == CK_PERMANENT) {
		DBG(DBG_X509,
		    DBG_log("connection->kind is CK_PERMANENT so send CERTREQ"));

		if (!ikev2_build_and_ship_CR(CERT_X509_SIGNATURE,
					     st->st_connection->spd.that.ca,
					     outpbs, np))
			return STF_INTERNAL_ERROR;
	} else {
		generalName_t *ca = NULL;
		generalName_t *gn = NULL;
		DBG(DBG_X509,
		    DBG_log("connection->kind is not CK_PERMANENT (instance), so collect CAs"));

		if ((gn = collect_rw_ca_candidates(md)) != NULL) {
			DBG(DBG_X509,
			    DBG_log("connection is RW, lookup CA candidates"));

			for (ca = gn; ca != NULL; ca = ca->next) {
				if (!ikev2_build_and_ship_CR(CERT_X509_SIGNATURE,
						       ca->name, outpbs,
						       ca->next == NULL ? np :
							 ISAKMP_NEXT_v2CERTREQ))
					return STF_INTERNAL_ERROR;
			}
			free_generalNames(ca, FALSE);
		} else {
			DBG(DBG_X509,
			    DBG_log("Not a roadwarrior instance, sending empty CA in CERTREQ"));
			if (!ikev2_build_and_ship_CR(CERT_X509_SIGNATURE,
					       empty_chunk,
					       outpbs, np))
				return STF_INTERNAL_ERROR;
		}
	}
	return STF_OK;
}

static bool ikev2_send_certreq_INIT_decision(struct state *st,
					     enum original_role role)
{
	DBG(DBG_X509, DBG_log("IKEv2 CERTREQ: send a cert request?"));

	if (role != ORIGINAL_INITIATOR) {
		DBG(DBG_X509,
			DBG_log("IKEv2 CERTREQ: not the original initiator"));
		return FALSE;
	}

	struct connection *c = st->st_connection;

	if (!(c->policy & POLICY_RSASIG)) {
		DBG(DBG_X509,
		       DBG_log("IKEv2 CERTREQ: policy does not have RSASIG! %s",
						      prettypolicy(c->policy)));
		return FALSE;
	}

	if (has_preloaded_public_key(st)) {
		DBG(DBG_X509,
		       DBG_log("IKEv2 CERTREQ: public key already known"));
		return FALSE;
	}

	if (c->spd.that.ca.ptr == NULL || c->spd.that.ca.len < 1) {
		DBG(DBG_X509,
		       DBG_log("IKEv2 CERTREQ: no CA DN known to send"));
		return FALSE;
	}

	DBG(DBG_X509, DBG_log("IKEv2 CERTREQ: OK to send a certificate request"));

	return TRUE;
}

/* Send v2 CERT and possible CERTREQ (which should be separated eventually)  */
stf_status ikev2_send_cert(struct state *st, struct msg_digest *md,
			   enum original_role role,
			   enum next_payload_types_ikev2 np,
			   pb_stream *outpbs)
{
	struct ikev2_cert certhdr;
	struct connection *c = st->st_connection;
	cert_t mycert = st->st_connection->spd.this.cert;
	bool send_certreq = ikev2_send_certreq_INIT_decision(st, role);

	certhdr.isac_critical = ISAKMP_PAYLOAD_NONCRITICAL;
	if (DBGP(IMPAIR_SEND_BOGUS_PAYLOAD_FLAG)) {
		libreswan_log(
			" setting bogus ISAKMP_PAYLOAD_LIBRESWAN_BOGUS flag in ISAKMP payload");
		certhdr.isac_critical |= ISAKMP_PAYLOAD_LIBRESWAN_BOGUS;
	}

	certhdr.isac_enc = mycert.ty;

	if (send_certreq) {
		certhdr.isac_critical = ISAKMP_PAYLOAD_NONCRITICAL;
		if (DBGP(IMPAIR_SEND_BOGUS_PAYLOAD_FLAG)) {
			libreswan_log(" setting bogus ISAKMP_PAYLOAD_LIBRESWAN_BOGUS flag in ISAKMP payload");
			certhdr.isac_critical |= ISAKMP_PAYLOAD_LIBRESWAN_BOGUS;
		}
		certhdr.isac_np = ISAKMP_NEXT_v2CERTREQ;
	} else {
		certhdr.isac_np = np;
		/*
		 * If we have a remote id configured in the conn,
		 * we can send it here to signal we insist on it.
		 * if (st->st_connection->spd.that.id)
		 *   cert.isaa_np = ISAKMP_NEXT_v2IDr;
		 */
	}

	/*   send own (Initiator CERT) */
	{
		pb_stream cert_pbs;

		DBG(DBG_X509, DBG_log("Sending [CERT] of certificate: %s",
					mycert.u.nss_cert->subjectName));

		if (!out_struct(&certhdr, &ikev2_certificate_desc,
				outpbs, &cert_pbs))
			return STF_INTERNAL_ERROR;

		if (!out_chunk(get_dercert_from_nss_cert(mycert.u.nss_cert),
							  &cert_pbs, "CERT"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&cert_pbs);
	}

	/* send CERTREQ  */
	if (send_certreq) {
		char buf[IDTOA_BUF];
		dntoa(buf, IDTOA_BUF, c->spd.that.ca);
		DBG(DBG_X509,
		    DBG_log("Sending [CERTREQ] of %s", buf));
		ikev2_send_certreq(st, md, role, np, outpbs);
	}
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
	if (buf == NULL || buflen < 1 || cert == NULL)
		return FALSE;

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
	if (cert == NULL || cert->serialNumber.len >= dstlen)
		return 0;

	return datatot(cert->serialNumber.data, cert->serialNumber.len,
			'x', dst, dstlen);
}

static void cert_detail_to_whacklog(CERTCertificate *cert)
{
	if (cert == NULL)
		return;

	bool is_CA = CERT_IsCACert(cert, NULL);
	bool is_root = cert->isRoot;
	SECKEYPublicKey *pub_k = SECKEY_ExtractPublicKey(&cert->subjectPublicKeyInfo);

	char sn[128] = {0};
	char *print_sn = certsntoa(cert, sn, sizeof(sn)) ? sn : "(NULL)";

	bool has_priv = cert_has_private_key(cert);

	if (pub_k == NULL)
		return;

	KeyType pub_k_t = SECKEY_GetPublicKeyType(pub_k);


	whack_log(RC_COMMENT, " ");
	whack_log(RC_COMMENT, "%s%s certificate \"%s\" - SN: %s", is_root ? "Root ":"",
							 is_CA ? "CA":"End",
							 cert->nickname, print_sn);
	{
		char sbuf[ASN1_BUF_LEN];

		dntoasi(sbuf, sizeof(sbuf), cert->derSubject);
		whack_log(RC_COMMENT, "  subject: %s", sbuf);

		char ibuf[ASN1_BUF_LEN];

		dntoasi(ibuf, sizeof(ibuf), cert->derIssuer);
		whack_log(RC_COMMENT, "  issuer: %s", ibuf);
	}

	{
		char before[256] = {0};
		if (cert_detail_notbefore_to_str(before, sizeof(before), cert))
			whack_log(RC_COMMENT, "  not before: %s", before);

		char after[256] = {0};
		if (cert_detail_notafter_to_str(after, sizeof(after), cert))
			whack_log(RC_COMMENT, "  not after: %s", after);
	}

	whack_log(RC_COMMENT, "  %d bit%s%s",
				SECKEY_PublicKeyStrengthInBits(pub_k),
				pub_k_t == rsaKey ? " RSA" : "(other)",
				has_priv ? ": has private key" : "");
}

typedef enum {
	CERT_TYPE_END = 1,
	CERT_TYPE_CA = 2,
	CERT_TYPE_ANY = 3
} show_cert_t;

static bool show_cert_of_type(CERTCertificate *cert, show_cert_t type)
{
	if (cert == NULL)
		return FALSE;

	if (type == CERT_TYPE_ANY)
		return TRUE;

	if (CERT_IsCACert(cert, NULL)) {
		if (type == CERT_TYPE_CA) {
			return TRUE;
		}
	} else if (type == CERT_TYPE_END) {
		return TRUE;
	}

	return FALSE;
}

static void crl_detail_to_whacklog(CERTCrl *crl)
{
	char ibuf[ASN1_BUF_LEN];
	char lu[256] = {0}, nu[256] = {0};
	int entries = 0;

	dntoasi(ibuf, ASN1_BUF_LEN, crl->derName);

	if (crl->entries != NULL) {
		while (crl->entries[entries] != NULL)
			entries++;
	}

	whack_log(RC_COMMENT, " ");
	whack_log(RC_COMMENT, "issuer: %s", ibuf);
	whack_log(RC_COMMENT, "revoked certs: %d", entries);
	if (crl_time_to_str(lu, sizeof(lu), &crl->lastUpdate))
		whack_log(RC_COMMENT, "updates: this %s", lu);
	if (crl_time_to_str(nu, sizeof(nu), &crl->nextUpdate))
		whack_log(RC_COMMENT, "         next %s", nu);

}

static void crl_detail_list(void)
{
	CERTCertDBHandle *handle = CERT_GetDefaultCertDB();

	whack_log(RC_COMMENT, " ");
	whack_log(RC_COMMENT, "List of CRLs:");

	if (handle == NULL)
		return;

	CERTCrlHeadNode *crl_list = NULL;

	if (SEC_LookupCrls(handle, &crl_list, SEC_CRL_TYPE) != SECSuccess)
		return;

	CERTCrlNode *crl_node = crl_list->first;

	while (crl_node != NULL) {
		if (crl_node->crl != NULL)
			crl_detail_to_whacklog(&crl_node->crl->crl);

		crl_node = crl_node->next;
	}
}

static void cert_detail_list(show_cert_t type)
{
	char *tstr = "";

	switch (type) {
	case CERT_TYPE_END:
		tstr = "End ";
		break;
	case CERT_TYPE_CA:
		tstr = "CA ";
		break;
	default:
		break;
	}

	whack_log(RC_COMMENT, " ");
	whack_log(RC_COMMENT, "List of X.509 %sCertificates:", tstr);

	PK11SlotInfo *slot = PK11_GetInternalKeySlot();

	if (slot == NULL)
		return;

	if (PK11_NeedLogin(slot)) {
		SECStatus rv = PK11_Authenticate(slot, PR_TRUE,
				lsw_return_nss_password_file_info());
		if (rv != SECSuccess)
			return;
	}

	CERTCertList *certs = PK11_ListCertsInSlot(slot);

	if (certs == NULL)
		return;

	CERTCertListNode *node;

	for (node = CERT_LIST_HEAD(certs); !CERT_LIST_END(node, certs);
					 node = CERT_LIST_NEXT(node)) {
		if (show_cert_of_type(node->cert, type))
			cert_detail_to_whacklog(node->cert);
	}

	if (certs != NULL)
		CERT_DestroyCertList(certs);
}

#if defined(LIBCURL) || defined(LDAP_VER)
void check_crls(void)
{
	CERTCertDBHandle *handle = CERT_GetDefaultCertDB();

	if (handle == NULL)
		return;

	CERTCrlHeadNode *crl_list = NULL;

	if (SEC_LookupCrls(handle, &crl_list, SEC_CRL_TYPE) != SECSuccess)
		return;

	CERTCrlNode *crl_node = crl_list->first;

	while (crl_node != NULL) {
		if (crl_node->crl != NULL) {
			SECItem *issuer = &crl_node->crl->crl.derName;

			add_crl_fetch_request_nss(issuer, NULL);

			generalName_t end_dp = {
				.kind = GN_URI,
				.name = {
					.ptr = (u_char *)crl_node->crl->url,
					.len = strlen(crl_node->crl->url)
				},
				.next = NULL
			};

			add_crl_fetch_request_nss(issuer, &end_dp);
		}
		crl_node = crl_node->next;
	}

	/* add the pubkeys distribution points to fetch list */

	struct pubkey_list *pubkeys = pluto_pubkeys;
	struct pubkey *key;

	while (pubkeys != NULL) {
		key = pubkeys->key;
		if (key != NULL) {
			SECItem issuer = same_chunk_as_dercert_secitem(key->issuer);
			add_crl_fetch_request_nss(&issuer, NULL);
		}
		pubkeys = pubkeys->next;
	}
}
#endif

void list_crls(void)
{
	crl_detail_list();
}

void list_certs(void)
{
	cert_detail_list(CERT_TYPE_END);
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

void list_authcerts(void)
{
	cert_detail_list(CERT_TYPE_CA);
}

void clear_ocsp_cache(void)
{
	DBG(DBG_X509, DBG_log("calling NSS to clear OCSP cache"));
	(void)CERT_ClearOCSPCache();
}
