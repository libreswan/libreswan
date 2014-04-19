/*
 * Support of X.509 keys
 *
 * Copyright (C) 2000 Andreas Hess, Patric Lichtsteiner, Roger Wegmann
 * Copyright (C) 2001 Marco Bertossa, Andreas Schleiss
 * Copyright (C) 2002 Mario Strasser
 * Copyright (C) 2000-2004 Andreas Steffen, Zuercher Hochschule Winterthur
 * Copyright (C) 2004-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2006 Matthias Haas" <mh@pompase.net>
 * Copyright (C) 2007-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
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
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <sys/types.h>
#include <errno.h>

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"

#include "defs.h"
#include "log.h"
#include "id.h"
#include "asn1.h"
#include "oid.h"
#include "x509.h"
#include "certs.h"
#include "keys.h"
#include "packet.h"
#include "demux.h"	/* needs packet.h */
#include "connections.h"
#include "state.h"
#include "md5.h"
#include "sha1.h"
#include "whack.h"
#include "fetch.h"
#include "pkcs.h"
#include "x509more.h"

/*
 * extract id and public key from x.509 certificate and
 * insert it into a pubkeyrec
 */
void add_x509_public_key(const struct id *keyid,
			x509cert_t *cert,
			time_t until,
			enum dns_auth_level dns_auth_level)
{
	generalName_t *gn;
	struct pubkey *pk;
	const cert_t c = { CERT_X509_SIGNATURE, { cert } };

	/* we support RSA only */
	if (cert->subjectPublicKeyAlgorithm != PUBKEY_ALG_RSA)
		return;

	/* ID type: ID_DER_ASN1_DN  (X.509 subject field) */
	pk = allocate_RSA_public_key(c);
	passert(pk != NULL);
	pk->id.kind = ID_DER_ASN1_DN;
	pk->id.name = cert->subject;
	pk->dns_auth_level = dns_auth_level;
	pk->until_time = until;
	pk->issuer = cert->issuer;
	delete_public_keys(&pluto_pubkeys, &pk->id, pk->alg);
	install_public_key(pk, &pluto_pubkeys);

	gn = cert->subjectAltName;

	while (gn != NULL) { /* insert all subjectAltNames */
		struct id id = empty_id;

		gntoid(&id, gn);
		if (id.kind != ID_NONE) {
			pk = allocate_RSA_public_key(c);
			pk->id = id;
			pk->dns_auth_level = dns_auth_level;
			pk->until_time = until;
			pk->issuer = cert->issuer;
			delete_public_keys(&pluto_pubkeys, &pk->id, pk->alg);
			install_public_key(pk, &pluto_pubkeys);
		}
		gn = gn->next;
	}

	if (keyid != NULL &&
		keyid->kind != ID_DER_ASN1_DN &&
		keyid->kind != ID_DER_ASN1_GN) {
		pk = allocate_RSA_public_key(c);
		pk->id = *keyid;

		pk->dns_auth_level = dns_auth_level;
		pk->until_time = until;
		pk->issuer = cert->issuer;
		delete_public_keys(&pluto_pubkeys, &pk->id, pk->alg);
		install_public_key(pk, &pluto_pubkeys);
	}
}

/*
 *  when a X.509 certificate gets revoked, all instances of
 *  the corresponding public key must be removed
 */
void remove_x509_public_key(/*const*/ x509cert_t *cert)
{
	const cert_t c = { CERT_X509_SIGNATURE, { cert } };
	struct pubkey_list *p, **pp;
	struct pubkey *revoked_pk;

	revoked_pk = allocate_RSA_public_key(c);
	p = pluto_pubkeys;
	pp = &pluto_pubkeys;

	while (p != NULL) {
		if (same_RSA_public_key(&p->key->u.rsa, &revoked_pk->u.rsa)) {
			/* remove p from list and free memory */
			*pp = free_public_keyentry(p);
			loglog(RC_LOG_SERIOUS,
				"invalid RSA public key deleted");
		} else {
			pp = &p->next;
		}
		p = *pp;
	}
	free_public_key(revoked_pk);
}

/*
 * Decode the CERT payload of Phase 1.
 */
void ikev1_decode_cert(struct msg_digest *md)
{
	struct payload_digest *p;

	for (p = md->chain[ISAKMP_NEXT_CERT]; p != NULL; p = p->next) {
		struct isakmp_cert *const cert = &p->payload.cert;
		chunk_t blob;

		blob.ptr = p->pbs.cur;
		blob.len = pbs_left(&p->pbs);
		switch (cert->isacert_type) {
		case CERT_X509_SIGNATURE:
		{
			x509cert_t cert2 = empty_x509cert;

			if (parse_x509cert(blob, 0, &cert2)) {
				time_t valid_until;

				if (verify_x509cert(&cert2, strict_crl_policy,
							&valid_until)) {
					DBG(DBG_X509 | DBG_PARSING,
						DBG_log("Public key validated"));
					add_x509_public_key(NULL, &cert2,
							valid_until,
							DAL_SIGNED);
				} else {
					libreswan_log("X.509 certificate rejected");
				}
				free_generalNames(cert2.subjectAltName, FALSE);
				free_generalNames(cert2.crlDistributionPoints,
						FALSE);
			} else {
				libreswan_log("Syntax error in X.509 certificate");
			}
			break;
		}
		case CERT_PKCS7_WRAPPED_X509:
		{
			x509cert_t *cert2 = NULL;

			if (parse_pkcs7_cert(blob, &cert2))
				store_x509certs(&cert2, strict_crl_policy);
			else
				libreswan_log(
					"Syntax error in PKCS#7 wrapped X.509 certificates");
			break;
		}
		default:
			loglog(RC_LOG_SERIOUS,
				"ignoring %s certificate payload",
				enum_show(&ike_cert_type_names,
					cert->isacert_type));
			DBG_cond_dump_chunk(DBG_PARSING, "CERT:\n", blob);
		}
	}
}

/* Decode IKEV2 CERT Payload */

void ikev2_decode_cert(struct msg_digest *md)
{
	struct payload_digest *p;

	for (p = md->chain[ISAKMP_NEXT_v2CERT]; p != NULL; p = p->next) {
		struct ikev2_cert *const v2cert = &p->payload.v2cert;
		chunk_t blob;

		blob.ptr = p->pbs.cur;
		blob.len = pbs_left(&p->pbs);
		switch (v2cert->isac_enc) {
		case CERT_X509_SIGNATURE:
		{
			x509cert_t cert2 = empty_x509cert;

			if (parse_x509cert(blob, 0, &cert2)) {
				time_t valid_until;

				if (verify_x509cert(&cert2, strict_crl_policy,
							&valid_until)) {
					DBG(DBG_X509 | DBG_PARSING,
						DBG_log("Public key validated"));
					add_x509_public_key(NULL, &cert2,
							valid_until,
							DAL_SIGNED);
				} else {
					libreswan_log("X.509 certificate rejected");
				}
				free_generalNames(cert2.subjectAltName, FALSE);
				free_generalNames(cert2.crlDistributionPoints,
						FALSE);
			} else {
				libreswan_log("Syntax error in X.509 certificate");
			}
			break;
		}
		case CERT_PKCS7_WRAPPED_X509:
		{
			x509cert_t *cert2 = NULL;

			if (parse_pkcs7_cert(blob, &cert2))
				store_x509certs(&cert2, strict_crl_policy);
			else
				libreswan_log(
					"Syntax error in PKCS#7 wrapped X.509 certificates");
			break;
		}
		default:
			loglog(RC_LOG_SERIOUS,
				"ignoring %s certificate payload",
				enum_show(&ike_cert_type_names,
					v2cert->isac_enc));
			DBG_cond_dump_chunk(DBG_PARSING, "CERT:\n", blob);
		}
	}
}

/*
 * Decode the CR payload of Phase 1.
 */
void ikev1_decode_cr(struct msg_digest *md, generalName_t **requested_ca)
{
	struct payload_digest *p;

	for (p = md->chain[ISAKMP_NEXT_CR]; p != NULL; p = p->next) {
		struct isakmp_cr *const cr = &p->payload.cr;
		chunk_t ca_name;

		ca_name.len = pbs_left(&p->pbs);
		ca_name.ptr = (ca_name.len > 0) ? p->pbs.cur : NULL;

		DBG_cond_dump_chunk(DBG_PARSING, "CR", ca_name);

		if (cr->isacr_type == CERT_X509_SIGNATURE) {

			if (ca_name.len > 0) {
				generalName_t *gn;

				if (!is_asn1(ca_name))
					continue;

				gn = alloc_thing(generalName_t, "generalName");
				clonetochunk(ca_name, ca_name.ptr, ca_name.len,
					"ca name");
				gn->kind = GN_DIRECTORY_NAME;
				gn->name = ca_name;
				gn->next = *requested_ca;
				*requested_ca = gn;
			}

			DBG(DBG_PARSING | DBG_CONTROL, {
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
 */
void ikev2_decode_cr(struct msg_digest *md, generalName_t **requested_ca)
{
	struct payload_digest *p;

	for (p = md->chain[ISAKMP_NEXT_v2CERTREQ]; p != NULL; p = p->next) {
		struct ikev2_certreq *const cr = &p->payload.v2certreq;
		chunk_t ca_name;

		ca_name.len = pbs_left(&p->pbs);
		ca_name.ptr = (ca_name.len > 0) ? p->pbs.cur : NULL;

		DBG_cond_dump_chunk(DBG_PARSING, "CR", ca_name);

		if (cr->isacertreq_enc == CERT_X509_SIGNATURE) {

			if (ca_name.len > 0) {
				generalName_t *gn;

				if (!is_asn1(ca_name))
					continue;

				gn = alloc_thing(generalName_t, "generalName");
				clonetochunk(ca_name, ca_name.ptr, ca_name.len,
					"ca name");
				gn->kind = GN_DIRECTORY_NAME;
				gn->name = ca_name;
				gn->next = *requested_ca;
				*requested_ca = gn;
			}

			DBG(DBG_PARSING | DBG_CONTROL, {
					char buf[IDTOA_BUF];
					dntoa_or_null(buf, IDTOA_BUF, ca_name,
						"%any");
					DBG_log("requested CA: '%s'", buf);
				});
		} else {
			loglog(RC_LOG_SERIOUS,
				"ignoring %s certificate request payload",
				enum_show(&ike_cert_type_names,
					cr->isacertreq_enc));
		}
	}
}

bool ikev1_build_and_ship_CR(u_int8_t type, chunk_t ca, pb_stream *outs, u_int8_t np)
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

bool ikev2_build_and_ship_CR(u_int8_t type, chunk_t ca, pb_stream *outs,
			u_int8_t np)
{
	pb_stream cr_pbs;
	struct ikev2_certreq cr_hd;

	cr_hd.isacertreq_critical =  ISAKMP_PAYLOAD_NONCRITICAL;
	cr_hd.isacertreq_np = np;
	cr_hd.isacertreq_enc = type;

	/* build CR header */
	if (!out_struct(&cr_hd, &ikev2_certificate_req_desc, outs, &cr_pbs))
		return FALSE;

	if (ca.ptr != NULL) {
		/* build CR body containing the distinguished name of the CA */
		if (!out_chunk(ca, &cr_pbs, "CA"))
			return FALSE;
	}
	close_output_pbs(&cr_pbs);
	return TRUE;
}
bool collect_rw_ca_candidates(struct msg_digest *md, generalName_t **top)
{
	struct connection *d = find_host_connection(&md->iface->ip_addr,
						pluto_port, (ip_address *)NULL,
						md->sender_port, LEMPTY);

	for (; d != NULL; d = d->hp_next) {
		/* must be a road warrior connection */
		if (d->kind == CK_TEMPLATE && !(d->policy & POLICY_OPPORTUNISTIC) &&
			d->spd.that.ca.ptr != NULL) {
			generalName_t *gn;
			bool new_entry = TRUE;

			for (gn = *top; gn != NULL; gn = gn->next) {
				if (same_dn(gn->name, d->spd.that.ca)) {
					new_entry = FALSE;
					break;
				}
			}
			if (new_entry) {
				gn = alloc_thing(generalName_t, "generalName");
				gn->kind = GN_DIRECTORY_NAME;
				gn->name = d->spd.that.ca;
				gn->next = *top;
				*top = gn;
			}
		}
	}
	return *top != NULL;
}

/*
 * Filter eliminating the directory entries starting with .,
*/
int filter_dotfiles(
#ifdef SCANDIR_HAS_CONST
	const
#endif
	struct dirent *entry)
{
	return entry->d_name[0] != '.';

}

/*
 *  Loads authority certificates
 */
void load_authcerts(const char *type, const char *path, u_char auth_flags)
{
	struct dirent **filelist;
	char buf[ASN1_BUF_LEN];
	char *save_dir;
	int n;

	/* change directory to specified path */
	save_dir = getcwd(buf, ASN1_BUF_LEN);

	if (chdir(path)) {
		libreswan_log("Could not change to directory '%s': %s",
			path, strerror(errno));
	} else {
		DBG(DBG_CONTROL,
			DBG_log("Changed path to directory '%s'", path));
		n = scandir(".", &filelist, (void *) filter_dotfiles, alphasort);

		if (n < 0) {
			char buff[256];
			strerror_r(errno, buff, 256);
			libreswan_log("  scandir() ./ error: %s", buff);
		} else {
			while (n--) {
				cert_t cert;

				if (load_cert(filelist[n]->d_name,
#ifdef SINGLE_CONF_DIR
						/*
						 * too verbose in
						 * single conf dir
						 */
						FALSE,
#else
						TRUE,
#endif
						type, &cert))
					add_authcert(cert.u.x509, auth_flags);

				free(filelist[n]);
			}
			free(filelist);
		}

		/* restore directory path */
		if (chdir(save_dir) != 0) {
			char buff[256];
			strerror_r(errno, buff, 256);
			libreswan_log("  chdir() ./ error: %s", buff);
		}
	}

}

/*
 * Checks if CA a is trusted by CA b
 */
bool trusted_ca(chunk_t a, chunk_t b, int *pathlen)
{
	bool match = FALSE;
	char abuf[ASN1_BUF_LEN], bbuf[ASN1_BUF_LEN];

	dntoa(abuf, ASN1_BUF_LEN, a);
	dntoa(bbuf, ASN1_BUF_LEN, b);

	DBG(DBG_X509 | DBG_CONTROLMORE,
		DBG_log("  trusted_ca called with a=%s b=%s", abuf, bbuf));

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
	if (same_dn(a, b))
		return TRUE;

	/* CA a might be a subordinate CA of b */
	lock_authcert_list("trusted_ca");

	while ((*pathlen)++ < MAX_CA_PATH_LEN) {
		x509cert_t *cacert = get_authcert(a, empty_chunk, empty_chunk,
						AUTH_CA);

		/* cacert not found or self-signed root cacert-> exit */
		if (cacert == NULL || same_dn(cacert->issuer, a))
			break;

		/* does the issuer of CA a match CA b? */
		match = same_dn(cacert->issuer, b);

		/* we have a match and exit the loop */
		if (match)
			break;

		/* go one level up in the CA chain */
		a = cacert->issuer;
	}

	unlock_authcert_list("trusted_ca");

	DBG(DBG_X509 | DBG_CONTROLMORE,
		DBG_log("  trusted_ca returning with %s",
			match ? "match" : "failed"));

	return match;
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

		if (trusted_ca(our_ca, requested_ca->name, &pathlen) &&
			pathlen < *our_pathlen)
			*our_pathlen = pathlen;
		requested_ca = requested_ca->next;
	}

	return *our_pathlen <= MAX_CA_PATH_LEN;
}
