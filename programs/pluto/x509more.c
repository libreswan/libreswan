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
		if (!ugh) {
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
	default:
		id->kind = ID_NONE;
		id->name = empty_chunk;
	}
}

/*
 * extract id and public key from x.509 certificate and
 * insert it into a pubkeyrec
 */
void add_x509_public_key(const struct id *keyid,
			x509cert_t *cert,
			realtime_t until,
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
		struct id id;

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
	struct connection *c = md->st->st_connection;
	struct payload_digest *p;
	x509cert_t *chain = NULL;

	for (p = md->chain[ISAKMP_NEXT_CERT]; p != NULL; p = p->next) {
		struct isakmp_cert *const cert = &p->payload.cert;

		switch (cert->isacert_type) {
		case CERT_X509_SIGNATURE:
		{
			chunk_t blob;
			x509cert_t cert2 = empty_x509cert;

			clonetochunk(blob, p->pbs.cur, pbs_left(&p->pbs), "cert chain blob");

			if (parse_x509cert(blob, 0, &cert2)) {
				x509cert_t *new = clone_thing(cert2, "x509cert_t");

				new->next = chain;
				chain = new;
			} else {
				libreswan_log("Syntax error in X.509 certificate");
				freeanychunk(blob);
			}
			break;
		}

/*  http://tools.ietf.org/html/rfc4945
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
 *  PKCS7 case forklifted from above.. Needs to be tested!
 *
 */
		case CERT_PKCS7_WRAPPED_X509:
		{
			chunk_t blob;
			x509cert_t *cert2 = NULL;

			clonetochunk(blob, p->pbs.cur, pbs_left(&p->pbs), "cert chain blob");

			if (parse_pkcs7_cert(blob, &cert2)) {
				/* stick new certs at front of chain */
				/*
				 * ??? how is memory managed for the actual cert blobs?
				 * Is not freeing "blob" good enough?  Leaky?
				 */
				if (cert2 != NULL) {
					x509cert_t *p;

					for (p = cert2; p->next != NULL; p = p->next)
						;
					p->next = chain;
					chain = cert2;
				}
			} else {
				libreswan_log(
					"Syntax error in PKCS#7 wrapped X.509 certificates");
				freeanychunk(blob);
			}
			break;
		}
		default:
			loglog(RC_LOG_SERIOUS,
				"ignoring %s certificate payload",
				enum_show(&ike_cert_type_names,
					cert->isacert_type));
		}
	}

	if (chain != NULL) {
		x509cert_t *ok = NULL;
		/* certs are validated here */
		store_x509certs(&chain, &ok, strict_crl_policy);
		if (ok != NULL) {
			c->spd.that.ca_path.u.x509 = ok;
			c->spd.that.ca_path.ty = CERT_X509_SIGNATURE;
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
				realtime_t valid_until;

				if (verify_x509cert(&cert2, strict_crl_policy,
						&valid_until, NULL)) {
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
			x509cert_t *cert2 = NULL, *out = NULL;

			if (parse_pkcs7_cert(blob, &cert2))
				store_x509certs(&cert2, &out, strict_crl_policy);
			else
				libreswan_log(
					"Syntax error in PKCS#7 wrapped X.509 certificates");
			break;
		}
		default:
			loglog(RC_LOG_SERIOUS,
				"ignoring %s certificate payload",
				enum_show(&ikev2_cert_type_names,
					v2cert->isac_enc));
			DBG_cond_dump_chunk(DBG_PARSING, "CERT:\n", blob);
		}
	}
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
				clonetochunk(gn->name, ca_name.ptr, ca_name.len,
					"ca name");
				gn->kind = GN_DIRECTORY_NAME;
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
 *
 * This needs to handle the SHA-1 hashes instead. However, receiving CRs
 * does nothing ATM.
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
				enum_show(&ikev2_cert_type_names,
					cr->isacertreq_enc));
		}
	}
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

/*
 * returns the concatenated SHA-1 hashes of each public key in the chain
 * */
static chunk_t ikev2_hash_ca_keys(x509cert_t *ca_chain)
{
	unsigned char combined_hash[SHA1_DIGEST_SIZE * 8 /*max path len*/];
	x509cert_t *ca = NULL;
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
		x509cert_t *authcert = get_authcert(ca, empty_chunk,
							empty_chunk,
							AUTH_CA);
		if (authcert != NULL) {
			DBG(DBG_X509, DBG_log("located authcert %s for CERTREQ",
									 cbuf));
			/*
			 * build CR body containing the concatenated SHA-1 hashes of the
			 * CA's public key. This function currently only uses a single CA
			 * and should support more in the future
			 * */
			chunk_t cr_full_hash = ikev2_hash_ca_keys(authcert);
			if (!out_chunk(cr_full_hash, &cr_pbs, "CA cert public key hashes")) {
				freeanychunk(cr_full_hash);
				return FALSE;
			}
			freeanychunk(cr_full_hash);
		} else {
			DBG(DBG_X509, DBG_log("could not locate authcert %s for CERTREQ", cbuf));
		}
	}
	/*
	 * can it be empty?
	 * this function's returns need fixing
	 * */
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
						type, &cert))
					add_authcert(&cert.u.x509, auth_flags);

				free(filelist[n]);	/* was malloced by scandir(3) */
			}
			free(filelist);	/* was malloced by scandir(3) */
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

/*
 * choose either subject DN or a subjectAltName as connection end ID
 */
void select_x509cert_id(x509cert_t *cert, struct id *end_id)
{
	bool copy_subject_dn = TRUE;	/* ID is subject DN */

	if (end_id->kind != ID_NONE) {	/* check for matching subjectAltName */
		generalName_t *gn;

		for (gn = cert->subjectAltName; gn != NULL; gn = gn->next) {
			struct id id = empty_id;

			gntoid(&id, gn);
			if (same_id(&id, end_id)) {
				/* take subjectAltName instead */
				copy_subject_dn = FALSE;
				break;
			}
		}
	}

	if (copy_subject_dn) {
		if (end_id->kind != ID_NONE &&
			end_id->kind != ID_DER_ASN1_DN &&
			end_id->kind != ID_FROMCERT) {
			char buf[IDTOA_BUF];

			idtoa(end_id, buf, IDTOA_BUF);
			libreswan_log(
				"  no subjectAltName matches ID '%s', replaced by subject DN",
				buf);
		}
		end_id->kind = ID_DER_ASN1_DN;
		end_id->name.len = cert->subject.len;
		end_id->name.ptr = temporary_cyclic_buffer();
		memcpy(end_id->name.ptr, cert->subject.ptr, cert->subject.len);
	}
}
