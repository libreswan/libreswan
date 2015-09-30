/*
 * mechanisms for preshared keys (public, private, and preshared secrets)
 *
 * this is the library for reading (and later, writing!) the ipsec.secrets
 * files.
 *
 * Copyright (C) 1998-2004  D. Hugh Redelmeier.
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2015 Paul Wouters <paul@libreswan.org>
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
#include <pthread.h>	/* pthread.h must be first include file */
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>	/* missing from <resolv.h> on old systems */
#include <glob.h>
#ifndef GLOB_ABORTED
#define GLOB_ABORTED GLOB_ABEND	/* fix for old versions */
#endif

#include <gmp.h>
#include <libreswan.h>

#include "sysdep.h"
#include "lswlog.h"
#include "constants.h"
#include "lswalloc.h"
#include "id.h"
#include "x509.h"
#include "secrets.h"
#include "certs.h"
#include "lex.h"
#include "mpzfuncs.h"

#include <nss.h>
#include <pk11pub.h>
#include <prerror.h>
#include <cert.h>
#include <key.h>
#include "lswconf.h"

/* this does not belong here, but leave it here for now */
const struct id empty_id;	/* ID_NONE */

struct fld {
	const char *name;
	size_t offset;
};

static const struct fld RSA_private_field[] =
{
	{ "Modulus", offsetof(struct RSA_private_key, pub.n) },
	{ "PublicExponent", offsetof(struct RSA_private_key, pub.e) },

	{ "PrivateExponent", offsetof(struct RSA_private_key, d) },
	{ "Prime1", offsetof(struct RSA_private_key, p) },
	{ "Prime2", offsetof(struct RSA_private_key, q) },
	{ "Exponent1", offsetof(struct RSA_private_key, dP) },
	{ "Exponent2", offsetof(struct RSA_private_key, dQ) },
	{ "Coefficient", offsetof(struct RSA_private_key, qInv) },
	{ "CKAIDNSS", offsetof(struct RSA_private_key, ckaid) },
};

static err_t lsw_process_psk_secret(chunk_t *psk);
static err_t lsw_process_rsa_secret(struct RSA_private_key *rsak);
static err_t lsw_process_rsa_keycert(struct RSA_private_key *rsak);
static void lsw_process_secret_records(struct secret **psecrets);
static void lsw_process_secrets_file(struct secret **psecrets,
				const char *file_pat);


static void RSA_show_key_fields(struct RSA_private_key *k, int fieldcnt)
{
	const struct fld *p;

	DBG_log(" keyid: *%s", k->pub.keyid);

	for (p = RSA_private_field; p < &RSA_private_field[fieldcnt]; p++) {
		MP_INT *n = (MP_INT *) ((char *)k + p->offset);
		size_t sz = mpz_sizeinbase(n, 16);
		/* ought to be big enough */
		char buf[RSA_MAX_OCTETS * 2 + 2];

		passert(sz <= sizeof(buf));
		mpz_get_str(buf, 16, n);

		DBG_log(" %s: %s", p->name, buf);
	}
}

static void RSA_show_public_key(struct RSA_public_key *k)
{
	/*
	 * Kludge: pretend that it is a private key, but only display the
	 * first two fields (which are the public key).
	 */
	passert(offsetof(struct RSA_private_key, pub) == 0);
	RSA_show_key_fields((struct RSA_private_key *)k, 2);
}

static err_t RSA_public_key_sanity(struct RSA_private_key *k)
{
	/* note that the *last* error found is reported */
	err_t ugh = NULL;

	/*
	 * PKCS#1 1.5 section 6 requires modulus to have at least 12 octets.
	 *
	 * We actually require more (for security).
	 */
	if (k->pub.k < RSA_MIN_OCTETS)
		return RSA_MIN_OCTETS_UGH;

	/* we picked a max modulus size to simplify buffer allocation */
	if (k->pub.k > RSA_MAX_OCTETS)
		return RSA_MAX_OCTETS_UGH;

	return ugh;
}

struct secret {
	struct secret  *next;
	struct id_list *ids;
	int secretlineno;
	struct private_key_stuff pks;
};

struct private_key_stuff *lsw_get_pks(struct secret *s)
{
	return &s->pks;
}

int lsw_get_secretlineno(const struct secret *s)
{
	return s->secretlineno;
}

struct id_list *lsw_get_idlist(const struct secret *s)
{
	return s->ids;
}

/*
 * This is a bad assumption, and fails when people put PSK
 * entries before the default RSA case, which most people do
 */
struct secret *lsw_get_defaultsecret(struct secret *secrets)
{
	struct secret *s, *s2;

	/* Search for PPK_RSA pks */
	s2 = secrets;
	while (s2) {
		for (; s2 && s2->pks.kind == PPK_RSA; s2 = s2->next)
			continue;
		for (s = s2; s && s->pks.kind != PPK_RSA; s = s->next)
			continue;
		if (s) {
			struct secret *tmp = s->next;
			struct secret curr = *s;
			s2->next = tmp;
			s->next = s2;
			*s = *s2;
			*s2 = curr;
			s2 = s;
		} else if (s2) {
			s2 = s2->next;
		}
	}
	return secrets;
}

/*
 * forms the keyid from the public exponent e and modulus n
 */
void form_keyid(chunk_t e, chunk_t n, char *keyid, unsigned *keysize)
{
	/* eliminate leading zero byte in modulus from ASN.1 coding */
	if (*n.ptr == 0x00) {
		n.ptr++;
		n.len--;
	}

	/* form the FreeS/WAN keyid */
	keyid[0] = '\0';	/* in case of splitkeytoid failure */
	splitkeytoid(e.ptr, e.len, n.ptr, n.len, keyid, KEYID_BUF);

	/* return the RSA modulus size in octets */
	*keysize = n.len;
}

static void form_keyid_from_nss(SECItem e, SECItem n, char *keyid,
				unsigned *keysize)
{
	/* eliminate leading zero byte in modulus from ASN.1 coding */
	if (*n.data == 0x00) {
		n.data++;
		n.len--;
	}

	/* form the FreeS/WAN keyid */
	keyid[0] = '\0';	/* in case of splitkeytoid failure */
	splitkeytoid(e.data, e.len, n.data, n.len, keyid, KEYID_BUF);

	/* return the RSA modulus size in octets */
	*keysize = n.len;
}

void free_RSA_public_content(struct RSA_public_key *rsa)
{
	mpz_clear(&rsa->n);
	mpz_clear(&rsa->e);
}

/*
 * free a public key struct
 */
void free_public_key(struct pubkey *pk)
{
	free_id_content(&pk->id);
	freeanychunk(pk->issuer);

	/* algorithm-specific freeing */
	switch (pk->alg) {
	case PUBKEY_ALG_RSA:
		free_RSA_public_content(&pk->u.rsa);
		break;
	default:
		bad_case(pk->alg);
	}
	pfree(pk);
}

struct secret *lsw_foreach_secret(struct secret *secrets,
				secret_eval func, void *uservoid)
{
	struct secret *s;

	for (s = secrets; s != NULL; s = s->next) {
		struct private_key_stuff *pks = &s->pks;
		int result = (*func)(s, pks, uservoid);

		if (result == 0)
			return s;

		if (result == -1)
			return NULL;
	}
	return NULL;
}

struct secret_byid {
	enum PrivateKeyKind kind;
	struct pubkey *my_public_key;
};

static int lsw_check_secret_byid(struct secret *secret UNUSED,
				struct private_key_stuff *pks,
				void *uservoid)
{
	struct secret_byid *sb = (struct secret_byid *)uservoid;

	DBG(DBG_CONTROL,
		DBG_log("searching for certificate %s:%s vs %s:%s",
			enum_name(&ppk_names, pks->kind),
			(pks->kind == PPK_RSA ?
				pks->u.RSA_private_key.pub.keyid : "N/A"),
			enum_name(&ppk_names, sb->kind),
			sb->my_public_key->u.rsa.keyid);
		);
	if (pks->kind == sb->kind &&
		same_RSA_public_key(&pks->u.RSA_private_key.pub,
				&sb->my_public_key->u.rsa))
		return 0;

	return 1;
}

/* ??? declared in keys.h */
struct secret *lsw_find_secret_by_public_key(struct secret *secrets,
					struct pubkey *my_public_key,
					enum PrivateKeyKind kind)
{
	struct secret_byid sb;

	sb.kind = kind;
	sb.my_public_key = my_public_key;

	return lsw_foreach_secret(secrets, lsw_check_secret_byid, &sb);
}

struct secret *lsw_find_secret_by_id(struct secret *secrets,
				enum PrivateKeyKind kind,
				const struct id *my_id,
				const struct id *his_id,
				bool asym)
{
	char idstr1[IDTOA_BUF], idme[IDTOA_BUF],
		idhim[IDTOA_BUF], idhim2[IDTOA_BUF];

	enum {	/* bits */
		match_default = 01,
		match_any = 02,
		match_him = 04,
		match_me = 010
	};
	unsigned int best_match = 0;
	struct secret *s, *best = NULL;

	idtoa(my_id,  idme,  IDTOA_BUF);

	idhim[0] = '\0';
	idhim2[0] = '\0';
	if (his_id) {
		idtoa(his_id, idhim, IDTOA_BUF);
		strcpy(idhim2, idhim);
	}

	for (s = secrets; s != NULL; s = s->next) {
		DBG(DBG_CONTROLMORE,
			DBG_log("line %d: key type %s(%s) to type %s",
				s->secretlineno,
				enum_name(&ppk_names, kind),
				idme,
				enum_name(&ppk_names, s->pks.kind));
			);

		if (s->pks.kind == kind) {
			unsigned int match = 0;

			if (s->ids == NULL) {
				/*
				 * a default (signified by lack of ids):
				 * accept if no more specific match found
				 */
				match = match_default;
			} else {
				/* check if both ends match ids */
				struct id_list *i;
				int idnum = 0;

				for (i = s->ids; i != NULL; i = i->next) {
					idnum++;
					idtoa(&i->id, idstr1, IDTOA_BUF);

					if (any_id(&i->id)) {
						/*
						 * match any will automatically
						 * match me and him so treat it
						 * as it's own match type so
						 * that specific matches get
						 * a higher "match" value and
						 * are used in preference to
						 * "any" matches.
						 */
						match |= match_any;
					} else {
						if (same_id(&i->id, my_id))
							match |= match_me;

						if (his_id != NULL &&
							same_id(&i->id,
								his_id))
							match |= match_him;
					}

					DBG(DBG_CONTROL,
						DBG_log("%d: compared key %s to %s / %s -> %d",
							idnum, idstr1, idme,
							idhim, match);
						);
				}

				/*
				 * If our end matched the only id in the list,
				 * default to matching any peer.
				 * A more specific match will trump this.
				 */
				if (match == match_me &&
					s->ids->next == NULL)
					match |= match_default;
			}

			DBG(DBG_CONTROL,
				DBG_log("line %d: match=%d", s->secretlineno,
					match);
				);

			switch (match) {
			case match_me:
				/*
				 * if this is an asymmetric (eg. public key)
				 * system, allow this-side-only match to count,
				 * even if there are other ids in the list.
				 */
				if (!asym)
					break;
				/* FALLTHROUGH */
			case match_default:	/* default all */
			case match_any:	/* a wildcard */
			case match_me | match_default:	/* default peer */
			case match_me | match_any:	/*
							 * %any/0.0.0.0 and
							 * me
							 */
			case match_him | match_any:	/*
							 * %any/0.0.0.0 and
							 * peer
							 */
			case match_me | match_him:	/* explicit */
				if (match == best_match) {
					/*
					 * two good matches are equally good:
					 * do they agree?
					 */
					bool same = 0;

					switch (kind) {
					case PPK_NULL:
							same = TRUE;
						break;
					case PPK_PSK:
						same = s->pks.u.preshared_secret.len ==
						       best->pks.u.preshared_secret.len &&
						       memeq(s->pks.u.preshared_secret.ptr,
							     best->pks.u.preshared_secret.ptr,
							     s->pks.u.preshared_secret.len);
						break;
					case PPK_RSA:
						/*
						 * Dirty trick: since we have
						 * code to compare RSA public
						 * keys, but not private keys,
						 * we make the assumption that
						 * equal public keys mean equal
						 * private keys. This ought to
						 * work.
						 */
						same = same_RSA_public_key(
							&s->pks.u.RSA_private_key.pub,
							&best->pks.u.RSA_private_key.pub);
						break;
					case PPK_XAUTH:
						/*
						 * We don't support this yet,
						 * but no need to die
						 */
						break;
					default:
						bad_case(kind);
					}
					if (!same) {
						loglog(RC_LOG_SERIOUS,
							"multiple ipsec.secrets entries with distinct secrets match endpoints: first secret used"
							);
						best = s;	/*
								 * list is
								 * backwards:
								 * take latest
								 * in list
								 */
					}
				} else if (match > best_match) {
					DBG(DBG_CONTROL,
						DBG_log("best_match %d>%d best=%p (line=%d)",
							best_match, match,
							s, s->secretlineno);
						);

					/* this is the best match so far */
					best_match = match;
					best = s;
				} else {
					DBG(DBG_CONTROL,
						DBG_log("match(%d) was not best_match(%d)",
							match, best_match);
						);
				}
			}
		}
	}
	DBG(DBG_CONTROL,
		DBG_log("concluding with best_match=%d best=%p (lineno=%d)",
			best_match, best, best ? best->secretlineno : -1);
		);

	return best;
}

static err_t extract_and_add_secret_from_nss_cert_file(struct RSA_private_key
						*rsak,
						char *nssHostCertNickName)
{
	err_t ugh = NULL;
	SECItem *certCKAID;
	SECKEYPublicKey *pubk;
	CERTCertificate *nssCert;

	DBG(DBG_CRYPT,
		DBG_log("NSS: extract_and_add_secret_from_nss_cert_file start");
		);

	nssCert = CERT_FindCertByNicknameOrEmailAddr(
		CERT_GetDefaultCertDB(), nssHostCertNickName);

	if (nssCert == NULL)
		nssCert = PK11_FindCertFromNickname(nssHostCertNickName,
					lsw_return_nss_password_file_info());

	if (nssCert == NULL) {
		libreswan_log(
			"    could not open host cert with nick name '%s' in NSS DB",
			nssHostCertNickName);
		ugh = "NSS certficate not found";
		goto error;
	}
	DBG(DBG_CRYPT,
		DBG_log("NSS: extract_and_add_secret_from_nss_cert_file: NSS Cert found");
		);

	pubk = CERT_ExtractPublicKey(nssCert);
	if (pubk == NULL) {
		loglog(RC_LOG_SERIOUS,
			"extract_and_add_secret_from_nsscert: cannot find cert's public key (err %d)",
			PR_GetError());
		ugh = "NSS cert found, pub key not found";
		goto error;
	}
	DBG(DBG_CRYPT,
		DBG_log("NSS: extract_and_add_secret_from_nss_cert_file: public key found");
		);

	/*
	 * does not return any lowkeyid
	 *
	 * certCKAID=PK11_GetLowLevelKeyIDForCert(nssCert->slot,nssCert,
	 *				lsw_return_nss_password_file_info());
	 */
	certCKAID = PK11_GetLowLevelKeyIDForCert(NULL, nssCert,
					lsw_return_nss_password_file_info());
	if (certCKAID == NULL) {
		loglog(RC_LOG_SERIOUS,
			"extract_and_add_secret_from_nsscert: cannot find cert's low level CKA ID (err %d)",
			PR_GetError());
		ugh = "cert cka id not found";
		goto error2;
	}
	DBG(DBG_CRYPT,
		DBG_log("NSS: extract_and_add_secret_from_nss_cert_file: ckaid found");
		);

	rsak->pub.nssCert = nssCert;

	passert(sizeof(rsak->ckaid) >= certCKAID->len);
	rsak->ckaid_len = certCKAID->len;
	memcpy(rsak->ckaid, certCKAID->data, certCKAID->len);

	n_to_mpz(&rsak->pub.e, pubk->u.rsa.publicExponent.data,
		pubk->u.rsa.publicExponent.len);
	n_to_mpz(&rsak->pub.n, pubk->u.rsa.modulus.data,
		pubk->u.rsa.modulus.len);

	form_keyid_from_nss(pubk->u.rsa.publicExponent, pubk->u.rsa.modulus,
			rsak->pub.keyid, &rsak->pub.k);

	/*
	 * loglog(RC_LOG_SERIOUS, "extract_and_add_secret_from_nsscert: before free (value of k %d)",
	 *	rsak->pub.k);
	 */
	SECITEM_FreeItem(certCKAID, PR_TRUE);

error2:
	/*
	 * loglog(RC_LOG_SERIOUS, "extract_and_add_secret_from_nss_cert_file: before freeing public key");
	 */
	SECKEY_DestroyPublicKey(pubk);
	/*
	 * loglog(RC_LOG_SERIOUS, "extract_and_add_secret_from_nss_cert_file: end retune fine");
	 */
error:
	DBG(DBG_CRYPT,
		DBG_log("NSS: extract_and_add_secret_from_nss_cert_file: end");
		);
	return ugh;
}

/*
 * check the existence of an RSA private key matching an RSA public
 */
bool lsw_has_private_rawkey(struct secret *secrets, struct pubkey *pk)
{
	struct secret *s;
	bool has_key = FALSE;

	if (pk == NULL)
		return FALSE;

	for (s = secrets; s != NULL; s = s->next) {
		if (s->pks.kind == PPK_RSA &&
			same_RSA_public_key(&s->pks.u.RSA_private_key.pub,
					&pk->u.rsa)) {
			has_key = TRUE;
			break;
		}
	}
	return has_key;
}

/*
 * digest a secrets file
 *
 * The file is a sequence of records.  A record is a maximal sequence of
 * tokens such that the first, and only the first, is in the first column
 * of a line.
 *
 * Tokens are generally separated by whitespace and are key words, ids,
 * strings, or data suitable for ttodata(3).  As a nod to convention,
 * a trailing ":" on what would otherwise be a token is taken as a
 * separate token.  If preceded by whitespace, a "#" is taken as starting
 * a comment: it and the rest of the line are ignored.
 *
 * One kind of record is an include directive.  It starts with "include".
 * The filename is the only other token in the record.
 * If the filename does not start with /, it is taken to
 * be relative to the directory containing the current file.
 *
 * The other kind of record describes a key.  It starts with a
 * sequence of ids and ends with key information.  Each id
 * is an IP address, a Fully Qualified Domain Name (which will immediately
 * be resolved), or @FQDN which will be left as a name.
 *
 * The form starts the key part with a ":".
 *
 * For Preshared Key, use the "PSK" keyword, and follow it by a string
 * or a data token suitable for ttodata(3).
 *
 * For raw RSA Keys in NSS, use the "RSA" keyword, followed by a
 * brace-enclosed list of key field keywords and data values.
 * The data values are large integers to be decoded by ttodata(3).
 * The fields are a subset of those used by BIND 8.2 and have the
 * same names.
 *
 * For RSA Keys from certificate imports in NSS, use the "RSA" keyword,
 * followed by the friendly_name used by NSS (usually specified during
 * key export when creating PKCS#12 files.
 *
 * For XAUTH passwords, use @username followed by ":XAUTH" followed by the password
 *
 * PIN for smartcard is no longer supported - use NSS with smartcards
 */

/*
 * process rsa key entry from certificate in NSS database
 */
static err_t lsw_process_rsa_keycert(struct RSA_private_key *rsak)
{
	char friendly_name[PATH_MAX]; /* XXX: is there an NSS limit < PATH_MAX ? */
	err_t ugh = NULL;
	bool unexpected;

	/* we expect the NSS friendly name of a PKCS#1 private key in the NSS store */

	if (*flp->tok == '"' || *flp->tok == '\'') {
		/* quoted friendly_name */
		passert(flp->tok[0] == flp->cur[-1]);	/* both quotes the same */
		passert((ptrdiff_t)sizeof(friendly_name) > flp->cur - flp->tok - 2);
		memcpy(friendly_name, flp->tok + 1, flp->cur - flp->tok - 2);
		friendly_name[flp->cur - flp->tok - 2] = '\0';
	} else {
		passert((ptrdiff_t)sizeof(friendly_name) > flp->cur - flp->tok);
		memcpy(friendly_name, flp->tok, flp->cur - flp->tok + 1);
	}

	unexpected = shift();
	/* we used to recommend people to provide an empty passphrase for NSS keys */
	if (unexpected && (streq(flp->tok, "\"\"") || streq(flp->tok, "''"))) {
		libreswan_log("RSA private key file -- ignoring empty token after friendly_name -- this will be an error in a future release");
		unexpected = shift();
	}
	if (unexpected) {
		ugh = "RSA private key file -- unexpected token after friendly_name";
	} else {
		ugh = extract_and_add_secret_from_nss_cert_file(rsak, friendly_name);
		if (ugh == NULL)
			ugh = RSA_public_key_sanity(rsak);
	}

	return ugh;
}

/* parse PSK from file */
static err_t lsw_process_psk_secret(chunk_t *psk)
{
	err_t ugh = NULL;

	if (*flp->tok == '"' || *flp->tok == '\'') {
		size_t len = flp->cur - flp->tok  - 2;

		if (len < 8) {
			loglog(RC_LOG_SERIOUS,"WARNING: using a weak secret (PSK)");
		}
		clonetochunk(*psk, flp->tok + 1, len, "PSK");
		(void) shift();
	} else {
		char buf[RSA_MAX_ENCODING_BYTES];	/*
							 * limit on size of
							 * binary
							 * representation
							 * of key
							 */
		size_t sz;
		char diag_space[TTODATAV_BUF];

		ugh = ttodatav(flp->tok, flp->cur - flp->tok, 0, buf,
			       sizeof(buf), &sz,
			       diag_space, sizeof(diag_space),
			       TTODATAV_SPACECOUNTS);
		if (ugh != NULL) {
			/* ttodata didn't like PSK data */
			ugh = builddiag("PSK data malformed (%s): %s", ugh,
					flp->tok);
		} else {
			clonetochunk(*psk, buf, sz, "PSK");
			(void) shift();
		}
	}

	DBG(DBG_CONTROL,
		DBG_log("Processing PSK at line %d: %s",
			flp->lino, ugh == NULL ? "passed" : ugh);
		);

	return ugh;
}

/* parse XAUTH secret from file */
static err_t lsw_process_xauth_secret(chunk_t *xauth)
{
	err_t ugh = NULL;

	if (*flp->tok == '"' || *flp->tok == '\'') {
		clonetochunk(*xauth, flp->tok + 1, flp->cur - flp->tok  - 2,
			"XAUTH");
		(void) shift();
	} else {
		char buf[RSA_MAX_ENCODING_BYTES];	/*
							 * limit on size of
							 * binary
							 * representation
							 * of key
							 */
		size_t sz;
		char diag_space[TTODATAV_BUF];

		ugh = ttodatav(flp->tok, flp->cur - flp->tok, 0, buf,
			       sizeof(buf), &sz,
			       diag_space, sizeof(diag_space),
			       TTODATAV_SPACECOUNTS);
		if (ugh != NULL) {
			/* ttodata didn't like PSK data */
			ugh = builddiag("PSK data malformed (%s): %s", ugh,
					flp->tok);
		} else {
			clonetochunk(*xauth, buf, sz, "XAUTH");
			(void) shift();
		}
	}

	DBG(DBG_CONTROL,
		DBG_log("Processing XAUTH at line %d: %s",
			flp->lino, ugh == NULL ? "passed" : ugh);
		);

	return ugh;
}

/*
 * Parse fields of RSA private key.
 *
 * A braced list of keyword and value pairs.
 * At the moment, each field is required, in order.
 * The fields come from BIND 8.2's representation
 */
static err_t lsw_process_rsa_secret(struct RSA_private_key *rsak)
{
	/*
	 * data structure to save public field values
	 * (Modulus and PublicExponent) for keyid calculation
	 */
	unsigned char pfv_space[RSA_MAX_ENCODING_BYTES];
	unsigned char *pfvs_next = pfv_space;
	chunk_t pub_field[2];	/* first 2 fields only */
	chunk_t *pfv_next = &pub_field[0];

	const struct fld *p;

	for (p = RSA_private_field;
		p < &RSA_private_field[elemsof(RSA_private_field)]; p++) {
		/* Binary Value of key field */
		unsigned char bv[RSA_MAX_ENCODING_BYTES];
		size_t bvlen;
		char diag_space[TTODATAV_BUF];
		err_t ugh;

		if (!shift()) {
			return "premature end of RSA key";
		} else if (!tokeqword(p->name)) {
			return builddiag(
				"%s keyword not found where expected in RSA key",
				p->name);
		} else if (!(shift() &&
				(!tokeq(":") || shift()))) {
			/* ignore optional ":" */
			return "premature end of RSA key";
		} else if (NULL !=
			(ugh = ttodatav(flp->tok, flp->cur - flp->tok, 0,
					(char *)bv, sizeof(bv),
					&bvlen,
					diag_space, sizeof(diag_space),
					TTODATAV_SPACECOUNTS))) {
			/* in RSA key, ttodata didn't like */
			return builddiag("RSA data malformed (%s): %s",
					ugh, flp->tok);
		} else if (streq(p->name, "CKAIDNSS")) {
			passert(sizeof(rsak->ckaid) >= bvlen);
			memcpy(rsak->ckaid, bv, bvlen);
			rsak->ckaid_len = bvlen;
		} else {
			MP_INT *n =
				(MP_INT *) ((char *)rsak + p->offset);

			n_to_mpz(n, bv, bvlen);
			if (pfv_next < &pub_field[elemsof(pub_field)]) {
				if (pfvs_next - pfv_space + bvlen >
					sizeof(pfv_space))
					return "public key takes too many bytes";
				setchunk(*pfv_next, pfvs_next, bvlen);
				memcpy(pfvs_next, bv, bvlen);
				pfvs_next += bvlen;
				pfv_next++;
			}
		}
	}

	/*
	 * We require an (indented) '}' and the end of the record.
	 * We break down the test so that the diagnostic will be
	 * more helpful.  Some people don't seem to wish to indent
	 * the brace!
	 */
	if (!shift() || !tokeq("}")) {
		return "malformed end of RSA private key -- indented '}' required";
	} else if (shift()) {
		return "malformed end of RSA private key -- unexpected token after '}'";
	} else {
		unsigned bits = mpz_sizeinbase(&rsak->pub.n, 2);

		rsak->pub.k = (bits + BITS_PER_BYTE - 1) / BITS_PER_BYTE;

		rsak->pub.keyid[0] = '\0';	/* in case of failure */
		splitkeytoid(pub_field[1].ptr, pub_field[1].len,
			pub_field[0].ptr, pub_field[0].len,
			rsak->pub.keyid, sizeof(rsak->pub.keyid));

		return RSA_public_key_sanity(rsak);
	}
}

static pthread_mutex_t certs_and_keys_mutex = PTHREAD_MUTEX_INITIALIZER;

#if defined(LIBCURL) || defined(LDAP_VER)
static pthread_mutex_t authcert_list_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

/*
 * lock access to my certs and keys
 */
void lock_certs_and_keys(const char *who)
{
	pthread_mutex_lock(&certs_and_keys_mutex);
	DBG(DBG_CONTROLMORE,
		DBG_log("certs and keys locked by '%s'", who);
		);
}

/*
 * unlock access to my certs and keys
 */
void unlock_certs_and_keys(const char *who)
{
	DBG(DBG_CONTROLMORE,
		DBG_log("certs and keys unlocked by '%s'", who);
		);
	pthread_mutex_unlock(&certs_and_keys_mutex);
}

#if defined(LIBCURL) || defined(LDAP_VER)

/*
 * lock access to the chained authcert list
 * ??? declared in x509.h
 */
void lock_authcert_list(const char *who)
{
	pthread_mutex_lock(&authcert_list_mutex);
	DBG(DBG_CONTROLMORE,
		DBG_log("authcert list locked by '%s'", who);
		);
}

/*
 * unlock access to the chained authcert list
 * ??? declared in x509.h
 */
void unlock_authcert_list(const char *who)
{
	DBG(DBG_CONTROLMORE,
		DBG_log("authcert list unlocked by '%s'", who);
		);
	pthread_mutex_unlock(&authcert_list_mutex);
}

#endif

static void process_secret(struct secret **psecrets,
			struct secret *s)
{
	err_t ugh = NULL;

	if (tokeqword("psk")) {
		s->pks.kind = PPK_PSK;
		/* preshared key: quoted string or ttodata format */
		ugh = !shift() ? "ERROR: unexpected end of record in PSK" :
			lsw_process_psk_secret(&s->pks.u.preshared_secret);
	} else if (tokeqword("xauth")) {
		/* xauth key: quoted string or ttodata format */
		s->pks.kind = PPK_XAUTH;
		ugh = !shift() ? "ERROR: unexpected end of record in PSK" :
			lsw_process_xauth_secret(&s->pks.u.preshared_secret);
	} else if (tokeqword("rsa")) {
		/*
		 * RSA key: the fun begins.
		 * A braced list of keyword and value pairs.
		 */
		s->pks.kind = PPK_RSA;
		if (!shift()) {
			ugh = "ERROR: bad RSA key syntax";
		} else if (tokeq("{")) {
			/* raw RSA key in NSS */
			ugh = lsw_process_rsa_secret(
					&s->pks.u.RSA_private_key);
		} else {
			/* RSA key in certificate in NSS */
			ugh = lsw_process_rsa_keycert(
				&s->pks.u.RSA_private_key);
		}
		if (!ugh) {
			libreswan_log("loaded private key for keyid: %s:%s",
				enum_name(&ppk_names, s->pks.kind),
				s->pks.u.RSA_private_key.pub.keyid);
		}
	} else if (tokeqword("pin")) {
		ugh = "ERROR: keyword 'pin' obsoleted, please use NSS for smartcard support";
	} else {
		ugh = builddiag("ERROR: unrecognized key format: %s", flp->tok);
	}

	if (ugh != NULL) {
		loglog(RC_LOG_SERIOUS, "\"%s\" line %d: %s",
			flp->filename, flp->lino, ugh);
		pfree(s);
	} else if (flushline("expected record boundary in key")) {

		/* gauntlet has been run: install new secret */
		lock_certs_and_keys("process_secret");

		if (s->ids == NULL) {
			/*
			 * make sure that empty lists have an implicit match
			 * everything set of IDs (ipv4 and ipv6)
			 */
			struct id_list *idl, *idl2;

			idl = alloc_bytes(sizeof(*idl), "id list");
			idl->next = NULL;
			idl->id = empty_id;
			idl->id.kind = ID_NONE;
			(void)anyaddr(AF_INET, &idl->id.ip_addr);

			idl2 = alloc_bytes(sizeof(*idl2), "id list");
			idl2->next = idl;
			idl2->id = empty_id;
			idl2->id.kind = ID_NONE;
			(void)anyaddr(AF_INET, &idl2->id.ip_addr);

			s->ids = idl2;
		}
		s->next   = *psecrets;
		*psecrets = s;
		unlock_certs_and_keys("process_secret");
	}
}

static void lsw_process_secret_records(struct secret **psecrets)
{
	/* const struct secret *secret = *psecrets; */

	/* read records from ipsec.secrets and load them into our table */
	for (;; ) {
		(void)flushline(NULL);	/* silently ditch leftovers, if any */
		if (flp->bdry == B_file)
			break;

		flp->bdry = B_none;	/* eat the Record Boundary */
		(void)shift();	/* get real first token */

		if (tokeqword("include")) {
			/* an include directive */
			char fn[MAX_TOK_LEN];	/*
						 * space for filename
						 * (I hope)
						 */
			char *p = fn;
			char *end_prefix = strrchr(flp->filename, '/');

			if (!shift()) {
				loglog(RC_LOG_SERIOUS,
					"\"%s\" line %d: unexpected end of include directive",
					flp->filename, flp->lino);
				continue;	/* abandon this record */
			}

			/*
			 * if path is relative and including file's pathname has
			 * a non-empty dirname, prefix this path with that
			 * dirname.
			 */
			if (flp->tok[0] != '/' && end_prefix != NULL) {
				size_t pl = end_prefix - flp->filename + 1;

				/*
				 * "clamp" length to prevent problems now;
				 * will be rediscovered and reported later.
				 */
				if (pl > sizeof(fn))
					pl = sizeof(fn);
				memcpy(fn, flp->filename, pl);
				p += pl;
			}
			if (flp->cur - flp->tok >= &fn[sizeof(fn)] - p) {
				loglog(RC_LOG_SERIOUS,
					"\"%s\" line %d: include pathname too long",
					flp->filename, flp->lino);
				continue;	/* abandon this record */
			}
			/*
			 * The above test checks that there is enough space for strcpy
			 * but clang 3.4 thinks the destination will overflow.
			 */
			strcpy(p, flp->tok);
			(void) shift();	/* move to Record Boundary, we hope */
			if (flushline("ignoring malformed INCLUDE -- expected Record Boundary after filename"))
			{
				lsw_process_secrets_file(psecrets, fn);
				flp->tok = NULL;	/* redundant? */
			}
		} else {
			/* expecting a list of indices and then the key info */
			struct secret *s = alloc_thing(struct secret, "secret");

			s->ids = NULL;
			s->pks.kind = PPK_PSK;	/* default */
			setchunk(s->pks.u.preshared_secret, NULL, 0);
			s->secretlineno = flp->lino;
			s->next = NULL;

			s->pks.u.RSA_private_key.pub.nssCert = NULL;

			for (;;) {
				struct id id;
				err_t ugh;

				if (tokeq(":")) {
					/* found key part */
					shift();	/* eat ":" */
					process_secret(psecrets, s);
					break;
				}

				/*
				 * an id
				 * See RFC2407 IPsec Domain of
				 * Interpretation 4.6.2
				 */
				if (tokeq("%any")) {
					id = empty_id;
					id.kind = ID_IPV4_ADDR;
					ugh = anyaddr(AF_INET, &id.ip_addr);
				} else if (tokeq("%any6")) {
					id = empty_id;
					id.kind = ID_IPV6_ADDR;
					ugh = anyaddr(AF_INET6, &id.ip_addr);
				} else {
					ugh = atoid(flp->tok, &id, FALSE,
						    FALSE);
				}

				if (ugh != NULL) {
					loglog(RC_LOG_SERIOUS,
						"ERROR \"%s\" line %d: index \"%s\" %s",
						flp->filename,
						flp->lino, flp->tok,
						ugh);
				} else {
					struct id_list *i = alloc_thing(
						struct id_list,
						"id_list");
					char idb[IDTOA_BUF];

					i->id = id;
					unshare_id_content(&i->id);
					i->next = s->ids;
					s->ids = i;
					idtoa(&id, idb, IDTOA_BUF);
					DBG(DBG_CONTROL,
						DBG_log("id type added to secret(%p) %s: %s",
							s,
							enum_name(&ppk_names,
								s->pks.kind),
							idb);
						);
				}
				if (!shift()) {
					/* unexpected Record Boundary or EOF */
					loglog(RC_LOG_SERIOUS,
						"\"%s\" line %d: unexpected end of id list",
						flp->filename, flp->lino);
					pfree(s);
					break;
				}
			}
		}
	}
}

static int globugh(const char *epath, int eerrno)
{
	libreswan_log_errno_routine(eerrno, "problem with secrets file \"%s\"",
				epath);
	return 1;	/* stop glob */
}

static void lsw_process_secrets_file(struct secret **psecrets,
				const char *file_pat)
{
	struct file_lex_position pos;
	char **fnp;
	glob_t globbuf;

	pos.depth = flp == NULL ? 0 : flp->depth + 1;

	if (pos.depth > 10) {
		loglog(RC_LOG_SERIOUS,
			"preshared secrets file \"%s\" nested too deeply",
			file_pat);
		return;
	}

	/* do globbing */
	{
		int r = glob(file_pat, GLOB_ERR, globugh, &globbuf);

		if (r != 0) {
			switch (r) {
			case GLOB_NOSPACE:
				loglog(RC_LOG_SERIOUS,
					"out of space processing secrets filename \"%s\"",
					file_pat);
				globfree(&globbuf);
				return;
			case GLOB_ABORTED:
				break;	/* already logged */

			case GLOB_NOMATCH:
				libreswan_log("no secrets filename matched \"%s\"",
					file_pat);
				break;

			default:
				loglog(RC_LOG_SERIOUS, "unknown glob error %d",
					r);
				globfree(&globbuf);
				return;
			}
		}
	}

	/* for each file... */
	for (fnp = globbuf.gl_pathv; fnp != NULL && *fnp != NULL; fnp++) {
		if (lexopen(&pos, *fnp, FALSE)) {
			libreswan_log("loading secrets from \"%s\"", *fnp);
			(void) flushline(
				"file starts with indentation (continuation notation)");
			lsw_process_secret_records(psecrets);
			lexclose();
		}
	}

	globfree(&globbuf);
}

void lsw_free_preshared_secrets(struct secret **psecrets)
{
	lock_certs_and_keys("free_preshared_secrets");

	if (*psecrets != NULL) {
		struct secret *s, *ns;

		libreswan_log("forgetting secrets");

		for (s = *psecrets; s != NULL; s = ns) {
			struct id_list *i, *ni;

			ns = s->next;	/* grab before freeing s */
			for (i = s->ids; i != NULL; i = ni) {
				ni = i->next;	/* grab before freeing i */
				free_id_content(&i->id);
				pfree(i);
			}
			switch (s->pks.kind) {
			case PPK_PSK:
				pfree(s->pks.u.preshared_secret.ptr);
				break;
			case PPK_XAUTH:
				pfree(s->pks.u.preshared_secret.ptr);
				break;
			case PPK_RSA:
				free_RSA_public_content(
					&s->pks.u.RSA_private_key.pub);
				mpz_clear(&s->pks.u.RSA_private_key.d);
				mpz_clear(&s->pks.u.RSA_private_key.p);
				mpz_clear(&s->pks.u.RSA_private_key.q);
				mpz_clear(&s->pks.u.RSA_private_key.dP);
				mpz_clear(&s->pks.u.RSA_private_key.dQ);
				mpz_clear(&s->pks.u.RSA_private_key.qInv);
				break;
			default:
				bad_case(s->pks.kind);
			}
			pfree(s);
		}
		*psecrets = NULL;
	}

	unlock_certs_and_keys("free_preshard_secrets");
}

void lsw_load_preshared_secrets(struct secret **psecrets,
				const char *secrets_file)
{
	lsw_free_preshared_secrets(psecrets);
	(void) lsw_process_secrets_file(psecrets, secrets_file);
}

struct pubkey *reference_key(struct pubkey *pk)
{
	pk->refcnt++;
	return pk;
}

void unreference_key(struct pubkey **pkp)
{
	struct pubkey *pk = *pkp;

	if (pk == NULL)
		return;

	/* print stuff */
	DBG(DBG_CONTROLMORE, {
			char b[IDTOA_BUF];

			idtoa(&pk->id, b, sizeof(b));
			DBG_log("unreference key: %p %s cnt %d--", pk, b,
				pk->refcnt);
		});

	/* cancel out the pointer */
	*pkp = NULL;

	passert(pk->refcnt != 0);
	pk->refcnt--;

	/* we are going to free the key as the refcount will hit zero */
	if (pk->refcnt == 0)
		free_public_key(pk);
}

/*
 * Free a public key record.
 * As a convenience, this returns a pointer to next.
 */
struct pubkey_list *free_public_keyentry(struct pubkey_list *p)
{
	struct pubkey_list *nxt = p->next;

	if (p->key != NULL)
		unreference_key(&p->key);
	pfree(p);
	return nxt;
}

void free_public_keys(struct pubkey_list **keys)
{
	while (*keys != NULL)
		*keys = free_public_keyentry(*keys);
}

/*
 * decode of RSA pubkey chunk
 * - format specified in RFC 2537 RSA/MD5 Keys and SIGs in the DNS
 * - exponent length in bytes (1 or 3 octets)
 *   + 1 byte if in [1, 255]
 *   + otherwise 0x00 followed by 2 bytes of length (big-endian)
 * - exponent (of specified length)
 * - modulus (the rest of the pubkey chunk)
 */
err_t unpack_RSA_public_key(struct RSA_public_key *rsa, const chunk_t *pubkey)
{
	chunk_t exponent;
	chunk_t mod;

	rsa->keyid[0] = '\0';	/* in case of keyblobtoid failure */

	if (pubkey->len < 3)
		return "RSA public key blob way too short";	/*
								 * not even
								 * room for
								 * length!
								 */

	/* exponent */
	if (pubkey->ptr[0] != 0x00) {
		/* one-byte length, followed by that many exponent bytes */
		setchunk(exponent, pubkey->ptr + 1, pubkey->ptr[0]);
	} else {
		/*
		 * 0x00 followed by 2 bytes of length (big-endian),
		 * followed by that many exponent bytes
		 */
		setchunk(exponent, pubkey->ptr + 3,
			(pubkey->ptr[1] << BITS_PER_BYTE) + pubkey->ptr[2]);
	}

	/*
	 * check that exponent fits within pubkey and leaves room for
	 * a reasonable modulus.
	 * Take care to avoid overflow in this check.
	 */
	if (pubkey->len -
		(exponent.ptr - pubkey->ptr) < exponent.len +
		RSA_MIN_OCTETS_RFC)
		return "RSA public key blob too short";

	/* modulus: all that's left in pubkey */
	mod.ptr = exponent.ptr + exponent.len;
	mod.len = &pubkey->ptr[pubkey->len] - mod.ptr;

	if (mod.len < RSA_MIN_OCTETS)
		return RSA_MIN_OCTETS_UGH;

	if (mod.len > RSA_MAX_OCTETS)
		return RSA_MAX_OCTETS_UGH;

	n_to_mpz(&rsa->e, exponent.ptr, exponent.len);
	n_to_mpz(&rsa->n, mod.ptr, mod.len);

	keyblobtoid(pubkey->ptr, pubkey->len, rsa->keyid, sizeof(rsa->keyid));

	DBG(DBG_PRIVATE, RSA_show_public_key(rsa));

	rsa->k = mpz_sizeinbase(&rsa->n, 2);	/* size in bits, for a start */
	rsa->k = (rsa->k + BITS_PER_BYTE - 1) / BITS_PER_BYTE;	/* now octets */

	if (rsa->k != mod.len) {
		mpz_clear(&rsa->e);
		mpz_clear(&rsa->n);
		return "RSA modulus shorter than specified";
	}

	return NULL;
}

bool same_RSA_public_key(const struct RSA_public_key *a,
			const struct RSA_public_key *b)
{
	DBG(DBG_CRYPT,
		DBG_log("k did %smatch", (a->k == b->k) ? "" : "NOT ");
		);
	DBG(DBG_CRYPT,
		DBG_log("n did %smatch",
			(mpz_cmp(&a->n,
				&b->n) == 0) ? "" : "NOT ");
		);
	DBG(DBG_CRYPT,
		DBG_log("e did %smatch",
			(mpz_cmp(&a->e,
				&b->e) == 0) ? "" : "NOT ");
		);

	return a == b ||
		(a->k == b->k &&
			mpz_cmp(&a->n, &b->n) == 0 &&
			mpz_cmp(&a->e, &b->e) == 0);
}

void install_public_key(struct pubkey *pk, struct pubkey_list **head)
{
	struct pubkey_list *p =
		alloc_thing(struct pubkey_list, "pubkey entry");

	unshare_id_content(&pk->id);

	/* copy issuer dn */
	if (pk->issuer.ptr != NULL)
		pk->issuer.ptr = clone_bytes(pk->issuer.ptr, pk->issuer.len,
					"issuer dn");

	/* store the time the public key was installed */
	pk->installed_time = realnow();

	/* install new key at front */
	p->key = reference_key(pk);
	p->next = *head;
	*head = p;
}

void delete_public_keys(struct pubkey_list **head,
			const struct id *id, enum pubkey_alg alg)
{
	struct pubkey_list **pp, *p;
	struct pubkey *pk;

	for (pp = head; (p = *pp) != NULL; ) {
		pk = p->key;
		if (same_id(id, &pk->id) && pk->alg == alg)
			*pp = free_public_keyentry(p);
		else
			pp = &p->next;
	}
}
