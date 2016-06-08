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
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
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

#include <nss.h>
#include <pk11pub.h>
#include <prerror.h>
#include <cert.h>
#include <key.h>
#include "lswconf.h"
#include "lswnss.h"

/* this does not belong here, but leave it here for now */
const struct id empty_id;	/* ID_NONE */

struct fld {
	const char *name;
	ssize_t offset;
};

static const struct fld RSA_private_field[] = {
	{
		.name = "Modulus",
		.offset = offsetof(struct RSA_private_key, pub.n),
	},
	{
		.name = "PublicExponent",
		.offset = offsetof(struct RSA_private_key, pub.e),
	},

	{
		.name = "PrivateExponent",
		.offset = -1,
	},
	{
		.name = "Prime1",
		.offset = -1,
	},
	{
		.name = "Prime2",
		.offset = -1,
	},
	{
		.name = "Exponent1",
		.offset = -1,
	},
	{
		.name = "Exponent2",
		.offset = -1,
	},
	{
		.name = "Coefficient",
		.offset = -1,
	},
	{
		.name = "CKAIDNSS",
		.offset = -1,
	},
};

static err_t lsw_process_psk_secret(chunk_t *psk);
static err_t lsw_process_rsa_secret(struct RSA_private_key *rsak);
static void lsw_process_secret_records(struct secret **psecrets);
static void lsw_process_secrets_file(struct secret **psecrets,
				const char *file_pat);

void DBG_log_RSA_public_key(const struct RSA_public_key *k)
{
	DBG_log(" keyid: *%s", k->keyid);
	DBG_dump_chunk("n", k->n);
	DBG_dump_chunk("e", k->e);
	DBG_log_ckaid("CKAID", k->ckaid);
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
	struct private_key_stuff pks;
};

struct private_key_stuff *lsw_get_pks(struct secret *s)
{
	return &s->pks;
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
	while (s2 != NULL) {
		for (; s2 != NULL && s2->pks.kind == PPK_RSA; s2 = s2->next)
			continue;
		for (s = s2; s != NULL && s->pks.kind != PPK_RSA; s = s->next)
			continue;
		if (s != NULL) {
			struct secret *tmp = s->next;
			struct secret curr = *s;
			s2->next = tmp;
			s->next = s2;
			*s = *s2;
			*s2 = curr;
			s2 = s;
		} else if (s2 != NULL) {
			s2 = s2->next;
		}
	}
	return secrets;
}

static void create_empty_idlist(struct secret *s)
{
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
}

/*
 * forms the keyid from the public exponent e and modulus n
 */
void form_keyid(chunk_t e, chunk_t n, char *keyid, unsigned *keysize)
{
	/* eliminate leading zero byte in modulus from ASN.1 coding */
	if (*n.ptr == 0x00) {
		/*
		 * The "adjusted" length of modulus n in octets:
		 * [RSA_MIN_OCTETS, RSA_MAX_OCTETS].
		 *
		 * According to form_keyid() this is the modulus length
		 * less any leading byte added by DER encoding.
		 *
		 * The adjusted length is used in sign_hash() as the
		 * signature length - wouldn't PK11_SignatureLen be
		 * better?
		 *
		 * The adjusted length is used in
		 * same_RSA_public_key() as part of comparing two keys
		 * - but wouldn't that be redundant?  The direct n==n
		 * test would pick up the difference.
		 */
		DBG(DBG_CRYPT, DBG_log("XXX: adjusted modulus length %zu->%zu",
				       n.len, n.len - 1));
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
		/*
		 * The "adjusted" length of modulus n in octets:
		 * [RSA_MIN_OCTETS, RSA_MAX_OCTETS].
		 *
		 * According to form_keyid() this is the modulus length
		 * less any leading byte added by DER encoding.
		 *
		 * The adjusted length is used in sign_hash() as the
		 * signature length - wouldn't PK11_SignatureLen be
		 * better?
		 *
		 * The adjusted length is used in
		 * same_RSA_public_key() as part of comparing two keys
		 * - but wouldn't that be redundant?  The direct n==n
		 * test would pick up the difference.
		 */
		DBG(DBG_CRYPT, DBG_log("XXX: adjusted modulus length %u->%u",
				       n.len, n.len - 1));
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
	freeanychunk(rsa->n);
	freeanychunk(rsa->e);
	freeanyckaid(&rsa->ckaid);
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
	if (his_id != NULL) {
		idtoa(his_id, idhim, IDTOA_BUF);
		strcpy(idhim2, idhim);
	}

	for (s = secrets; s != NULL; s = s->next) {
		DBG(DBG_CONTROLMORE,
			DBG_log("line %d: key type %s(%s) to type %s",
				s->pks.line,
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
				DBG_log("line %d: match=%d", s->pks.line,
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
							s, s->pks.line);
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
			best_match, best, best ? best->pks.line : -1);
		);

	return best;
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
 * For XAUTH passwords, use @username followed by ":XAUTH" followed by the password
 *
 * PIN for smartcard is no longer supported - use NSS with smartcards
 */

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
 * Return true IFF CKAID starts with all of START (which is in HEX).
 */
bool ckaid_starts_with(ckaid_t ckaid, const char *start)
{
	if (strlen(start) > ckaid.nss->len * 2) {
		return FALSE;
	}
	int i;
	for (i = 0; start[i]; i++) {
		const char *p = start + i;
		unsigned byte = ckaid.nss->data[i / 2];
		/* high or low */
		unsigned nibble = (i & 1) ? (byte & 0xf) : (byte >> 4);
		char n[2] = { *p, };
		char *end;
		unsigned long ni = strtoul(n, &end, 16);
		if (*end) {
			return FALSE;
		}
		if (ni != nibble) {
			return FALSE;
		}
	}
	return TRUE;
}

char *ckaid_as_string(ckaid_t ckaid)
{
	size_t string_len = ckaid.nss->len * 2 + 1;
	char *string = alloc_bytes(string_len, "ckaid-string");
	datatot(ckaid.nss->data, ckaid.nss->len, 16, string, string_len);
	return string;
}

err_t form_ckaid_nss(const SECItem *const nss_ckaid, ckaid_t *ckaid)
{
	SECItem *dup = SECITEM_DupItem(nss_ckaid);
	if (dup == NULL) {
		return "problem saving CKAID";
	}
	ckaid->nss = dup;
	return NULL;
}

err_t form_ckaid_rsa(chunk_t modulus, ckaid_t *ckaid)
{
	/*
	 * Compute the CKAID directly using the modulus. - keep old
	 * configurations hobbling along.
	 */
	SECItem nss_modulus = same_chunk_as_secitem(modulus, siBuffer);
	SECItem *nss_ckaid = PK11_MakeIDFromPubKey(&nss_modulus);
	if (nss_ckaid == NULL) {
		return "unable to compute 'CKAID' from modulus";
	}
	DBG(DBG_CONTROLMORE, DBG_dump("computed rsa CKAID",
				      nss_ckaid->data, nss_ckaid->len));
	err_t err = form_ckaid_nss(nss_ckaid, ckaid);
	SECITEM_FreeItem(nss_ckaid, PR_TRUE);
	return err;
}

void freeanyckaid(ckaid_t *ckaid)
{
	if (ckaid && ckaid->nss) {
		SECITEM_FreeItem(ckaid->nss, PR_TRUE);
		ckaid->nss = NULL;
	}
}

void DBG_log_ckaid(const char *prefix, ckaid_t ckaid)
{
	DBG_dump(prefix, ckaid.nss->data, ckaid.nss->len);
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
	passert(tokeq("{"));
	while (1) {
		if (!shift()) {
			return "premature end of RSA key";
		}
		if (tokeq("}")) {
			break;
		}

		const struct fld *p = NULL;
		const struct fld *f;
		for (f = RSA_private_field;
		     f < RSA_private_field + elemsof(RSA_private_field);
		     f++) {
			if (tokeqword(f->name)) {
				p = f;
				break;
			}
		}
		if (p == NULL) {
			return builddiag("RSA keyword '%s' not recognised", flp->tok);
		}
		if (!shift()) {
			return "premature end of RSA key";
		}

		/* skip optional ':' */
		if (tokeq(":") && !shift()) {
			return "premature end of RSA key";
		}

		/* Binary Value of key field */
		unsigned char bv[RSA_MAX_ENCODING_BYTES];
		size_t bvlen;
		char diag_space[TTODATAV_BUF];
		err_t ugh = ttodatav(flp->tok, flp->cur - flp->tok, 0,
				     (char *)bv, sizeof(bv),
				     &bvlen,
				     diag_space, sizeof(diag_space),
				     TTODATAV_SPACECOUNTS);
		if (ugh != NULL) {
			/* in RSA key, ttodata didn't like */
			return builddiag("RSA data malformed (%s): %s",
					 ugh, flp->tok);
		}
		passert(sizeof(bv) >= bvlen);

		/* dispose of the data */
		if (p->offset >= 0) {
			DBG(DBG_CONTROLMORE, DBG_log("saving %s", p->name));
			DBG(DBG_PRIVATE, DBG_dump(p->name, bv, bvlen));
			chunk_t *n = (chunk_t*) ((char *)rsak + p->offset);
			clonetochunk(*n, bv, bvlen, p->name);
			DBG(DBG_PRIVATE, DBG_dump_chunk(p->name, *n));
		} else {
			DBG(DBG_CONTROL, DBG_log("ignoring %s", p->name));
		}
	}
	passert(tokeq("}"));
	if (shift()) {
		return "malformed end of RSA private key -- unexpected token after '}'";
	}

	/*
	 * Check that all required fields are present.
	 */
	const struct fld *p;
	for (p = RSA_private_field;
	     p < &RSA_private_field[elemsof(RSA_private_field)]; p++) {
		if (p->offset >= 0) {
			chunk_t *n = (chunk_t*) ((char *)rsak + p->offset);
			if (n->len == 0) {
				return builddiag("field '%s' either missing or empty", p->name);
			}
		}
	}

	rsak->pub.k = rsak->pub.n.len;
	rsak->pub.keyid[0] = '\0';	/* in case of failure */
	if (rsak->pub.e.len > 0 || rsak->pub.n.len >0) {
		splitkeytoid(rsak->pub.e.ptr, rsak->pub.e.len,
			     rsak->pub.n.ptr, rsak->pub.n.len,
			     rsak->pub.keyid, sizeof(rsak->pub.keyid));
	}

	/* Finally, the CKAID */
	err_t err = form_ckaid_rsa(rsak->pub.n, &rsak->pub.ckaid);
	if (err) {
		/* let caller recover from mess */
		return err;
	}

	return RSA_public_key_sanity(rsak);
}

static pthread_mutex_t certs_and_keys_mutex = PTHREAD_MUTEX_INITIALIZER;

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
			ugh = "WARNING: The :RSA secrets entries for X.509 certificates are no longer needed";
		}
		if (ugh == NULL) {
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

		create_empty_idlist(s);
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
			s->pks.line = flp->lino;
			s->next = NULL;

			for (;;) {
				struct id id;
				err_t ugh;

				if (tokeq(":")) {
					/* found key part */
					(void) shift();	/* eat ":" */
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

bool same_RSA_public_key(const struct RSA_public_key *a,
			 const struct RSA_public_key *b)
{
	/*
	 * The "adjusted" length of modulus n in octets:
	 * [RSA_MIN_OCTETS, RSA_MAX_OCTETS].
	 *
	 * According to form_keyid() this is the modulus length less
	 * any leading byte added by DER encoding.
	 *
	 * The adjusted length is used in sign_hash() as the signature
	 * length - wouldn't PK11_SignatureLen be better?
	 *
	 * The adjusted length is used in same_RSA_public_key() as
	 * part of comparing two keys - but wouldn't that be
	 * redundant?  The direct n==n test would pick up the
	 * difference.
	 */
	DBG(DBG_CRYPT,
	    if (a->k != b->k && same_chunk(a->e, b->e)) {
		    DBG_log("XXX: different modulus k (%u vs %u) modulus (%zu vs %zu) caused a mismatch",
			    a->k, b->k, a->n.len, b->n.len);
	    });

	DBG(DBG_CRYPT,
		DBG_log("k did %smatch", (a->k == b->k) ? "" : "NOT ");
		);
	DBG(DBG_CRYPT,
	    DBG_log("n did %smatch",
		    same_chunk(a->n, b->n) ? "" : "NOT ");
		);
	DBG(DBG_CRYPT,
		DBG_log("e did %smatch",
			same_chunk(a->e, b->e) ? "" : "NOT ");
		);

	return a == b ||
		(a->k == b->k &&
		 same_chunk(a->n, b->n) &&
		 same_chunk(a->e, b->e));
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

/*
 * Relocated from x509.c for convenience
 */
struct pubkey *allocate_RSA_public_key_nss(CERTCertificate *cert)
{
	ckaid_t ckaid;
	{
		SECItem *nss_ckaid = PK11_GetLowLevelKeyIDForCert(NULL, cert,
								  lsw_return_nss_password_file_info());
		if (nss_ckaid == NULL) {
			return NULL;
		}
		err_t err = form_ckaid_nss(nss_ckaid, &ckaid);
		SECITEM_FreeItem(nss_ckaid, PR_TRUE);
		if (err) {
			/* XXX: What to do with the error?  */
			return NULL;
		}
	}
	/* free: ckaid */

	chunk_t e;
	chunk_t n;
	{
		SECKEYPublicKey *nsspk = SECKEY_ExtractPublicKey(&cert->subjectPublicKeyInfo);
		if (nsspk == NULL) {
			freeanyckaid(&ckaid);
			return NULL;
		}
		e = clone_secitem_as_chunk(nsspk->u.rsa.publicExponent, "e");
		n = clone_secitem_as_chunk(nsspk->u.rsa.modulus, "n");
		SECKEY_DestroyPublicKey(nsspk);
	}
	/* free: ckaid, n, e */

	struct pubkey *pk = alloc_thing(struct pubkey, "pubkey");
	pk->u.rsa.e = e;
	pk->u.rsa.n = n;
	pk->u.rsa.ckaid = ckaid;
	/*
	 * based on comments in form_keyid, the modulus length
	 * returned by NSS might contain a leading zero and this
	 * ignores that when generating the keyid.
	 */
	form_keyid(e, n, pk->u.rsa.keyid, &pk->u.rsa.k);

	/*
	DBG(DBG_PRIVATE, RSA_show_public_key(&pk->u.rsa));
	*/

	pk->alg = PUBKEY_ALG_RSA;
	pk->id  = empty_id;
	pk->issuer = empty_chunk;

	return pk;
}

static err_t add_ckaid_to_rsa_privkey(struct RSA_private_key *rsak,
				      CERTCertificate *cert)
{
	err_t ugh = NULL;
	SECItem *certCKAID = NULL;
	SECKEYPublicKey *pubk = NULL;
	SECKEYPrivateKey *privk = NULL;

	if ((pubk = CERT_ExtractPublicKey(cert)) == NULL) {
		loglog(RC_LOG_SERIOUS,
		       "%s: should not happen: cert public key not found [%d]",
		       __FUNCTION__, PR_GetError());
		return "NSS: cert public key not found";
	}

	/* only a check */
	if ((privk = PK11_FindKeyByAnyCert(cert,
				lsw_return_nss_password_file_info())) == NULL) {
		SECKEY_DestroyPublicKey(pubk);
		return "NSS: cert private key not found";
	}
	SECKEY_DestroyPrivateKey(privk);

	certCKAID = PK11_GetLowLevelKeyIDForCert(NULL, cert,
					lsw_return_nss_password_file_info());
	if (certCKAID == NULL) {
		loglog(RC_LOG_SERIOUS,
		       "%s: no key ID - slot or DB error [%d]",
		       __FUNCTION__, PR_GetError());
		ugh = "NSS: key ID not found";
		goto out;
	}

	/*
	 * Getting a SECItem ptr from PK11_GetLowLevelKeyID doesn't mean
	 * that the private key exists. The data may be empty if there's no
	 * private key.
	 *
	 * Update: I don't think this is true anymore, hence the search for the private
	 * key above
	 */
	if (certCKAID->data == NULL || certCKAID->len < 1) {
		ugh = "NSS: no CKAID data";
		goto out;
	}

	clonetochunk(rsak->pub.e, pubk->u.rsa.publicExponent.data,
		     pubk->u.rsa.publicExponent.len, "e");
	clonetochunk(rsak->pub.n, pubk->u.rsa.modulus.data,
		     pubk->u.rsa.modulus.len, "n");
	ugh = form_ckaid_nss(certCKAID, &rsak->pub.ckaid);
	if (ugh) {
		/* let caller clean up mess */
		goto out;
	}

	form_keyid_from_nss(pubk->u.rsa.publicExponent, pubk->u.rsa.modulus,
			rsak->pub.keyid, &rsak->pub.k);

out:
	if (certCKAID != NULL) {
		SECITEM_FreeItem(certCKAID, PR_TRUE);
	}
	if (pubk != NULL) {
		SECKEY_DestroyPublicKey(pubk);
	}
	return ugh;
}

static err_t lsw_extract_nss_cert_privkey(struct RSA_private_key *rsak,
					  CERTCertificate *cert)
{
	err_t ugh = NULL;

	DBG(DBG_CRYPT,
	    DBG_log("extracting the RSA private key for %s", cert->nickname));

	if ((ugh = add_ckaid_to_rsa_privkey(rsak, cert)) != NULL) {
		return ugh;
	}

	return RSA_public_key_sanity(rsak);
}

static const struct RSA_private_key *get_nss_cert_privkey(struct secret *secrets,
							  CERTCertificate *cert)
{
	struct secret *s = NULL;
	const struct RSA_private_key *priv = NULL;
	struct pubkey *pub = allocate_RSA_public_key_nss(cert);
	if (pub == NULL) {
		return NULL;
	}

	for (s = secrets; s != NULL; s = s->next) {
		if (s->pks.kind == PPK_RSA &&
			same_RSA_public_key(&s->pks.u.RSA_private_key.pub,
					    &pub->u.rsa)) {
			priv = &s->pks.u.RSA_private_key;
			break;
		}
	}
	free_public_key(pub);
	return priv;
}

err_t lsw_add_rsa_secret(struct secret **secrets, CERTCertificate *cert)
{
	struct secret *s = NULL;
	const struct RSA_private_key *pkey = NULL;
	err_t ugh = NULL;

	if ((pkey = get_nss_cert_privkey(*secrets, cert)) != NULL) {
		DBG(DBG_CONTROL, DBG_log("secrets entry for %s already exists",
					 cert->nickname));
		return NULL;
	}
	s = alloc_thing(struct secret, "secret");
	s->pks.kind = PPK_RSA;
	s->pks.line = 0;

	if ((ugh = lsw_extract_nss_cert_privkey(&s->pks.u.RSA_private_key,
						cert)) != NULL) {
		pfree(s);
		return ugh;
	}

	lock_certs_and_keys("lsw_add_rsa_secret");

	create_empty_idlist(s);
	s->next = *secrets;
	*secrets = s;

	unlock_certs_and_keys("lsw_add_rsa_secret");

	return NULL;
}
