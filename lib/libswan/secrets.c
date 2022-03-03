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
 * Copyright (C) 2016-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2018 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2019 D. Hugh Redelmeier <hugh@mimosa.com>
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

#include <pthread.h>	/* pthread.h must be first include file */
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>	/* missing from <resolv.h> on old systems */

#include <pk11pub.h>
#include <prerror.h>
#include <cert.h>
#include <cryptohi.h>
#include <keyhi.h>

#include "lswglob.h"
#include "sysdep.h"
#include "lswlog.h"
#include "constants.h"
#include "lswalloc.h"
#include "id.h"
#include "x509.h"
#include "secrets.h"
#include "certs.h"
#include "lex.h"

#include "lswconf.h"
#include "lswnss.h"
#include "ip_info.h"
#include "nss_cert_load.h"
#include "ike_alg.h"
#include "ike_alg_hash.h"
#include "certs.h"

/*
 * Build up a diagnostic in a static buffer -- NOT RE-ENTRANT.
 *
 * Although this would be a generally useful function, it is very
 * hard to come up with a discipline that prevents different uses
 * from interfering.  It is intended that by limiting it to building
 * diagnostics, we will avoid this problem.
 * Juggling is performed to allow an argument to be a previous
 * result: the new string may safely depend on the old one.  This
 * restriction is not checked in any way: violators will produce
 * confusing results (without crashing!).
 *
 * @param fmt String format
 * @param ... strings
 * @return err_t
 */

static err_t builddiag(const char *fmt, ...) PRINTF_LIKE(1);	/* NOT RE-ENTRANT */
static err_t builddiag(const char *fmt, ...)
{
	/* longer messages will be truncated */
	static char mydiag_space[LOG_WIDTH];
	char t[sizeof(mydiag_space)];	/* build result here first */
	va_list args;
	va_start(args, fmt);
	t[0] = '\0';	/* in case nothing terminates string */
	vsnprintf(t, sizeof(t), fmt, args);
	va_end(args);
	strcpy(mydiag_space, t);
	return mydiag_space;
}

struct fld {
	const char *name;
	ssize_t offset;
};

static void process_secrets_file(struct file_lex_position *flp,
				 struct secret **psecrets, const char *file_pat);

struct secret {
	struct secret *next;
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
 * forms the keyid from the public exponent e and modulus n
 */
void form_keyid(chunk_t e, chunk_t n, keyid_t *keyid, size_t *keysize)
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
		DBGF(DBG_CRYPT, "XXX: adjusted modulus length %zu->%zu",
		     n.len, n.len - 1);
		n.ptr++;
		n.len--;
	}

	/* form the Libreswan keyid */
	err_t err = splitkey_to_keyid(e.ptr, e.len, n.ptr, n.len, keyid);
	passert(err == NULL);

	/* return the RSA modulus size in octets */
	*keysize = n.len;
}

const struct pubkey_type *pubkey_alg_type(enum pubkey_alg alg)
{
	static const struct pubkey_type *pubkey_types[] = {
		[PUBKEY_ALG_RSA] = &pubkey_type_rsa,
		[PUBKEY_ALG_ECDSA] = &pubkey_type_ecdsa,
	};
	passert(alg < elemsof(pubkey_types));
	const struct pubkey_type *type = pubkey_types[alg];
	pexpect(type != NULL);
	return type;
}

/*
 * XXX: Go for a simplicity - a switch is easier than adding to
 * pubkey_type - especially when the fields could end up moving to
 * struct pubkey proper (we can but dream).
 */

const keyid_t *pubkey_keyid(const struct pubkey *pk)
{
	switch (pk->type->alg) {
	case PUBKEY_ALG_RSA:
	case PUBKEY_ALG_ECDSA:
		return &pk->keyid;
	default:
		bad_case(pk->type->alg);
	}
}

const ckaid_t *pubkey_ckaid(const struct pubkey *pk)
{
	return &pk->ckaid;
}

const ckaid_t *secret_ckaid(const struct secret *secret)
{
	if (secret->pks.pubkey_type != NULL) {
		return &secret->pks.ckaid;
	} else {
		return NULL;
	}
}

const keyid_t *secret_keyid(const struct secret *secret)
{

	if (secret->pks.pubkey_type != NULL) {
		switch (secret->pks.pubkey_type->alg) {
		case PUBKEY_ALG_RSA:
		case PUBKEY_ALG_ECDSA:
			return &secret->pks.keyid;
		default:
			bad_case(secret->pks.pubkey_type->alg);
		}
	} else {
		return NULL;
	}
}

unsigned pubkey_size(const struct pubkey *pk)
{
	switch (pk->type->alg) {
	case PUBKEY_ALG_RSA:
	case PUBKEY_ALG_ECDSA:
		return pk->size;
	default:
		bad_case(pk->type->alg);
	}
}

struct secret *lsw_foreach_secret(struct secret *secrets,
				secret_eval func, void *uservoid)
{
	for (struct secret *s = secrets; s != NULL; s = s->next) {
		struct private_key_stuff *pks = &s->pks;
		int result = (*func)(s, pks, uservoid);

		if (result == 0)
			return s;

		if (result == -1)
			break;
	}
	return NULL;
}

static struct secret *find_secret_by_pubkey_ckaid_1(struct secret *secrets,
						    const struct pubkey_type *type,
						    const SECItem *pubkey_ckaid)
{
	for (struct secret *s = secrets; s != NULL; s = s->next) {
		const struct private_key_stuff *pks = &s->pks;
		dbg("trying secret %s:%s",
		    enum_name(&private_key_kind_names, pks->kind),
		    str_keyid(pks->keyid));
		if (type == NULL/*wildcard*/ ||
		    s->pks.pubkey_type == type) {
			/* only public/private key pairs have a CKAID */
			const ckaid_t *sckaid = secret_ckaid(s);
			if (sckaid != NULL &&
			    ckaid_eq_nss(sckaid, pubkey_ckaid)) {
				dbg("matched");
				return s;
			}
		}
	}
	return NULL;
}

struct secret *lsw_find_secret_by_id(struct secret *secrets,
				     enum private_key_kind kind,
				     const struct id *local_id,
				     const struct id *remote_id,
				     bool asym)
{
	enum {
		match_none = 000,

		/* bits */
		match_default = 001,
		match_any = 002,
		match_remote = 004,
		match_local = 010
	};
	unsigned int best_match = match_none;
	struct secret *best = NULL;

	for (struct secret *s = secrets; s != NULL; s = s->next) {
		if (DBGP(DBG_BASE)) {
			id_buf idl;
			DBG_log("line %d: key type %s(%s) to type %s",
				s->pks.line,
				enum_name(&private_key_kind_names, kind),
				str_id(local_id, &idl),
				enum_name(&private_key_kind_names, s->pks.kind));
		}

		if (s->pks.kind == kind) {
			unsigned int match = match_none;

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
					if (id_is_any(&i->id)) {
						/*
						 * match any will
						 * automatically match
						 * local and remote so
						 * treat it as its own
						 * match type so that
						 * specific matches
						 * get a higher
						 * "match" value and
						 * are used in
						 * preference to "any"
						 * matches.
						 */
						match |= match_any;
					} else {
						if (same_id(&i->id, local_id)) {
							match |= match_local;
						}

						if (remote_id != NULL &&
						    same_id(&i->id, remote_id)) {
							match |= match_remote;
						}
					}

					if (DBGP(DBG_BASE)) {
						id_buf idi;
						id_buf idl;
						id_buf idr;
						DBG_log("%d: compared key %s to %s / %s -> 0%02o",
							idnum,
							str_id(&i->id, &idi),
							str_id(local_id, &idl),
							(remote_id == NULL ? "" : str_id(remote_id, &idr)),
							match);
					}
				}

				/*
				 * If our end matched the only id in the list,
				 * default to matching any peer.
				 * A more specific match will trump this.
				 */
				if (match == match_local &&
				    s->ids->next == NULL)
					match |= match_default;
			}

			dbg("line %d: match=0%02o", s->pks.line, match);

			if (match == match_none) {
				continue;
			}

			if (match == best_match) {
				/*
				 * two good matches are equally good:
				 * do they agree?
				 */
				bool same = false;

				switch (kind) {
				case PKK_NULL:
					same = true;
					break;
				case PKK_PSK:
					same = hunk_eq(s->pks.u.preshared_secret,
						       best->pks.u.preshared_secret);
					break;
				case PKK_RSA:
					/*
					 * Dirty trick: since we have
					 * code to compare RSA public
					 * keys, but not private keys,
					 * we make the assumption that
					 * equal public keys mean
					 * equal private keys. This
					 * ought to work.
					 */
					same = same_RSA_public_key(
						&s->pks.u.RSA_private_key.pub,
						&best->pks.u.RSA_private_key.pub);
					break;
				case PKK_ECDSA:
					/* there are no ECDSA kind of secrets */
					/* ??? this seems not to be the case */
					break;
				case PKK_XAUTH:
					/*
					 * We don't support this yet,
					 * but no need to die.
					 */
					break;
				case PKK_PPK:
					same = hunk_eq(s->pks.ppk,
						       best->pks.ppk);
					break;
				default:
					bad_case(kind);
				}
				if (!same) {
					dbg("multiple ipsec.secrets entries with distinct secrets match endpoints: first secret used");
					/*
					 * list is backwards: take
					 * latest in list
					 */
					best = s;
				}
				continue;
			}

			if (match == match_local && !asym) {
				/*
				 * Only when this is an asymmetric
				 * (eg. public key) system, allow
				 * this-side-only match to count, even
				 * when there are other ids in the
				 * list.
				 */
				continue;
			}

			switch (match) {
			case match_local:
			case match_default:	/* default all */
			case match_any:	/* a wildcard */
			case match_local | match_default:	/* default peer */
			case match_local | match_any: /* %any/0.0.0.0 and local */
			case match_remote | match_any: /* %any/0.0.0.0 and remote */
			case match_local | match_remote:	/* explicit */
				/*
				 * XXX: what combinations are missing?
				 */
				if (match > best_match) {
					dbg("match 0%02o beats previous best_match 0%02o match=%p (line=%d)",
					    match, best_match, s, s->pks.line);
					/* this is the best match so far */
					best_match = match;
					best = s;
				} else {
					dbg("match 0%02o loses to best_match 0%02o",
					    match, best_match);
				}
			}
		}
	}

	dbg("concluding with best_match=0%02o best=%p (lineno=%d)",
	    best_match, best,
	    best == NULL ? -1 : best->pks.line);

	return best;
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
 * For Post-Quantum Preshared Keys, use the "PPKS" keyword if the PPK is static.
 *
 * PIN for smartcard is no longer supported - use NSS with smartcards
 */

/* parse PSK from file */
static err_t process_psk_secret(struct file_lex_position *flp, chunk_t *psk)
{
	err_t ugh = NULL;

	if (flp->quote == '"' || flp->quote == '\'') {
		size_t len = strlen(flp->tok);
		if (len < 8) {
			llog(RC_LOG_SERIOUS, flp->logger,
			     "WARNING: using a weak secret (PSK)");
		}
		*psk = clone_bytes_as_chunk(flp->tok, len, "PSK");
		shift(flp);
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
			*psk = clone_bytes_as_chunk(buf, sz, "PSK");
			shift(flp);
		}
	}

	dbg("processing PSK at line %d: %s",
	    flp->lino, ugh == NULL ? "passed" : ugh);

	return ugh;
}

/* parse XAUTH secret from file */
static err_t process_xauth_secret(struct file_lex_position *flp, chunk_t *xauth)
{
	err_t ugh = NULL;

	if (flp->quote == '"' || flp->quote == '\'') {
		*xauth = clone_bytes_as_chunk(flp->tok, strlen(flp->tok), "XAUTH");
		shift(flp);
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
			*xauth = clone_bytes_as_chunk(buf, sz, "XAUTH");
			shift(flp);
		}
	}

	dbg("processing XAUTH at line %d: %s",
	    flp->lino, ugh == NULL ? "passed" : ugh);

	return ugh;
}

/* parse static PPK */
static err_t process_ppk_static_secret(struct file_lex_position *flp,
				       chunk_t *ppk, chunk_t *ppk_id)
{
	err_t ugh = NULL;

	if (flp->quote == '"' || flp->quote == '\'') {
		*ppk_id = clone_bytes_as_chunk(flp->tok, strlen(flp->tok), "PPK ID");
	} else {
		ugh = "No quotation marks found. PPK ID should be in quotation marks";
		return ugh;
	}

	if (!shift(flp)) {
		ugh = "No PPK found. PPK should be specified after PPK ID";
		free_chunk_content(ppk_id);
		return ugh;
	}

	if (flp->quote == '"' || flp->quote == '\'') {
		*ppk = clone_bytes_as_chunk(flp->tok, strlen(flp->tok), "PPK");
		shift(flp);
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
			/* ttodata didn't like PPK data */
			ugh = builddiag("PPK data malformed (%s): %s", ugh,
					flp->tok);
			free_chunk_content(ppk_id);
		} else {
			*ppk = clone_bytes_as_chunk(buf, sz, "PPK");
			shift(flp);
		}
	}

	dbg("processing PPK at line %d: %s",
	    flp->lino, ugh == NULL ? "passed" : ugh);

	return ugh;
}

struct secret *lsw_get_ppk_by_id(struct secret *s, chunk_t ppk_id)
{
	while (s != NULL) {
		struct private_key_stuff pks = s->pks;
		if (pks.kind == PKK_PPK && hunk_eq(pks.ppk_id, ppk_id))
			return s;
		s = s->next;
	}
	return NULL;
}

static SECKEYPrivateKey *copy_private_key(SECKEYPrivateKey *private_key)
{
	SECKEYPrivateKey *unpacked_key = NULL;
	if (private_key->pkcs11Slot != NULL) {
		PK11SlotInfo *slot = PK11_ReferenceSlot(private_key->pkcs11Slot);
		if (slot != NULL) {
			dbg("copying key using reference slot");
			unpacked_key = PK11_CopyTokenPrivKeyToSessionPrivKey(slot, private_key);
			PK11_FreeSlot(slot);
		}
	}
	if (unpacked_key == NULL) {
		CK_MECHANISM_TYPE mech = PK11_MapSignKeyType(private_key->keyType);
		PK11SlotInfo *slot = PK11_GetBestSlot(mech, NULL);
		if (slot != NULL) {
			dbg("copying key using mech/slot");
			unpacked_key = PK11_CopyTokenPrivKeyToSessionPrivKey(slot, private_key);
			PK11_FreeSlot(slot);
		}
	}
	if (unpacked_key == NULL) {
		dbg("copying key using SECKEY_CopyPrivateKey()");
		unpacked_key = SECKEY_CopyPrivateKey(private_key);
	}
	return unpacked_key;
}

static pthread_mutex_t certs_and_keys_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * lock access to my certs and keys
 */
static void lock_certs_and_keys(const char *who)
{
	pthread_mutex_lock(&certs_and_keys_mutex);
	dbg("certs and keys locked by '%s'", who);
}

/*
 * unlock access to my certs and keys
 */
static void unlock_certs_and_keys(const char *who)
{
	dbg("certs and keys unlocked by '%s'", who);
	pthread_mutex_unlock(&certs_and_keys_mutex);
}

static void add_secret(struct secret **slist,
		       struct secret *s,
		       const char *story)
{
	/*
	 * If the ID list is empty, add two empty IDs.
	 *
	 * XXX: The below seem to be acting as a sentinal so that
	 * lsw_find_secret_by_id() always finds something (they act as
	 * wildcards) in the ID list.
	 *
	 * But why are two needed?!?.
	 */
	if (s->ids == NULL) {
		struct id_list *idl = alloc_bytes(sizeof(struct id_list), "id list");
		idl->next = NULL;
		idl->id = empty_id;
		idl->id.kind = ID_NONE;
		idl->id.ip_addr = unset_address;

		struct id_list *idl2 = alloc_bytes(sizeof(struct id_list), "id list");
		idl2->next = idl;
		idl2->id = empty_id;
		idl2->id.kind = ID_NONE;
		idl2->id.ip_addr = unset_address;

		s->ids = idl2;
	}

	lock_certs_and_keys(story);
	s->next = *slist;
	*slist = s;
	unlock_certs_and_keys(story);
}

static void process_secret(struct file_lex_position *flp,
			   struct secret **psecrets, struct secret *s)
{
	err_t ugh = NULL;

	if (tokeqword(flp, "psk")) {
		s->pks.kind = PKK_PSK;
		/* preshared key: quoted string or ttodata format */
		ugh = !shift(flp) ? "ERROR: unexpected end of record in PSK" :
			process_psk_secret(flp, &s->pks.u.preshared_secret);
	} else if (tokeqword(flp, "xauth")) {
		/* xauth key: quoted string or ttodata format */
		s->pks.kind = PKK_XAUTH;
		ugh = !shift(flp) ? "ERROR: unexpected end of record in PSK" :
			process_xauth_secret(flp, &s->pks.u.preshared_secret);
	} else if (tokeqword(flp, "ppks")) {
		s->pks.kind = PKK_PPK;
		ugh = !shift(flp) ? "ERROR: unexpected end of record in static PPK" :
			process_ppk_static_secret(flp, &s->pks.ppk, &s->pks.ppk_id);
	} else {
		ugh = builddiag("WARNING: ignored unrecognized keyword: %s", flp->tok);
	}

	if (ugh != NULL) {
		llog(RC_LOG_SERIOUS, flp->logger,
			    "\"%s\" line %d: %s",
			    flp->filename, flp->lino, ugh);
		/* free id's that should have been allocated */
		if (s->ids != NULL) {
			struct id_list *i, *ni;
			for (i = s->ids; i != NULL; i = ni) {
				ni = i->next;	/* grab before freeing i */
				free_id_content(&i->id);
				pfree(i);
			}
		}
		/* finally free s */
		pfree(s);
	} else if (flushline(flp, "expected record boundary in key")) {
		/* gauntlet has been run: install new secret */
		add_secret(psecrets, s, "process_secret");
	}
}

static void process_secret_records(struct file_lex_position *flp,
				   struct secret **psecrets)
{
	/* const struct secret *secret = *psecrets; */

	/* read records from ipsec.secrets and load them into our table */
	for (;; ) {
		flushline(flp, NULL);	/* silently ditch leftovers, if any */
		if (flp->bdry == B_file)
			break;

		flp->bdry = B_none;	/* eat the Record Boundary */
		shift(flp);	/* get real first token */

		if (tokeqword(flp, "include")) {
			/* an include directive */
			char fn[MAX_TOK_LEN];	/*
						 * space for filename
						 * (I hope)
						 */
			char *p = fn;
			char *end_prefix = strrchr(flp->filename, '/');

			if (!shift(flp)) {
				llog(RC_LOG_SERIOUS, flp->logger,
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
				llog(RC_LOG_SERIOUS, flp->logger,
					    "\"%s\" line %d: include pathname too long",
					    flp->filename, flp->lino);
				continue;	/* abandon this record */
			}
			/*
			 * The above test checks that there is enough space for strcpy
			 * but clang 3.4 thinks the destination will overflow.
			 *	strcpy(p, flp->tok);
			 * Rewrite as a memcpy in the hope of calming it.
			 */
			memcpy(p, flp->tok, flp->cur - flp->tok + 1);
			shift(flp);	/* move to Record Boundary, we hope */
			if (flushline(flp, "ignoring malformed INCLUDE -- expected Record Boundary after filename")) {
				process_secrets_file(flp, psecrets, fn);
				flp->tok = NULL;	/* redundant? */
			}
		} else {
			/* expecting a list of indices and then the key info */
			struct secret *s = alloc_thing(struct secret, "secret");

			s->ids = NULL;
			s->pks.kind = PKK_PSK;	/* default */
			s->pks.u.preshared_secret = EMPTY_CHUNK;
			s->pks.line = flp->lino;
			s->next = NULL;

			for (;;) {
				struct id id;
				err_t ugh;

				if (tokeq(flp, ":")) {
					/* found key part */
					shift(flp);	/* eat ":" */
					process_secret(flp, psecrets, s);
					break;
				}

				/*
				 * an id
				 * See RFC2407 IPsec Domain of
				 * Interpretation 4.6.2
				 */
				if (tokeq(flp, "%any")) {
					id = empty_id;
					id.kind = ID_IPV4_ADDR;
					id.ip_addr = ipv4_info.address.unspec;
					ugh = NULL;
				} else if (tokeq(flp, "%any6")) {
					id = empty_id;
					id.kind = ID_IPV6_ADDR;
					id.ip_addr = ipv6_info.address.unspec;
					ugh = NULL;
				} else {
					ugh = atoid(flp->tok, &id);
				}

				if (ugh != NULL) {
					llog(RC_LOG_SERIOUS, flp->logger,
						    "ERROR \"%s\" line %d: index \"%s\" %s",
						    flp->filename,
						    flp->lino, flp->tok,
						    ugh);
				} else {
					struct id_list *i = alloc_thing(
						struct id_list,
						"id_list");

					i->id = id;
					i->next = s->ids;
					s->ids = i;
					id_buf b;
					dbg("id type added to secret(%p) %s: %s",
					    s, enum_name(&private_key_kind_names, s->pks.kind),
					    str_id(&id, &b));
				}
				if (!shift(flp)) {
					/* unexpected Record Boundary or EOF */
					llog(RC_LOG_SERIOUS, flp->logger,
						    "\"%s\" line %d: unexpected end of id list",
						    flp->filename, flp->lino);
					pfree(s);
					break;
				}
			}
		}
	}
}

static void process_secrets_file(struct file_lex_position *oflp,
				 struct secret **psecrets, const char *file_pat)
{
	if (oflp->depth > 10) {
		llog(RC_LOG_SERIOUS, oflp->logger,
			    "preshared secrets file \"%s\" nested too deeply",
			    file_pat);
		return;
	}

	/* do globbing */
	glob_t globbuf;
	int r = lswglob(file_pat, &globbuf, "secrets", oflp->logger);

	switch (r) {
	case 0:
		/* success */
		/* for each file... */
		for (char **fnp = globbuf.gl_pathv; fnp != NULL && *fnp != NULL; fnp++) {
			struct file_lex_position *flp = NULL;
			if (lexopen(&flp, *fnp, false, oflp)) {
				llog(RC_LOG, flp->logger,
					    "loading secrets from \"%s\"", *fnp);
				flushline(flp, "file starts with indentation (continuation notation)");
				process_secret_records(flp, psecrets);
				lexclose(&flp);
			}
		}
		break;

	case GLOB_NOSPACE:
		llog(RC_LOG_SERIOUS, oflp->logger,
			    "out of space processing secrets filename \"%s\"",
			    file_pat);
		break;

	case GLOB_ABORTED:
		/* already logged by globugh_secrets() */
		break;

	case GLOB_NOMATCH:
		llog(RC_LOG, oflp->logger,
			    "no secrets filename matched \"%s\"", file_pat);
		break;

	default:
		llog(RC_LOG_SERIOUS, oflp->logger,
			    "unknown glob error %d", r);
		break;
	}

	globfree(&globbuf);
}

void lsw_free_preshared_secrets(struct secret **psecrets, struct logger *logger)
{
	lock_certs_and_keys("free_preshared_secrets");

	if (*psecrets != NULL) {
		struct secret *s, *ns;

		llog(RC_LOG, logger, "forgetting secrets");

		for (s = *psecrets; s != NULL; s = ns) {
			struct id_list *i, *ni;

			ns = s->next;	/* grab before freeing s */
			for (i = s->ids; i != NULL; i = ni) {
				ni = i->next;	/* grab before freeing i */
				free_id_content(&i->id);
				pfree(i);
			}
			switch (s->pks.kind) {
			case PKK_PSK:
				pfree(s->pks.u.preshared_secret.ptr);
				break;
			case PKK_PPK:
				pfree(s->pks.ppk.ptr);
				pfree(s->pks.ppk_id.ptr);
				break;
			case PKK_XAUTH:
				pfree(s->pks.u.preshared_secret.ptr);
				break;
			case PKK_RSA:
			case PKK_ECDSA:
				/* Note: pub is all there is */
				s->pks.pubkey_type->free_secret_content(&s->pks);
				break;
			default:
				bad_case(s->pks.kind);
			}
			pfree(s);
		}
		*psecrets = NULL;
	}

	unlock_certs_and_keys("free_preshared_secrets");
}

void lsw_load_preshared_secrets(struct secret **psecrets, const char *secrets_file,
				struct logger *logger)
{
	lsw_free_preshared_secrets(psecrets, logger);
	struct file_lex_position flp = {
		.logger = logger,
		.depth = 0,
	};
	process_secrets_file(&flp, psecrets, secrets_file);
}

struct pubkey *pubkey_addref(struct pubkey *pk, where_t where)
{
	return addref_where(pk, where);
}

/*
 * free a public key struct
 */
static void free_pubkey(void *obj, where_t where UNUSED)
{
	struct pubkey *pk = obj;
	free_id_content(&pk->id);
	/* algorithm-specific freeing */
	pk->type->free_pubkey_content(&pk->u);
	pfree(pk);
}

void pubkey_delref(struct pubkey **pkp, where_t where)
{
	delref_where(pkp, where);
}

/*
 * Free a public key record.
 * As a convenience, this returns a pointer to next.
 */
struct pubkey_list *free_public_keyentry(struct pubkey_list *p)
{
	struct pubkey_list *nxt = p->next;

	if (p->key != NULL)
		pubkey_delref(&p->key, HERE);
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
	if (DBGP(DBG_CRYPT)) {
	    DBG_log("n did %smatch", hunk_eq(a->n, b->n) ? "" : "NOT ");
	    DBG_log("e did %smatch", hunk_eq(a->e, b->e) ? "" : "NOT ");
	}

	return a == b ||
		(hunk_eq(a->n, b->n) &&
		 hunk_eq(a->e, b->e));
}

/*
 * XXX: this gets called, via replace_public_key() with a PK that is
 * still pointing into a cert.  Hence the "how screwed up is this?"
 * :-(
 */
static void install_public_key(struct pubkey **pk, struct pubkey_list **head)
{
	struct pubkey_list *p = alloc_thing(struct pubkey_list, "pubkey entry");
	/* install new key at front */
	p->key = *pk;
	p->next = *head;
	*head = p;
	*pk = NULL; /* stolen */
}

void delete_public_keys(struct pubkey_list **head,
			const struct id *id,
			const struct pubkey_type *type)
{
	struct pubkey_list **pp, *p;

	for (pp = head; (p = *pp) != NULL; ) {
		struct pubkey *pk = p->key;

		if (same_id(id, &pk->id) && pk->type == type)
			*pp = free_public_keyentry(p);
		else
			pp = &p->next;
	}
}

void replace_public_key(struct pubkey_list **pubkey_db,
			struct pubkey **pk)
{
	/* ??? clang 3.5 thinks pk might be NULL */
	delete_public_keys(pubkey_db, &(*pk)->id, (*pk)->type);
	install_public_key(pk, pubkey_db);
	passert(*pk == NULL); /* stolen */
}

static struct pubkey *alloc_pubkey(const struct id *id, /* ASKK */
				   enum dns_auth_level dns_auth_level,
				   const struct pubkey_type *type,
				   realtime_t install_time, realtime_t until_time,
				   uint32_t ttl,
				   const union pubkey_content *pkc,
				   const keyid_t *keyid,
				   const ckaid_t *ckaid,
				   shunk_t issuer,
				   size_t size,
				   where_t where)
{
	struct pubkey *pk = refcnt_overalloc(struct pubkey, issuer.len,
					     free_pubkey, where);
	pk->u = *pkc;
	pk->id = clone_id(id, "public key id");
	pk->dns_auth_level = dns_auth_level;
	pk->type = type;
	pk->installed_time = install_time;
	pk->until_time = until_time;
	pk->dns_ttl = ttl;
	pk->keyid = *keyid;
	pk->ckaid = *ckaid;
	pk->size = size;

	/* Append any issuer to the end */
	if (issuer.len > 0) {
		memcpy(pk->end, issuer.ptr, issuer.len);
		pk->issuer = shunk2(pk->end, issuer.len);
	}

	return pk;
}

err_t add_public_key(const struct id *id, /* ASKK */
		     enum dns_auth_level dns_auth_level,
		     const struct pubkey_type *type,
		     realtime_t install_time, realtime_t until_time,
		     uint32_t ttl,
		     const chunk_t *key,
		     struct pubkey **pkp,
		     struct pubkey_list **head)
{
	/* first: algorithm-specific decoding of key chunk */
	union pubkey_content scratch_pkc;
	keyid_t keyid;
	ckaid_t ckaid;
	size_t size;
	err_t err = type->unpack_pubkey_content(&scratch_pkc, &keyid, &ckaid, &size, *key);
	if (err != NULL) {
		return err;
	}

	struct pubkey *pubkey = alloc_pubkey(id, dns_auth_level, type,
					     install_time, until_time, ttl,
					     &scratch_pkc, &keyid, &ckaid,
					     null_shunk,	/* raw keys have no issuer */
					     size, HERE);
	if (pkp != NULL) {
		*pkp = pubkey_addref(pubkey, HERE);
	}
	install_public_key(&pubkey, head);
	passert(pubkey == NULL); /* stolen */
	return NULL;
}

static const struct pubkey_type *pubkey_type_nss(SECKEYPublicKey *pubk)
{
	KeyType key_type = SECKEY_GetPublicKeyType(pubk);
	switch (key_type) {
	case rsaKey:
		return &pubkey_type_rsa;
	case ecKey:
		return &pubkey_type_ecdsa;
	default:
		return NULL;
	}
}

static const struct pubkey_type *private_key_type_nss(SECKEYPrivateKey *private_key)
{
	KeyType key_type = SECKEY_GetPrivateKeyType(private_key);
	switch (key_type) {
	case rsaKey:
		return &pubkey_type_rsa;
	case ecKey:
		return &pubkey_type_ecdsa;
	default:
		return NULL;
	}
}

static err_t add_private_key(struct secret **secrets, const struct private_key_stuff **pks,
			     SECKEYPublicKey *pubk, SECItem *ckaid_nss,
			     const struct pubkey_type *type, SECKEYPrivateKey *private_key)
{
	struct secret *s = alloc_thing(struct secret, "pubkey secret");
	s->pks.pubkey_type = type;
	s->pks.kind = type->private_key_kind;
	s->pks.line = 0;
	/* make an unpacked copy of the private key */
	s->pks.private_key = copy_private_key(private_key);
	type->extract_private_key_pubkey_content(&s->pks, &s->pks.keyid, &s->pks.ckaid, &s->pks.size,
						 pubk, ckaid_nss);

	err_t err = type->secret_sane(&s->pks);
	if (err != NULL) {
		type->free_secret_content(&s->pks);
		pfree(s);
		return err;
	}

	add_secret(secrets, s, "lsw_add_rsa_secret");
	*pks = &s->pks;
	return NULL;
}

static err_t find_or_load_private_key_by_cert_3(struct secret **secrets, CERTCertificate *cert,
						const struct private_key_stuff **pks, struct logger *logger,
						SECKEYPublicKey *pubk, SECItem *ckaid_nss,
						const struct pubkey_type *type)
{

	SECKEYPrivateKey *private_key = PK11_FindKeyByAnyCert(cert, lsw_nss_get_password_context(logger));
	if (private_key == NULL)
		return "NSS: cert private key not found";
	err_t err = add_private_key(secrets, pks,
				    /* extracted fields */
				    pubk, ckaid_nss, type, private_key);
	SECKEY_DestroyPrivateKey(private_key);
	return err;
}

static err_t find_or_load_private_key_by_cert_2(struct secret **secrets, CERTCertificate *cert,
						const struct private_key_stuff **pks, bool *load_needed,
						struct logger *logger,
						SECKEYPublicKey *pubk, SECItem *ckaid_nss)
{

	/* XXX: see also nss_cert_key_kind(cert) */
	const struct pubkey_type *type = pubkey_type_nss(pubk);
	if (type == NULL) {
		return "NSS cert not supported";
	}

	struct secret *s = find_secret_by_pubkey_ckaid_1(*secrets, type, ckaid_nss);
	if (s != NULL) {
		dbg("secrets entry for certificate already exists: %s", cert->nickname);
		*pks = &s->pks;
		*load_needed = false;
		return NULL;
	}

	dbg("adding %s secret for certificate: %s", type->name, cert->nickname);
	*load_needed = true;
	err_t err = find_or_load_private_key_by_cert_3(secrets, cert, pks, logger,
						       /* extracted fields */
						       pubk, ckaid_nss, type);
	return err;
}

static err_t find_or_load_private_key_by_cert_1(struct secret **secrets, CERTCertificate *cert,
						const struct private_key_stuff **pks, bool *load_needed,
						struct logger *logger,
						SECKEYPublicKey *pubk)
{
	/*
	 * Getting a SECItem ptr from PK11_GetLowLevelKeyID doesn't
	 * mean that the private key exists - it is just a hash formed
	 * from the cert's public key.
	 */
	SECItem *ckaid_nss =
		PK11_GetLowLevelKeyIDForCert(NULL, cert, lsw_nss_get_password_context(logger)); /* MUST FREE */
	if (ckaid_nss == NULL) {
		return "NSS: key ID not found";
	}

	err_t err = find_or_load_private_key_by_cert_2(secrets, cert, pks, load_needed, logger,
						       /* extracted fields */
						       pubk, ckaid_nss);
	SECITEM_FreeItem(ckaid_nss, PR_TRUE);
	return err;
}

err_t find_or_load_private_key_by_cert(struct secret **secrets, const struct cert *cert,
				       const struct private_key_stuff **pks, bool *load_needed,
				       struct logger *logger)
{
	*load_needed = false;

	if (cert == NULL || cert->nss_cert == NULL) {
		return "NSS cert not found";
	}

	SECKEYPublicKey *pubk = SECKEY_ExtractPublicKey(&cert->nss_cert->subjectPublicKeyInfo);
	if (pubk == NULL) {
		/* dbg(... nss error) */
		return "NSS: could not determine certificate kind; SECKEY_ExtractPublicKey() failed";
	}

	err_t err = find_or_load_private_key_by_cert_1(secrets, cert->nss_cert, pks, load_needed, logger,
						       /* extracted fields */
						       pubk);
	SECKEY_DestroyPublicKey(pubk);
	return err;
}

static err_t find_or_load_private_key_by_ckaid_1(struct secret **secrets,
						 const struct private_key_stuff **pks,
						 SECItem *ckaid_nss, SECKEYPrivateKey *private_key)
{
	const struct pubkey_type *type = private_key_type_nss(private_key);
	if (type == NULL) {
		return "NSS private key not supported (unknown type)";
	}

	SECKEYPublicKey *pubk = SECKEY_ConvertToPublicKey(private_key); /* must free */
	if (pubk == NULL) {
		return "NSS private key has no public key";
	}

	err_t err = add_private_key(secrets, pks, pubk, ckaid_nss, type, private_key);
	SECKEY_DestroyPublicKey(pubk);
	return err;
}

err_t find_or_load_private_key_by_ckaid(struct secret **secrets, const ckaid_t *ckaid,
					const struct private_key_stuff **pks, bool *load_needed,
					struct logger *logger)
{
	*load_needed = false;
	passert(ckaid != NULL);

	SECItem ckaid_nss = same_ckaid_as_secitem(ckaid);
	struct secret *s = find_secret_by_pubkey_ckaid_1(*secrets, NULL, &ckaid_nss);
	if (s != NULL) {
		dbg("secrets entry for ckaid already exists");
		*pks = &s->pks;
		*load_needed = false;
		return NULL;
	}

	*load_needed = true;
	PK11SlotInfo *slot = PK11_GetInternalKeySlot();
	if (!pexpect(slot != NULL)) {
		return "NSS: has no internal slot ....";
	}

	/* must free */
	SECKEYPrivateKey *private_key = PK11_FindKeyByKeyID(slot, &ckaid_nss,
							    lsw_nss_get_password_context(logger));
	if (private_key == NULL) {
		/*
		 * XXX: The code loading ipsec.secrets also tries to
		 * use the CKAID to find the certificate, and then
		 * uses that to find the private key?  Why?
		 */
		return "can't find the private key matching the NSS CKAID";
	}

	ckaid_buf ckb;
	dbg("loaded private key matching CKAID %s", str_ckaid(ckaid, &ckb));
	err_t err = find_or_load_private_key_by_ckaid_1(secrets, pks, &ckaid_nss, private_key);
	SECKEY_DestroyPrivateKey(private_key);
	return err;
}

static diag_t create_pubkey_from_cert_1(const struct id *id,
					CERTCertificate *cert,
					SECKEYPublicKey *pubkey_nss,
					struct pubkey **pk,
					struct logger *logger)
{
	const struct pubkey_type *type = pubkey_type_nss(pubkey_nss);
	if (type == NULL) {
		return diag("NSS: certificate key kind is unknown; not creating pubkey");
	}

	SECItem *ckaid_nss = PK11_GetLowLevelKeyIDForCert(NULL, cert,
							  lsw_nss_get_password_context(logger)); /* must free */
	if (ckaid_nss == NULL) {
		/* someone deleted CERT from the NSS DB */
		return diag("NSS: could not extract CKAID from RSA certificate '%s'",
			    cert->nickname);
	}

	union pubkey_content pkc;
	keyid_t keyid;
	ckaid_t ckaid;
	size_t size;
	type->extract_pubkey_content(&pkc, &keyid, &ckaid, &size, pubkey_nss, ckaid_nss);

	realtime_t install_time = realnow();
	realtime_t until_time;
	PRTime not_before, not_after;
	if (CERT_GetCertTimes(cert, &not_before, &not_after) != SECSuccess) {
		until_time = realtime(-1);
	} else {
		until_time = realtime(not_after / PR_USEC_PER_SEC);
	}
	*pk = alloc_pubkey(id, /*dns_auth_level*/0/*default*/,
			   type, install_time, until_time,
			   /*ttl*/0, &pkc, &keyid, &ckaid,
			   same_secitem_as_shunk(cert->derIssuer),
			   size, HERE);
	SECITEM_FreeItem(ckaid_nss, PR_TRUE);
	return NULL;
}

diag_t create_pubkey_from_cert(const struct id *id,
			       CERTCertificate *cert, struct pubkey **pk, struct logger *logger)
{
	if (!pexpect(cert != NULL)) {
		return NULL;
	}

	/*
	 * Try to convert CERT to an internal PUBKEY object.  If
	 * someone, in parallel, deletes the underlying cert from the
	 * NSS DB, then this will fail.
	 */
	SECKEYPublicKey *pubkey_nss = SECKEY_ExtractPublicKey(&cert->subjectPublicKeyInfo); /* must free */
	if (pubkey_nss == NULL) {
		return diag("NSS: could not extract public key from certificate '%s'",
			    cert->nickname);
	}

	diag_t d = create_pubkey_from_cert_1(id, cert, pubkey_nss, pk, logger);
	SECKEY_DestroyPublicKey(pubkey_nss);
	return d;
}
