/*
 * interfaces to the secrets.c library functions in libswan.
 * for now, just stupid wrappers!
 *
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2003-2008  Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2015 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2016, Andrew Cagney <cagney@gnu.org>
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

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>

#include <glob.h>
#ifndef GLOB_ABORTED
# define GLOB_ABORTED    GLOB_ABEND     /* fix for old versions */
#endif

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "lex.h"
#include "keys.h"
#include "dnskey.h"     /* needs keys.h and adns.h */
#include "log.h"
#include "whack.h"      /* for RC_LOG_SERIOUS */
#include "timer.h"

#include "fetch.h"
#include "pluto_x509.h"
#include "nss_cert_load.h"

#include "nat_traversal.h"

#include <prerror.h>
#include <prinit.h>
#include <prmem.h>
#include <key.h>
#include <keyt.h>
#include <nss.h>
#include <pk11pub.h>
#include <seccomon.h>
#include <secerr.h>
#include <secport.h>
#include <time.h>
#include "lswconf.h"
#include "lswnss.h"
#include "secrets.h"

static struct secret *pluto_secrets = NULL;

void load_preshared_secrets(void)
{
	const struct lsw_conf_options *oco = lsw_init_options();
	lsw_load_preshared_secrets(&pluto_secrets, oco->secretsfile);
}

void free_preshared_secrets(void)
{
	lsw_free_preshared_secrets(&pluto_secrets);
}

static int print_secrets(struct secret *secret,
			 struct private_key_stuff *pks UNUSED,
			 void *uservoid UNUSED)
{
	char idb1[IDTOA_BUF];
	char idb2[IDTOA_BUF];
	const char *kind = "?";
	const char *more = "";
	struct id_list *ids;

	switch (pks->kind) {
	case PPK_PSK:
		kind = "PSK";
		break;
	case PPK_RSA:
		kind = "RSA";
		break;
	case PPK_XAUTH:
		kind = "XAUTH";
		break;
	default:
		return 1;
	}

	ids = lsw_get_idlist(secret);
	strcpy(idb1, "%any");
	strcpy(idb2, "");

	if (ids != NULL) {
		idtoa(&ids->id, idb1, sizeof(idb1));
		if (ids->next != NULL) {
			idtoa(&ids->next->id, idb2, sizeof(idb2));
			if (ids->next->next != NULL)
				more = "more";
		}
	}

	whack_log(RC_COMMENT, "    %d: %s %s %s%s",
		  pks->line, kind, idb1, idb2, more);

	/* continue loop until end */
	return 1;
}

void list_psks(void)
{
	const struct lsw_conf_options *oco = lsw_init_options();
	whack_log(RC_COMMENT, " ");
	whack_log(RC_COMMENT, "List of Pre-shared secrets (from %s)",
		  oco->secretsfile);
	whack_log(RC_COMMENT, " ");
	lsw_foreach_secret(pluto_secrets, print_secrets, NULL);
}

/* returns the length of the result on success; 0 on failure */
int sign_hash(const struct RSA_private_key *k,
		  const u_char *hash_val, size_t hash_len,
		  u_char *sig_val, size_t sig_len)
{
	SECKEYPrivateKey *privateKey = NULL;
	SECItem signature;
	SECItem data;
	PK11SlotInfo *slot = NULL;

	DBG(DBG_CRYPT, DBG_log("RSA_sign_hash: Started using NSS"));

	slot = PK11_GetInternalKeySlot();
	if (slot == NULL) {
		loglog(RC_LOG_SERIOUS,
		       "RSA_sign_hash: Unable to find (slot security) device (err %d)",
		       PR_GetError());
		return 0;
	}

	/* XXX: is there no way to detect if we _need_ to authenticate ?? */
	if (PK11_Authenticate(slot, PR_FALSE,
			       lsw_return_nss_password_file_info()) ==
	     SECSuccess) {
		DBG(DBG_CRYPT,
		    DBG_log("NSS: Authentication to NSS successful"));
	} else {
		DBG(DBG_CRYPT,
		    DBG_log("NSS: Authentication to NSS either failed or not required,if NSS DB without password"));
	}

	privateKey = PK11_FindKeyByKeyID(slot, k->pub.ckaid.nss,
					 lsw_return_nss_password_file_info());
	if (privateKey == NULL) {
		DBG(DBG_CRYPT,
		    DBG_log("Can't find the private key from the NSS CKA_ID"));
	}

	/*
	 * SIG_LEN contains "adjusted" length of modulus n in octets:
	 * [RSA_MIN_OCTETS, RSA_MAX_OCTETS].
	 *
	 * According to form_keyid() this is the modulus length less
	 * any leading byte added by DER encoding.
	 *
	 * The adjusted length is used in sign_hash() as the signature
	 * length - wouldn't PK11_SignatureLen be better?
	 *
	 * Lets find out.
	 */
	pexpect((int)sig_len == PK11_SignatureLen(privateKey));

	PK11_FreeSlot(slot);

	if (privateKey == NULL)
		return 0;

	data.type = siBuffer;
	data.len = hash_len;
	data.data = DISCARD_CONST(u_char *, hash_val);

	signature.len = sig_len;
	signature.data = sig_val;

	{
		SECStatus s = PK11_Sign(privateKey, &signature, &data);

		if (s != SECSuccess) {
			loglog(RC_LOG_SERIOUS,
			       "RSA_sign_hash: sign function failed (%d)",
			       PR_GetError());
			return 0;
		}
	}

	SECKEY_DestroyPrivateKey(privateKey);

	DBG(DBG_CRYPT, DBG_log("RSA_sign_hash: Ended using NSS"));
	return signature.len;
}

err_t RSA_signature_verify_nss(const struct RSA_public_key *k,
			       const u_char *hash_val, size_t hash_len,
			       const u_char *sig_val, size_t sig_len)
{
	SECKEYPublicKey *publicKey;
	PRArenaPool *arena;
	SECStatus retVal;
	SECItem nss_n, nss_e;
	SECItem signature, data;

	/* Converting n and e to form public key in SECKEYPublicKey data structure */

	arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
	if (arena == NULL) {
		PORT_SetError(SEC_ERROR_NO_MEMORY);
		return "10" "NSS error: Not enough memory to create arena";
	}

	publicKey = (SECKEYPublicKey *)
		PORT_ArenaZAlloc(arena, sizeof(SECKEYPublicKey));
	if (publicKey == NULL) {
		PORT_FreeArena(arena, PR_FALSE);
		PORT_SetError(SEC_ERROR_NO_MEMORY);
		return "11" "NSS error: Not enough memory to create publicKey";
	}

	publicKey->arena = arena;
	publicKey->keyType = rsaKey;
	publicKey->pkcs11Slot = NULL;
	publicKey->pkcs11ID = CK_INVALID_HANDLE;

	/* make a local copy.  */
	chunk_t n = chunk_clone(k->n, "n");
	chunk_t e = chunk_clone(k->e, "e");

	/* Converting n and e to nss_n and nss_e */
	nss_n.data = n.ptr;
	nss_n.len = (unsigned int)n.len;
	nss_n.type = siBuffer;

	nss_e.data = e.ptr;
	nss_e.len = (unsigned int)e.len;
	nss_e.type = siBuffer;

	retVal = SECITEM_CopyItem(arena, &publicKey->u.rsa.modulus, &nss_n);
	if (retVal == SECSuccess) {
		retVal = SECITEM_CopyItem(arena,
					  &publicKey->u.rsa.publicExponent,
					  &nss_e);
	}

	if (retVal != SECSuccess) {
		pfree(n.ptr);
		pfree(e.ptr);
		SECKEY_DestroyPublicKey(publicKey);
		return "12NSS error: Not able to copy modulus or exponent or both while forming SECKEYPublicKey structure";
	}
	signature.type = siBuffer;
	signature.data = DISCARD_CONST(unsigned char *, sig_val);
	signature.len  = (unsigned int)sig_len;

	data.len = (unsigned int)sig_len;
	data.data = alloc_bytes(data.len, "NSS decrypted signature");
	data.type = siBuffer;

	if (PK11_VerifyRecover(publicKey, &signature, &data,
			       lsw_return_nss_password_file_info()) ==
	    SECSuccess ) {
		DBG(DBG_CRYPT,
		    DBG_dump("NSS RSA verify: decrypted sig: ", data.data,
			     data.len));
	} else {
		DBG(DBG_CRYPT,
		    DBG_log("NSS RSA verify: decrypting signature is failed"));
		return "13" "NSS error: Not able to decrypt";
	}

	if (!memeq(data.data + data.len - hash_len, hash_val, hash_len)) {
		pfree(data.data);
		loglog(RC_LOG_SERIOUS, "RSA Signature NOT verified");
		return "14" "NSS error: Not able to verify";
	}

	DBG(DBG_CRYPT,
	    DBG_dump("NSS RSA verify: hash value: ", hash_val, hash_len));

	pfree(data.data);
	pfree(n.ptr);
	pfree(e.ptr);
	SECKEY_DestroyPublicKey(publicKey);

	DBG(DBG_CRYPT, DBG_log("RSA Signature verified"));

	return NULL;
}

/* Check signature against all RSA public keys we can find.
 * If we need keys from DNS KEY records, and they haven't been fetched,
 * return STF_SUSPEND to ask for asynch DNS lookup.
 *
 * Note: parameter keys_from_dns contains results of DNS lookup for key
 * or is NULL indicating lookup not yet tried.
 *
 * take_a_crack is a helper function.  Mostly forensic.
 * If only we had coroutines.
 */
struct tac_state {
	/* RSA_check_signature's args that take_a_crack needs */
	struct state *st;
	const u_char *hash_val;
	size_t hash_len;
	const pb_stream *sig_pbs;

	err_t (*try_RSA_signature)(const u_char hash_val[MAX_DIGEST_LEN],
				   size_t hash_len,
				   const pb_stream *sig_pbs,
				   struct pubkey *kr,
				   struct state *st);

	/* state carried between calls */
	err_t best_ugh; /* most successful failure */
	int tried_cnt;  /* number of keys tried */
	char tried[50]; /* keyids of tried public keys */
	char *tn;       /* roof of tried[] */
};

static bool take_a_crack(struct tac_state *s,
			 struct pubkey *kr,
			 const char *story)
{
	err_t ugh =
		(s->try_RSA_signature)(s->hash_val, s->hash_len, s->sig_pbs,
				       kr, s->st);
	const struct RSA_public_key *k = &kr->u.rsa;

	s->tried_cnt++;
	if (ugh == NULL) {
		DBG(DBG_CRYPT | DBG_CONTROL,
		    DBG_log("an RSA Sig check passed with *%s [%s]",
			    k->keyid, story));
		return TRUE;
	} else {
		DBG(DBG_CRYPT,
		    DBG_log("an RSA Sig check failure %s with *%s [%s]",
			    ugh + 1, k->keyid, story));
		if (s->best_ugh == NULL || s->best_ugh[0] < ugh[0])
			s->best_ugh = ugh;
		if (ugh[0] > '0' &&
		    s->tn - s->tried + KEYID_BUF + 2 <
		    (ptrdiff_t)sizeof(s->tried)) {
			strcpy(s->tn, " *");
			strcpy(s->tn + 2, k->keyid);
			s->tn += strlen(s->tn);
		}
		return FALSE;
	}
}

stf_status RSA_check_signature_gen(struct state *st,
				   const u_char hash_val[MAX_DIGEST_LEN],
				   size_t hash_len,
				   const pb_stream *sig_pbs
#ifdef USE_KEYRR
				   , const struct pubkey_list *keys_from_dns
#endif /* USE_KEYRR */
				   , const struct gw_info *gateways_from_dns,
				   err_t (*try_RSA_signature)(
					   const u_char hash_val[MAX_DIGEST_LEN],
					   size_t hash_len,
					   const pb_stream *sig_pbs,
					   struct pubkey *kr,
					   struct state *st))
{
	const struct connection *c = st->st_connection;
	struct tac_state s;
	err_t dns_ugh = NULL;

	s.st = st;
	s.hash_val = hash_val;
	s.hash_len = hash_len;
	s.sig_pbs = sig_pbs;
	s.try_RSA_signature = try_RSA_signature;

	s.best_ugh = NULL;
	s.tried_cnt = 0;
	s.tn = s.tried;

	/* try all gateway records hung off c */
	if ((c->policy & POLICY_OPPORTUNISTIC)) {
		struct gw_info *gw;

		for (gw = c->gw_info; gw != NULL; gw = gw->next) {
			/* only consider entries that have a key and are for our peer */
			if (gw->gw_key_present &&
			    same_id(&gw->gw_id, &c->spd.that.id) &&
			    take_a_crack(&s, gw->key,
					 "key saved from DNS TXT"))
				return STF_OK;
		}
	}

	/* try all appropriate Public keys */
	{
		struct pubkey_list *p, **pp;
		int pathlen;
		realtime_t nw = realnow();

		pp = &pluto_pubkeys;

		{

			DBG(DBG_CONTROL, {
				    char buf[IDTOA_BUF];
				    dntoa_or_null(buf, IDTOA_BUF,
						  c->spd.that.ca, "%any");
				    DBG_log("required CA is '%s'", buf);
			    });
		}

		for (p = pluto_pubkeys; p != NULL; p = *pp) {
			struct pubkey *key = p->key;

			if (key->alg == PUBKEY_ALG_RSA &&
			    same_id(&c->spd.that.id, &key->id) &&
			    trusted_ca_nss(key->issuer, c->spd.that.ca,
				       &pathlen)) {

				DBG(DBG_CONTROL, {
					    char buf[IDTOA_BUF];
					    dntoa_or_null(buf, IDTOA_BUF,
							  key->issuer, "%any");
					    DBG_log("key issuer CA is '%s'",
						    buf);
				    });

				/* check if found public key has expired */
				if (!isundefinedrealtime(key->until_time) &&
				    realbefore(key->until_time, nw)) {
					loglog(RC_LOG_SERIOUS,
					       "cached RSA public key has expired and has been deleted");
					*pp = free_public_keyentry(p);
					continue; /* continue with next public key */
				}

				if (take_a_crack(&s, key, "preloaded key"))
					return STF_OK;
			}
			pp = &p->next;
		}
	}

	/* if no key was found (evidenced by best_ugh == NULL)
	 * and that side of connection is key_from_DNS_on_demand
	 * then go search DNS for keys for peer.
	 */
	if (s.best_ugh == NULL && c->spd.that.key_from_DNS_on_demand) {
		if (gateways_from_dns != NULL) {
			/* TXT keys */
			const struct gw_info *gwp;

			for (gwp = gateways_from_dns; gwp != NULL;
			     gwp = gwp->next)
				if (gwp->gw_key_present &&
				    take_a_crack(&s, gwp->key,
						 "key from DNS TXT"))
					return STF_OK;
#ifdef USE_KEYRR
		} else if (keys_from_dns != NULL) {
			/* KEY keys */
			const struct pubkey_list *kr;

			for (kr = keys_from_dns; kr != NULL; kr = kr->next)
				if (kr->key->alg == PUBKEY_ALG_RSA &&
				    take_a_crack(&s, kr->key,
						 "key from DNS KEY"))
					return STF_OK;
#endif          /* USE_KEYRR */
		} else {
			/* nothing yet: ask for asynch DNS lookup */
			return STF_SUSPEND;
		}
	}

	/* no acceptable key was found: diagnose */
	{
		char id_buf[IDTOA_BUF]; /* arbitrary limit on length of ID reported */

		(void) idtoa(&st->st_connection->spd.that.id, id_buf,
			     sizeof(id_buf));

		if (s.best_ugh == NULL) {
			if (dns_ugh == NULL) {
				loglog(RC_LOG_SERIOUS,
				       "no RSA public key known for '%s'",
				       id_buf);
			} else {
				loglog(RC_LOG_SERIOUS, "no RSA public key known for '%s'; DNS search for KEY failed (%s)",
				       id_buf,
				       dns_ugh);
			}

			/* ??? is this the best code there is? */
			return STF_FAIL + INVALID_KEY_INFORMATION;
		}

		if (s.best_ugh[0] == '9') {
			loglog(RC_LOG_SERIOUS, "%s", s.best_ugh + 1);
			/* XXX Could send notification back */
			return STF_FAIL + INVALID_HASH_INFORMATION;
		} else {
			if (s.tried_cnt == 1) {
				loglog(RC_LOG_SERIOUS,
				       "Signature check (on %s) failed (wrong key?); tried%s",
				       id_buf, s.tried);
				DBG(DBG_CONTROL,
				    DBG_log("public key for %s failed: decrypted SIG payload into a malformed ECB (%s)",
					    id_buf, s.best_ugh + 1));
			} else {
				loglog(RC_LOG_SERIOUS,
				       "Signature check (on %s) failed: tried%s keys but none worked.",
				       id_buf, s.tried);
				DBG(DBG_CONTROL,
				    DBG_log("all %d public keys for %s failed: best decrypted SIG payload into a malformed ECB (%s)",
					    s.tried_cnt, id_buf,
					    s.best_ugh + 1));
			}
			return STF_FAIL + INVALID_KEY_INFORMATION;
		}
	}
}

/* find the struct secret associated with the combination of
 * me and the peer.  We match the Id (if none, the IP address).
 * Failure is indicated by a NULL.
 *
 * my_id = &c->spd.this.id
 * his_id = &c->spd.that.id
 */
static struct secret *lsw_get_secret(const struct connection *c,
				     const struct id *my_id,
				     const struct id *his_id,
				     enum PrivateKeyKind kind, bool asym)
{
	char idme[IDTOA_BUF],
	     idhim[IDTOA_BUF], idhim2[IDTOA_BUF];
	struct secret *best = NULL;
	struct id rw_id;

	idtoa(my_id,  idme,  IDTOA_BUF);
	idtoa(his_id, idhim, IDTOA_BUF);
	strcpy(idhim2, idhim);

	DBG(DBG_CONTROL,
	    DBG_log("started looking for secret for %s->%s of kind %s",
		    idme, idhim,
		    enum_name(&ppk_names, kind)));

	/* is there a certificate assigned to this connection? */
	if (kind == PPK_RSA && c->spd.this.cert.ty == CERT_X509_SIGNATURE &&
			c->spd.this.cert.u.nss_cert != NULL) {
		/* Must free MY_PUBLIC_KEY */
		struct pubkey *my_public_key = allocate_RSA_public_key_nss(
			c->spd.this.cert.u.nss_cert);
		passert(my_public_key != NULL);

		best = lsw_find_secret_by_public_key(pluto_secrets,
						     my_public_key, kind);
		if (best != NULL) {
			free_public_key(my_public_key);
			return best;
		}

		const char *nickname = cert_nickname(&c->spd.this.cert);
		DBG(DBG_CONTROL,
		    DBG_log("private key for cert %s not found in local cache; loading from NSS DB",
			    nickname));


		err_t err = load_nss_cert_secret(c->spd.this.cert.u.nss_cert);
		if (err != NULL) {
			DBG(DBG_CONTROL,
			    DBG_log("private key for cert %s not found in NSS DB",
				    nickname));
			free_public_key(my_public_key);
			return NULL;
		}

		best = lsw_find_secret_by_public_key(pluto_secrets,
						     my_public_key, kind);
		/*
		 * Just added a secret using the cert as the key; how
		 * can it then not be found?
		 */
		pexpect(best != NULL);
		free_public_key(my_public_key);
		return best;
	}

	if (his_id_was_instantiated(c) && (!(c->policy & POLICY_AGGRESSIVE)) &&
	    isanyaddr(&c->spd.that.host_addr)) {
		DBG(DBG_CONTROL,
		    DBG_log("instantiating him to 0.0.0.0"));

		/* roadwarrior: replace him with 0.0.0.0 */
		rw_id.kind = addrtypeof(&c->spd.that.host_addr) == AF_INET ?
			     ID_IPV4_ADDR : ID_IPV6_ADDR;
		happy(anyaddr(addrtypeof(&c->spd.that.host_addr),
			      &rw_id.ip_addr));
		his_id = &rw_id;
		idtoa(his_id, idhim2, IDTOA_BUF);
	} else if ((c->policy & POLICY_PSK) &&
		  (kind == PPK_PSK) &&
		  (((c->kind == CK_TEMPLATE) &&
		    (c->spd.that.id.kind == ID_NONE)) ||
		   ((c->kind == CK_INSTANCE) &&
		    (id_is_ipaddr(&c->spd.that.id))
		    /* Check if we are a road warrior instantiation, not a vnet: instantiation */
		    && (isanyaddr(&c->spd.that.host_addr)))
		  )
		  ) {
		DBG(DBG_CONTROL,
		    DBG_log("replace him to 0.0.0.0"));

		/* roadwarrior: replace him with 0.0.0.0 */
		rw_id.kind = ID_IPV4_ADDR;
		happy(anyaddr(addrtypeof(&c->spd.that.host_addr),
			      &rw_id.ip_addr));
		his_id = &rw_id;
		idtoa(his_id, idhim2, IDTOA_BUF);
	}

	DBG(DBG_CONTROL,
	    DBG_log("actually looking for secret for %s->%s of kind %s",
		    idme, idhim2,
		    enum_name(&ppk_names, kind)));

	best = lsw_find_secret_by_id(pluto_secrets,
				     kind,
				     my_id, his_id, asym);

	return best;
}

/*
 * find the struct secret associated with an XAUTH username.
 */
struct secret *lsw_get_xauthsecret(const struct connection *c UNUSED,
				   char *xauthname)
{
	struct secret *best = NULL;
	struct id xa_id;

	DBG(DBG_CONTROL,
	    DBG_log("started looking for xauth secret for %s",
		    xauthname));

	zero(&xa_id);	/* redundant */
	xa_id.kind = ID_FQDN;
	xa_id.name.ptr = (unsigned char *)xauthname;
	xa_id.name.len = strlen(xauthname);

	best = lsw_find_secret_by_id(pluto_secrets,
				     PPK_XAUTH,
				     &xa_id, NULL, TRUE);

	return best;
}

/* check the existence of an RSA private key matching an RSA public
 */
static bool has_private_rawkey(struct pubkey *pk)
{
	return lsw_has_private_rawkey(pluto_secrets, pk);
}

/* find the appropriate preshared key (see get_secret).
 * Failure is indicated by a NULL pointer.
 * Note: the result is not to be freed by the caller.
 */
const chunk_t *get_preshared_secret(const struct connection *c)
{
	struct secret *s = lsw_get_secret(c,
					  &c->spd.this.id,
					  &c->spd.that.id,
					  PPK_PSK, FALSE);
	const struct private_key_stuff *pks = NULL;

	if (c->policy & POLICY_AUTH_NULL) {
		DBG(DBG_PRIVATE, DBG_log("AUTH_NULl secret - returning empty_chunk"));
		return &empty_chunk;
	}

	if (s != NULL)
		pks = lsw_get_pks(s);

	DBG(DBG_PRIVATE, {
		if (s == NULL)
			DBG_log("no Preshared Key Found");
		else
			DBG_dump_chunk("Preshared Key",
				       pks->u.preshared_secret);
	});
	return s == NULL ? NULL : &pks->u.preshared_secret;
}

/* find the appropriate RSA private key (see get_secret).
 * Failure is indicated by a NULL pointer.
 */
const struct RSA_private_key *get_RSA_private_key(const struct connection *c)
{
	struct secret *s = lsw_get_secret(c,
					  &c->spd.this.id, &c->spd.that.id,
					  PPK_RSA, TRUE);
	const struct private_key_stuff *pks = NULL;

	if (s != NULL)
		pks = lsw_get_pks(s);

	DBG(DBG_PRIVATE, {
		if (s == NULL)
			DBG_log("no RSA key Found");
		else
			DBG_log("rsa key %s found",
				pks->u.RSA_private_key.pub.keyid);
	});
	return s == NULL ? NULL : &pks->u.RSA_private_key;
}

/* public key machinery
 * Note: caller must set dns_auth_level.
 */

struct pubkey *public_key_from_rsa(const struct RSA_public_key *k)
{
	struct pubkey *p = alloc_thing(struct pubkey, "pubkey");

	p->id = empty_id; /* don't know, doesn't matter */
	p->issuer = empty_chunk;
	p->alg = PUBKEY_ALG_RSA;

	memcpy(p->u.rsa.keyid, k->keyid, sizeof(p->u.rsa.keyid));
	p->u.rsa.k = k->k;
	p->u.rsa.e = chunk_clone(k->e, "e");
	p->u.rsa.n = chunk_clone(k->n, "n");

	/* note that we return a 1 reference count upon creation:
	 * invariant: recount > 0.
	 */
	p->refcnt = 1;
	p->installed_time = realnow();
	return p;
}

/* root of chained public key list */

struct pubkey_list *pluto_pubkeys = NULL;       /* keys from ipsec.conf */

void free_remembered_public_keys(void)
{
	free_public_keys(&pluto_pubkeys);
}

/* transfer public keys from *keys list to front of pubkeys list */
void transfer_to_public_keys(struct gw_info *gateways_from_dns
#ifdef USE_KEYRR
			     , struct pubkey_list **keys
#endif /* USE_KEYRR */
			     )
{
	{
		struct gw_info *gwp;

		for (gwp = gateways_from_dns; gwp != NULL; gwp = gwp->next) {
			struct pubkey_list *pl = alloc_thing(
				struct pubkey_list, "from TXT");

			pl->key = gwp->key;     /* note: this is a transfer */
			gwp->key = NULL;        /* really, it is! */
			pl->next = pluto_pubkeys;
			pluto_pubkeys = pl;
		}
	}

#ifdef USE_KEYRR
	{
		struct pubkey_list **pp = keys;

		while (*pp != NULL)
			pp = &(*pp)->next;
		*pp = pluto_pubkeys;
		pluto_pubkeys = *keys;
		*keys = NULL;
	}
#endif  /* USE_KEYRR */
}

err_t add_public_key(const struct id *id,
		     enum dns_auth_level dns_auth_level,
		     enum pubkey_alg alg,
		     const chunk_t *key,
		     struct pubkey_list **head)
{
	struct pubkey *pk = alloc_thing(struct pubkey, "pubkey");

	/* first: algorithm-specific decoding of key chunk */
	switch (alg) {
	case PUBKEY_ALG_RSA:
	{
		err_t ugh = unpack_RSA_public_key(&pk->u.rsa, key);

		if (ugh != NULL) {
			pfree(pk);
			return ugh;
		}
	}
	break;
	default:
		bad_case(alg);
	}

	pk->id = *id;
	pk->dns_auth_level = dns_auth_level;
	pk->alg = alg;
	pk->until_time = undefinedrealtime();
	pk->issuer = empty_chunk;

	install_public_key(pk, head);
	return NULL;
}

/*
 *  list all public keys in the chained list
 */
void list_public_keys(bool utc, bool check_pub_keys)
{
	struct pubkey_list *p = pluto_pubkeys;

	if (!check_pub_keys) {
		whack_log(RC_COMMENT, " ");
		whack_log(RC_COMMENT, "List of RSA Public Keys:");
		whack_log(RC_COMMENT, " ");
	}

	while (p != NULL) {
		struct pubkey *key = p->key;

		if (key->alg == PUBKEY_ALG_RSA) {
			const char *check_expiry_msg = check_expiry(key->until_time,
							PUBKEY_WARNING_INTERVAL,
							TRUE);

			if (!check_pub_keys ||
			    !startswith(check_expiry_msg, "ok")) {
				char expires_buf[REALTIMETOA_BUF];
				char installed_buf[REALTIMETOA_BUF];
				char id_buf[IDTOA_BUF];

				idtoa(&key->id, id_buf, IDTOA_BUF);

				whack_log(RC_COMMENT,
					  "%s, %4d RSA Key %s (%s private key), until %s %s",
					  realtimetoa(key->installed_time, utc,
						  installed_buf,
						  sizeof(installed_buf)),
					  8 * key->u.rsa.k,
					  key->u.rsa.keyid,
					  (has_private_rawkey(key) ? "has" :
					   "no"),
					  realtimetoa(key->until_time, utc,
						  expires_buf,
						  sizeof(expires_buf)),
					  check_expiry_msg);

				/* XXX could be ikev2_idtype_names */
				whack_log(RC_COMMENT, "       %s '%s'",
					  enum_show(&ike_idtype_names,
						    key->id.kind), id_buf);

				if (key->issuer.len > 0) {
					dntoa(id_buf, IDTOA_BUF, key->issuer);
					whack_log(RC_COMMENT,
						  "       Issuer '%s'",
						  id_buf);
				}
			}
		}
		p = p->next;
	}
}

err_t load_nss_cert_secret(CERTCertificate *cert)
{
	if (cert == NULL) {
		return "NSS cert not found";
	}

	if (cert_key_is_rsa(cert)) {
		return lsw_add_rsa_secret(&pluto_secrets, cert);
	} else {
		return "NSS cert not supported";
	}
}

static bool rsa_pubkey_ckaid_matches(struct pubkey *pubkey, char *buf, size_t buflen)
{
	if (pubkey->u.rsa.n.ptr == NULL) {
		DBG_log("RSA pubkey with NULL modulus");
		return FALSE;
	}
	SECItem modulus = {
		.type = siBuffer,
		.len = pubkey->u.rsa.n.len,
		.data = pubkey->u.rsa.n.ptr,
	};
	SECItem *pubkey_ckaid = PK11_MakeIDFromPubKey(&modulus);
	if (pubkey_ckaid == NULL) {
		DBG_log("RSA pubkey incomputable CKAID");
		return FALSE;
	}
	DBG_dump("comparing ckaid with", pubkey_ckaid->data, pubkey_ckaid->len);
	bool eq = (pubkey_ckaid->len == buflen
		   && memcmp(pubkey_ckaid->data, buf, buflen) == 0);
	SECITEM_FreeItem(pubkey_ckaid, PR_TRUE);
	return eq;
}

struct pubkey *get_pubkey_with_matching_ckaid(const char *ckaid)
{
	size_t buflen = strlen(ckaid); /* good enough */
	char *buf = alloc_bytes(buflen, "ckaid");
	const char *ugh = ttodata(ckaid, 0, 16, buf, buflen, &buflen);
	if (ugh != NULL) {
		pfree(buf);
		/* should have been rejected by whack? */
		libreswan_log("invalid hex CKAID '%s': %s", ckaid, ugh);
		return NULL;
	}
	DBG(DBG_CONTROL,
	    DBG_dump("looking for pubkey with CKAID that matches", buf, buflen));

	struct pubkey_list *p;
	for (p = pluto_pubkeys; p != NULL; p = p->next) {
		DBG_log("looking at a PUBKEY");
		struct pubkey *key = p->key;
		switch (key->alg) {
		case PUBKEY_ALG_RSA: {
			if (rsa_pubkey_ckaid_matches(key, buf, buflen)) {
				DBG_log("ckaid matching pubkey");
				pfree(buf);
				return key;
			}
		}
		default:
			break;
		}
	}
	pfree(buf);
	return NULL;
}
