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
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2018 Sahana Prasad <sahana.prasad07@gmail.com>
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
 *
 */

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>


#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "keys.h"
#include "log.h"
#include "whack.h"      /* for RC_LOG_SERIOUS */
#include "timer.h"

#include "fetch.h"
#include "pluto_x509.h"
#include "nss_cert_load.h"
#include "crypt_mac.h"
#include "nat_traversal.h"

#include <prerror.h>
#include <prinit.h>
#include <prmem.h>
#include <keyhi.h>
#include <keythi.h>
#include <nss.h>
#include <pk11pub.h>
#include <seccomon.h>
#include <secerr.h>
#include <secport.h>
#include <time.h>
#include "lswconf.h"
#include "lswnss.h"
#include "secrets.h"
#include "ike_alg_hash.h"
#include "pluto_timing.h"

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
			 void *uservoid)
{
	struct fd *whackfd = uservoid;

	const char *kind;
	switch (pks->kind) {
	case PKK_PSK:
		kind = "PSK";
		break;
	case PKK_RSA:
		kind = "RSA";
		break;
	case PKK_XAUTH:
		kind = "XAUTH";
		break;
	case PKK_ECDSA:
		kind = "ECDSA";
		break;
	default:
		return 1;
	}

	struct id_list *ids = lsw_get_idlist(secret);

	int indent;
	WHACK_LOG(RC_COMMENT, whackfd, buf) {
		indent = jam(buf, "%5d:", pks->line);
		jam(buf, " %s ", kind);
		if (ids == NULL) {
			jam(buf, "%%any");
		} else {
			jam_id(buf, &ids->id, jam_sanitized_bytes);
			if (ids->next != NULL) {
				jam(buf, " ");
				jam_id(buf, &ids->next->id, jam_sanitized_bytes);
				if (ids->next->next != NULL) {
					jam(buf, " more");
				}
			}
		}
	}

	const ckaid_t *ckaid = secret_ckaid(secret); /* may be NULL */
	if (ckaid != NULL) {
		WHACK_LOG(RC_COMMENT, whackfd, buf) {
			jam(buf, "%*s ckaid: ", indent, "");
			jam_ckaid(buf, ckaid);
		}
	}

	/* continue loop until end */
	return 1;
}

void list_psks(struct fd *whackfd)
{
	const struct lsw_conf_options *oco = lsw_init_options();
	whack_comment(whackfd, " ");
	whack_comment(whackfd, "List of Pre-shared secrets (from %s)",
		  oco->secretsfile);
	whack_comment(whackfd, " ");
	lsw_foreach_secret(pluto_secrets, print_secrets, whackfd);
}

err_t RSA_signature_verify_nss(const struct RSA_public_key *k,
			       const struct crypt_mac *expected_hash,
			       const uint8_t *sig_val, size_t sig_len,
			       const struct hash_desc *hash_algo)
{
	SECStatus retVal;
	if (DBGP(DBG_BASE)) {
		DBG_dump_hunk("NSS RSA: verifying that decrypted signature matches hash: ",
			      *expected_hash);
	}

	/*
	 * Create a public key storing all keying material in an
	 * arena.  The arena's lifetime is tied to and released by the
	 * key.
	 *
	 * Danger:
	 *
	 * Need to use SECKEY_DestroyPublicKey() to release any
	 * allocated memory; not SECITEM_FreeArena(); and not both!
	 *
	 * A look at SECKEY_DestroyPublicKey()'s source shows that it
	 * releases the allocated public key by freeing the arena,
	 * hence only that is needed.
	 */
	SECKEYPublicKey *publicKey;
	{
		PRArenaPool *arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
		if (arena == NULL) {
			PORT_SetError(SEC_ERROR_NO_MEMORY); /* why? */
			return "10""NSS error: Not enough memory to create arena";
		}
		publicKey = PORT_ArenaZAlloc(arena, sizeof(SECKEYPublicKey));
		if (publicKey == NULL) {
			PORT_FreeArena(arena, PR_FALSE);
			PORT_SetError(SEC_ERROR_NO_MEMORY); /* why? */
			return "11""NSS error: Not enough memory to create publicKey";
		}
		publicKey->arena = arena;
	}

	publicKey->keyType = rsaKey;
	publicKey->pkcs11Slot = NULL;
	publicKey->pkcs11ID = CK_INVALID_HANDLE;

	/* Converting n and e to form public key in SECKEYPublicKey data structure */

	const SECItem nss_n = {
		.type = siBuffer,
		.data = k->n.ptr,
		.len = k->n.len,
	};
	retVal = SECITEM_CopyItem(publicKey->arena, &publicKey->u.rsa.modulus, &nss_n);
	if (retVal != SECSuccess) {
		SECKEY_DestroyPublicKey(publicKey);
		return "12""NSS error: unable to copy modulus while forming SECKEYPublicKey structure";
	}

	const SECItem nss_e = {
		.type = siBuffer,
		.data = k->e.ptr,
		.len = k->e.len,
	};
	retVal = SECITEM_CopyItem(publicKey->arena,
				  &publicKey->u.rsa.publicExponent,
				  &nss_e);
	if (retVal != SECSuccess) {
		SECKEY_DestroyPublicKey(publicKey);
		return "12""NSS error: unable to copy exponent while forming SECKEYPublicKey structure";
	}

	const SECItem encrypted_signature = {
		.type = siBuffer,
		.data = DISCARD_CONST(unsigned char *, sig_val),
		.len  = (unsigned int)sig_len,
	};

	if (hash_algo == NULL /* ikev1*/ ||
	    hash_algo == &ike_alg_hash_sha1 /* old style rsa with SHA1*/) {
		SECItem decrypted_signature = {
			.type = siBuffer,
		};
		if (SECITEM_AllocItem(publicKey->arena, &decrypted_signature,
				      sig_len) == NULL) {
			SECKEY_DestroyPublicKey(publicKey);
			return "12""NSS error: unable to allocate space for decrypted signature";
		}

		if (PK11_VerifyRecover(publicKey, &encrypted_signature,
				       &decrypted_signature,
				       lsw_return_nss_password_file_info()) != SECSuccess) {
			dbg("NSS RSA verify: decrypting signature is failed");
			SECKEY_DestroyPublicKey(publicKey);
			return "13""NSS error: Not able to decrypt";
		}

		LSWDBGP(DBG_CRYPT, buf) {
			jam_string(buf, "NSS RSA verify: decrypted sig: ");
			jam_nss_secitem(buf, &decrypted_signature);
		}

		/* hash at end? See above for length check */
		passert(decrypted_signature.len >= expected_hash->len);
		uint8_t *start = (decrypted_signature.data
				  + decrypted_signature.len
				  - expected_hash->len);
		if (!memeq(start, expected_hash->ptr, expected_hash->len)) {
			loglog(RC_LOG_SERIOUS, "RSA Signature NOT verified");
			SECKEY_DestroyPublicKey(publicKey);
			return "14""NSS error: Not able to verify";
		}
	} else {
		/* Digital signature scheme with RSA-PSS */
		const CK_RSA_PKCS_PSS_PARAMS *mech = hash_algo->nss.rsa_pkcs_pss_params;
		if (mech == NULL) {
			dbg("NSS RSA verify: hash algorithm not supported");
			SECKEY_DestroyPublicKey(publicKey);
			return "13""hash algorithm not supported";
		}
		const SECItem hash_mech_item = {
			.type = siBuffer,
			.data = (void*)mech, /* strip const */
			.len = sizeof(*mech),
		};

		struct crypt_mac hash_data = *expected_hash; /* cast away const */
		const SECItem expected_hash_item = {
			.len = hash_data.len,
			.data = hash_data.ptr,
			.type = siBuffer,
		};

		if (PK11_VerifyWithMechanism(publicKey, CKM_RSA_PKCS_PSS,
					     &hash_mech_item, &encrypted_signature,
					     &expected_hash_item,
					     lsw_return_nss_password_file_info()) != SECSuccess) {
			dbg("NSS RSA verify: decrypting signature is failed");
			SECKEY_DestroyPublicKey(publicKey);
			return "13""NSS error: Not able to decrypt";
		}
	}

	SECKEY_DestroyPublicKey(publicKey);

	return NULL;
}

/*
 * Check signature against all RSA public keys we can find.  If we
 * need keys from DNS KEY records, and they haven't been fetched,
 * return STF_SUSPEND to ask for asynch DNS lookup.
 *
 * Note: parameter keys_from_dns contains results of DNS lookup for
 * key or is NULL indicating lookup not yet tried.
 *
 * take_a_crack is a helper function.  Mostly forensic.  If only we
 * had coroutines. (XXX: generators).
 */
struct tac_state {
	const struct pubkey_type *type;
	/* check_signature's args that take_a_crack needs */
	struct state *st;
	const struct crypt_mac *hash;
	const pb_stream *sig_pbs;
	const struct hash_desc *hash_algo;
	try_signature_fn *try_signature;

	/* state carried between calls */
	err_t best_ugh; /* most successful failure */
	int tried_cnt;  /* number of keys tried */
	char tried[50]; /* keyids of tried public keys */
	jambuf_t tn;
};

static bool take_a_crack(struct tac_state *s,
			 struct pubkey *kr,
			 const char *story)
{
	s->tried_cnt++;
	err_t ugh = (s->try_signature)(s->hash, s->sig_pbs,
				       kr, s->st, s->hash_algo);

	const char *key_id_str = pubkey_keyid(kr);

	if (ugh == NULL) {
		dbg("an %s Sig check passed with *%s [%s]",
		    kr->type->name, key_id_str, story);
		return true;
	} else {
		loglog(RC_LOG_SERIOUS, "an %s Sig check failed '%s' with *%s [%s]",
		    kr->type->name, ugh + 1, key_id_str, story);
		if (s->best_ugh == NULL || s->best_ugh[0] < ugh[0])
			s->best_ugh = ugh;
		if (ugh[0] > '0') {
		    jam_string(&s->tn, " *");
		    jam_string(&s->tn, key_id_str);
		}
		return false;
	}
}

static bool try_all_keys(const char *pubkey_description,
			 struct pubkey_list **pubkey_db,
			 const struct connection *c, realtime_t now,
			 struct tac_state *s)
{

	id_buf thatid;
	dbg("trying all %s public keys for %s key that matches ID: %s",
	    pubkey_description, s->type->name, str_id(&c->spd.that.id, &thatid));

	/*
	 * XXX: danger, serves double purpose of pruning expired
	 * public keys, hence strange trailing pp pointer.
	 */
	struct pubkey_list **pp = pubkey_db;
	for (struct pubkey_list *p = *pubkey_db; p != NULL; p = *pp) {
		struct pubkey *key = p->key;

		/* passed to trusted_ca_nss() */
		int pl;	/* value ignored */

		if (key->type != s->type) {
			id_buf printkid;
			dbg("  skipping '%s' with type %s",
			    str_id(&key->id, &printkid), key->type->name);
		} else if (!same_id(&c->spd.that.id, &key->id)) {
			id_buf printkid;
			dbg("  skipping '%s' with wrong ID",
			    str_id(&key->id, &printkid));
		} else if (!trusted_ca_nss(key->issuer, c->spd.that.ca, &pl)) {
			id_buf printkid;
			dn_buf buf;
			dbg("  skipping '%s' with untrusted CA '%s'",
			    str_id(&key->id, &printkid),
			    str_dn_or_null(key->issuer, "%any", &buf));
		} else if (!is_realtime_epoch(key->until_time) &&
			   realbefore(key->until_time, now)) {
			/*
			 * XXX: danger: found public key has expired;
			 * deleting mid loop.  Why only do this for
			 * matched keys as the test is relatively
			 * cheap?
			 */
			id_buf printkid;
			loglog(RC_LOG_SERIOUS,
			       "cached %s public key '%s' has expired and has been deleted",
			       s->type->name, str_id(&key->id, &printkid));
			*pp = free_public_keyentry(p);
			continue; /* continue with next public key */
		} else {
			id_buf printkid;
			dn_buf buf;
			dbg("  trying '%s' issued by CA '%s'",
			    str_id(&key->id, &printkid), str_dn_or_null(key->issuer, "%any", &buf));

			statetime_t try_time = statetime_start(s->st);
			bool ok = take_a_crack(s, key, pubkey_description);
			statetime_stop(&try_time, "%s() trying a pubkey", __func__);
			if (ok) {
				return true;
			}
		}
		pp = &p->next;
	}
	return false;
}

stf_status check_signature_gen(struct state *st,
			       const struct crypt_mac *hash,
			       const pb_stream *sig_pbs,
			       const struct hash_desc *hash_algo,
			       const struct pubkey_type *type,
			       try_signature_fn *try_signature)
{
	const struct connection *c = st->st_connection;
	struct tac_state s = {
		.type = type,
		.st = st,
		.hash = hash,
		.sig_pbs = sig_pbs,
		.hash_algo = hash_algo,
		.try_signature = try_signature,
		.best_ugh = NULL,
		.tried_cnt = 0,
	};
	s.tn = ARRAY_AS_JAMBUF(s.tried);

	/* try all appropriate Public keys */
	realtime_t now = realnow();

	if (DBGP(DBG_BASE)) {
		dn_buf buf;
		DBG_log("required %s CA is '%s'",
			type->name,
			str_dn_or_null(c->spd.that.ca, "%any", &buf));
	}

	pexpect(st->st_remote_certs.processed);
	if (try_all_keys("remote certificates",
			 &st->st_remote_certs.pubkey_db,
			 c, now, &s) ||
	    try_all_keys("preloaded keys",
			 &pluto_pubkeys,
			 c, now, &s)) {
		log_state(RC_LOG_SERIOUS, st,
			  "authenticated using %s with %s",
			  type->name,
			  (c->ike_version == IKEv1) ? "SHA-1" : hash_algo->common.fqn);
		return STF_OK;
	}

	/*
	 * if no key was found (evidenced by best_ugh == NULL) and
	 * that side of connection is key_from_DNS_on_demand then go
	 * search DNS for keys for peer.
	 */

	/* To be re-implemented */

	/* sanitize the ID suitable for logging */
	id_buf id_str = { "" }; /* arbitrary limit on length of ID reported */
	str_id(&st->st_connection->spd.that.id, &id_str);
	passert(id_str.buf[0] != '\0');

	if (s.best_ugh == NULL) {
		log_state(RC_LOG_SERIOUS, st,
			  "no %s public key known for '%s'",
			  type->name, id_str.buf);
		/* ??? is this the best code there is? */
		return STF_FAIL + INVALID_KEY_INFORMATION;
	}

	if (s.best_ugh[0] == '9') {
		log_state(RC_LOG_SERIOUS, st, "%s", s.best_ugh + 1);
		/* XXX Could send notification back */
		return STF_FAIL + INVALID_HASH_INFORMATION;
	}

	if (s.tried_cnt == 1) {
		log_state(RC_LOG_SERIOUS, st,
			  "%s Signature check (on %s) failed (wrong key?); tried%s",
			  type->name, id_str.buf, s.tried);
	} else {
		log_state(RC_LOG_SERIOUS, st,
			  "%s Signature check (on %s) failed: tried%s keys but none worked.",
			  type->name, id_str.buf, s.tried);
	}
	dbg("all %d %s public keys for %s failed: best decrypted SIG payload into a malformed ECB (%s)",
	    s.tried_cnt, type->name, id_str.buf, s.best_ugh+1/*skip '9'*/);

	return STF_FAIL + INVALID_KEY_INFORMATION;
}

/*
 * find the struct secret associated with the combination of
 * me and the peer.  We match the Id (if none, the IP address).
 * Failure is indicated by a NULL.
 */
static struct secret *lsw_get_secret(const struct connection *c,
				     enum PrivateKeyKind kind,
				     bool asym, struct logger *logger)
{
	/* is there a certificate assigned to this connection? */
	if ((kind == PKK_ECDSA || kind == PKK_RSA) &&
	    c->spd.this.cert.ty == CERT_X509_SIGNATURE &&
	    c->spd.this.cert.u.nss_cert != NULL) {

		id_buf this_buf, that_buf;
		dbg("%s() using certificate for %s->%s of kind %s",
		    __func__,
		    str_id(&c->spd.this.id, &this_buf),
		    str_id(&c->spd.that.id, &that_buf),
		    enum_name(&pkk_names, kind));

		dbg("allocating public key using connection's certificate; only to throw it a way");
		/* from here on: must free my_public_key */
		struct pubkey *my_public_key = allocate_pubkey_nss(c->spd.this.cert.u.nss_cert, logger);
		if (my_public_key == NULL) {
			loglog(RC_LOG_SERIOUS, "private key not found (certificate missing from NSS DB or token locked?)");
			return NULL;
		}

		dbg("finding secret using public key");
		struct secret *best = lsw_find_secret_by_public_key(pluto_secrets,
								    my_public_key);
		if (best == NULL) {
			const char *nickname = cert_nickname(&c->spd.this.cert);
			dbg("private key for cert %s not found in local cache; loading from NSS DB",
			    nickname);

			err_t err = load_nss_cert_secret(c->spd.this.cert.u.nss_cert);
			if (err != NULL) {
				/* ??? should this be logged? */
				dbg("private key for cert %s not found in NSS DB (%s)",
				    nickname, err);
			} else {
				best = lsw_find_secret_by_public_key(pluto_secrets,
								     my_public_key);
			}
		}
		/*
		 * If we don't find the right keytype (RSA, ECDSA, etc)
		 * then best will end up as NULL
		 */
		free_public_key(my_public_key);
		return best;
	}

	/* under certain conditions, override that_id to %ANYADDR */

	struct id rw_id;
	const struct id *const this_id = &c->spd.this.id;
	const struct id *that_id = &c->spd.that.id; /* can change */

	if (
	    /* case 1: */
	    ( remote_id_was_instantiated(c) &&
	      !(c->policy & POLICY_AGGRESSIVE) &&
	      isanyaddr(&c->spd.that.host_addr) ) ||

	    /* case 2 */
	    ( (c->policy & POLICY_PSK) &&
	      kind == PKK_PSK &&
	      ( ( c->kind == CK_TEMPLATE &&
		  c->spd.that.id.kind == ID_NONE ) ||
		( c->kind == CK_INSTANCE &&
		  id_is_ipaddr(&c->spd.that.id) &&
		  /* Check if we are a road warrior instantiation, not a vnet: instantiation */
		  isanyaddr(&c->spd.that.host_addr) ) ) )
		) {
		/* roadwarrior: replace that with %ANYADDR */
		rw_id.kind = addrtypeof(&c->spd.that.host_addr) == AF_INET ?
			     ID_IPV4_ADDR : ID_IPV6_ADDR;
		rw_id.ip_addr = address_any(address_type(&c->spd.that.host_addr));
		id_buf old_buf, new_buf;
		dbg("%s() switching remote roadwarrier ID from %s to %s (%%ANYADDR)",
		    __func__, str_id(that_id, &old_buf), str_id(&rw_id, &new_buf));
		that_id = &rw_id;

	}

	id_buf this_buf, that_buf;
	dbg("%s() using IDs for %s->%s of kind %s",
	    __func__,
	    str_id(this_id, &this_buf),
	    str_id(that_id, &that_buf),
	    enum_name(&pkk_names, kind));

	return lsw_find_secret_by_id(pluto_secrets,
				     kind,
				     this_id, that_id, asym);
}

/*
 * find the struct secret associated with an XAUTH username.
 */
struct secret *lsw_get_xauthsecret(char *xauthname)
{
	struct secret *best = NULL;

	dbg("started looking for xauth secret for %s", xauthname);

	struct id xa_id = {
		.kind = ID_FQDN,
		.name = {
			.ptr = (unsigned char *)xauthname,
			.len = strlen(xauthname)
		}
	};

	best = lsw_find_secret_by_id(pluto_secrets,
				     PKK_XAUTH,
				     &xa_id, NULL, TRUE);

	return best;
}

/* check the existence of an RSA private key matching an RSA public */
static bool has_private_rawkey(struct pubkey *pk)
{
	return lsw_has_private_rawkey(pluto_secrets, pk);
}

/*
 * find the appropriate preshared key (see get_secret).
 * Failure is indicated by a NULL pointer.
 * Note: the result is not to be freed by the caller.
 * Note2: this seems to be called for connections using RSA too?
 */
const chunk_t *get_psk(const struct connection *c,
		       struct logger *logger)
{
	if (c->policy & POLICY_AUTH_NULL) {
		DBG(DBG_CRYPT, DBG_log("Mutual AUTH_NULL secret - returning empty_chunk"));
		return &empty_chunk;
	}

	struct secret *s = lsw_get_secret(c, PKK_PSK, FALSE, logger);
	const chunk_t *psk =
		s == NULL ? NULL : &lsw_get_pks(s)->u.preshared_secret;

	if (psk != NULL) {
		DBG(DBG_PRIVATE, {
			DBG_dump_hunk("PreShared Key", *psk);
		});
	} else {
		dbg("no PreShared Key Found");
	}
	return psk;
}


/* Return ppk and store ppk_id in *ppk_id */

chunk_t *get_ppk(const struct connection *c, chunk_t **ppk_id,
		 struct logger *logger)
{
	struct secret *s = lsw_get_secret(c, PKK_PPK, FALSE, logger);

	if (s == NULL) {
		*ppk_id = NULL;
		return NULL;
	}

	struct private_key_stuff *pks = lsw_get_pks(s);
	*ppk_id = &pks->ppk_id;
	DBG(DBG_PRIVATE, {
		DBG_log("Found PPK");
		DBG_dump_hunk("PPK_ID:", **ppk_id);
		DBG_dump_hunk("PPK:", pks->ppk);
		});
	return &pks->ppk;
}

/*
 * Find PPK, by its id (PPK_ID).
 * Used by responder.
 */
const chunk_t *get_ppk_by_id(const chunk_t *ppk_id)
{
	struct secret *s = lsw_get_ppk_by_id(pluto_secrets, *ppk_id);

	if (s != NULL) {
		const struct private_key_stuff *pks = lsw_get_pks(s);
		DBG(DBG_PRIVATE, {
			DBG_dump_hunk("Found PPK:", pks->ppk);
			DBG_dump_hunk("with PPK_ID:", *ppk_id);
		});
		return &pks->ppk;
	}
	dbg("No PPK found with given PPK_ID");
	return NULL;
}

/*
 * Find the appropriate private key (see get_secret).  Failure is
 * indicated by a NULL pointer.
 */

const struct private_key_stuff *get_connection_private_key(const struct connection *c,
							   const struct pubkey_type *type,
							   struct logger *logger)
{
	struct secret *s = lsw_get_secret(c, type->private_key_kind, TRUE, logger);
	if (s == NULL) {
		dbg("no %s private key Found", type->name);
		return NULL;
	}

	const struct private_key_stuff *pks = lsw_get_pks(s);
	passert(pks != NULL);

	dbg("%s private key found", type->name);
	return pks;
}

/*
 * public key machinery
 */

/* root of chained public key list */

struct pubkey_list *pluto_pubkeys = NULL;       /* keys from ipsec.conf */

void free_remembered_public_keys(void)
{
	free_public_keys(&pluto_pubkeys);
}

err_t add_public_key(const struct id *id, /* ASKK */
		     enum dns_auth_level dns_auth_level,
		     const struct pubkey_type *type,
		     const chunk_t *key,
		     struct pubkey_list **head)
{
	struct pubkey *pk = alloc_thing(struct pubkey, "pubkey");

	/* first: algorithm-specific decoding of key chunk */
	type->unpack_pubkey_content(&pk->u, *key);
	pk->id = clone_id(id, "public key id");
	pk->dns_auth_level = dns_auth_level;
	pk->type = type;
	pk->until_time = realtime_epoch;
	pk->issuer = EMPTY_CHUNK;

	install_public_key(pk, head);
	return NULL;
}

err_t add_ipseckey(const struct id *id,
		   enum dns_auth_level dns_auth_level,
		   const struct pubkey_type *type,
		   uint32_t ttl, uint32_t ttl_used,
		   const chunk_t *key,
		   struct pubkey_list **head)
{
	struct pubkey *pk = alloc_thing(struct pubkey, "ipseckey publickey");

	/* first: algorithm-specific decoding of key chunk */
	type->unpack_pubkey_content(&pk->u, *key);
	pk->dns_ttl = ttl;
	pk->installed_time = realnow();
	pk->until_time = realtimesum(pk->installed_time, deltatime(ttl_used));
	pk->id = clone_id(id, "ipsec keyid");
	pk->dns_auth_level = dns_auth_level;
	pk->type = type;
	pk->issuer = EMPTY_CHUNK; /* ipseckey has no issuer */

	install_public_key(pk, head);
	return NULL;
}

/*
 *  list all public keys in the chained list
 */
void list_public_keys(struct fd *whackfd, bool utc, bool check_pub_keys)
{
	struct pubkey_list *p = pluto_pubkeys;

	if (!check_pub_keys) {
		whack_comment(whackfd, " ");
		whack_comment(whackfd, "List of Public Keys:");
		whack_comment(whackfd, " ");
	}

	while (p != NULL) {
		struct pubkey *key = p->key;

		switch (key->type->alg) {
		case PUBKEY_ALG_RSA:
		case PUBKEY_ALG_ECDSA:
		{
			const char *check_expiry_msg = check_expiry(key->until_time,
							PUBKEY_WARNING_INTERVAL,
							TRUE);

			if (!check_pub_keys ||
			    !startswith(check_expiry_msg, "ok")) {
				WHACK_LOG(RC_COMMENT, whackfd, buf) {
					jam_realtime(buf, key->installed_time, utc);
					jam(buf, ", ");
					switch (key->type->alg) {
					case PUBKEY_ALG_RSA:
						jam(buf, "%4d RSA Key %s",
						    8 * key->u.rsa.k,
						    key->u.rsa.keyid);
						break;
					case PUBKEY_ALG_ECDSA:
						jam(buf, "%4d ECDSA Key %s",
						    8 * key->u.ecdsa.k,
						    key->u.ecdsa.keyid);
						break;
					default:
						bad_case(key->type->alg);
					}
					jam(buf, " (%s private key), until ",
					    (has_private_rawkey(key) ? "has" : "no"));
					jam_realtime(buf, key->until_time, utc);
					jam(buf, " %s", check_expiry_msg);
				}

				/* XXX could be ikev2_idtype_names */
				id_buf idb;

				whack_comment(whackfd, "       %s '%s'",
					enum_show(&ike_idtype_names,
						    key->id.kind),
					str_id(&key->id, &idb));

				if (key->issuer.len > 0) {
					dn_buf b;
					whack_comment(whackfd,
						  "       Issuer '%s'",
						  str_dn(key->issuer, &b));
				}
			}
			break;
		}
		default:
			dbg("ignoring key with unsupported alg %d", key->type->alg);
		}
		p = p->next;
	}
}

err_t load_nss_cert_secret(CERTCertificate *cert)
{
	threadtime_t start = threadtime_start();
	err_t err = lsw_add_secret(&pluto_secrets, cert);
	threadtime_stop(&start, SOS_NOBODY, "%s() loading private key %s", __func__,
			cert->nickname);
	return err;
}

static bool rsa_pubkey_ckaid_matches(struct pubkey *pubkey, char *buf, size_t buflen)
{
	if (pubkey->u.rsa.n.ptr == NULL) {
		dbg("RSA pubkey with NULL modulus");
		return FALSE;
	}
	SECItem modulus = {
		.type = siBuffer,
		.len = pubkey->u.rsa.n.len,
		.data = pubkey->u.rsa.n.ptr,
	};
	SECItem *pubkey_ckaid = PK11_MakeIDFromPubKey(&modulus);
	if (pubkey_ckaid == NULL) {
		dbg("RSA pubkey incomputable CKAID");
		return FALSE;
	}
	LSWDBGP(DBG_BASE, buf) {
		jam(buf, "comparing ckaid with: ");
		jam_nss_secitem(buf, pubkey_ckaid);
	}
	bool eq = pubkey_ckaid->len == buflen &&
		  memcmp(pubkey_ckaid->data, buf, buflen) == 0;
	SECITEM_FreeItem(pubkey_ckaid, PR_TRUE);
	return eq;
}

struct pubkey *get_pubkey_with_matching_ckaid(const char *ckaid)
{
	/* convert hex string ckaid to binary bin */
	size_t binlen = (strlen(ckaid) + 1) / 2;
	char *bin = alloc_bytes(binlen, "ckaid");
	const char *ugh = ttodata(ckaid, 0, 16, bin, binlen, &binlen);
	if (ugh != NULL) {
		pfree(bin);
		/* should have been rejected by whack? */
		libreswan_log("invalid hex CKAID '%s': %s", ckaid, ugh);
		return NULL;
	}
	if (DBGP(DBG_BASE)) {
		DBG_dump("looking for pubkey with CKAID that matches", bin, binlen);
	}

	struct pubkey_list *p;
	for (p = pluto_pubkeys; p != NULL; p = p->next) {
		DBG_log("looking at a PUBKEY");
		struct pubkey *key = p->key;
		switch (key->type->alg) {
		case PUBKEY_ALG_RSA: {
			if (rsa_pubkey_ckaid_matches(key, bin, binlen)) {
				dbg("ckaid matching pubkey");
				pfree(bin);
				return key;
			}
		}
		default:
			break;
		}
	}
	pfree(bin);
	return NULL;
}
