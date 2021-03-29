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
#include "ip_info.h"
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

void load_preshared_secrets(struct logger *logger)
{
	const struct lsw_conf_options *oco = lsw_init_options();
	lsw_load_preshared_secrets(&pluto_secrets, oco->secretsfile, logger);
}

void free_preshared_secrets(struct logger *logger)
{
	lsw_free_preshared_secrets(&pluto_secrets, logger);
}

static int print_secrets(struct secret *secret,
			 struct private_key_stuff *pks UNUSED,
			 void *uservoid)
{
	struct show *s = uservoid;

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

	int indent = 0;
	SHOW_JAMBUF(RC_COMMENT, s, buf) {
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
		SHOW_JAMBUF(RC_COMMENT, s, buf) {
			jam(buf, "%*s ckaid: ", indent, "");
			jam_ckaid(buf, ckaid);
		}
	}

	/* continue loop until end */
	return 1;
}

void list_psks(struct show *s)
{
	const struct lsw_conf_options *oco = lsw_init_options();
	show_comment(s, " "); /* show_separator(s); */
	show_comment(s, "List of Pre-shared secrets (from %s)",
		     oco->secretsfile);
	show_comment(s, " "); /* show_separator(s); */
	lsw_foreach_secret(pluto_secrets, print_secrets, s);
}

err_t try_signature_RSA(const struct crypt_mac *expected_hash,
			shunk_t signature,
			struct pubkey *kr,
			const struct hash_desc *hash_algo,
			struct logger *logger)
{
	const struct RSA_public_key *k = &kr->u.rsa;

	/* decrypt the signature -- reversing RSA_sign_hash */
	if (signature.len != kr->size) {
		/* XXX notification: INVALID_KEY_INFORMATION */
		return "1" "SIG length does not match public key length";
	}

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
		.data = DISCARD_CONST(unsigned char *, signature.ptr),
		.len  = signature.len,
	};

	if (hash_algo == NULL /* ikev1*/ ||
	    hash_algo == &ike_alg_hash_sha1 /* old style rsa with SHA1*/) {
		SECItem decrypted_signature = {
			.type = siBuffer,
		};
		if (SECITEM_AllocItem(publicKey->arena, &decrypted_signature,
				      signature.len) == NULL) {
			SECKEY_DestroyPublicKey(publicKey);
			return "12""NSS error: unable to allocate space for decrypted signature";
		}

		if (PK11_VerifyRecover(publicKey, &encrypted_signature,
				       &decrypted_signature,
				       lsw_nss_get_password_context(logger)) != SECSuccess) {
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
			llog(RC_LOG_SERIOUS, logger, "RSA Signature NOT verified");
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
					     lsw_nss_get_password_context(logger)) != SECSuccess) {
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
	const struct crypt_mac *hash;
	shunk_t signature;
	const struct hash_desc *hash_algo;
	try_signature_fn *try_signature;
	realtime_t now;
	struct logger *logger;
	const struct end *remote;

	/* state carried between calls */
	err_t best_ugh; /* most successful failure */
	int tried_cnt;  /* number of keys tried */
	char tried[50]; /* keyids of tried public keys */
	struct jambuf tried_jambuf;
	struct pubkey *key;
};

static bool try_all_keys(const char *pubkey_description,
			 struct pubkey_list *pubkey_db,
			 struct tac_state *s)
{

	id_buf thatid;
	dbg("trying all %s public keys for %s key that matches ID: %s",
	    pubkey_description, s->type->name, str_id(&s->remote->id, &thatid));

	for (struct pubkey_list *p = pubkey_db; p != NULL; p = p->next) {
		struct pubkey *key = p->key;

		if (key->type != s->type) {
			id_buf printkid;
			dbg("  skipping '%s' with type %s",
			    str_id(&key->id, &printkid), key->type->name);
			continue;
		}

		if (!same_id(&s->remote->id, &key->id)) {
			id_buf printkid;
			dbg("  skipping '%s' with wrong ID",
			    str_id(&key->id, &printkid));
			continue;
		}

		int pl;	/* value ignored */
		if (!trusted_ca_nss(key->issuer, s->remote->ca, &pl)) {
			id_buf printkid;
			dn_buf buf;
			dbg("  skipping '%s' with untrusted CA '%s'",
			    str_id(&key->id, &printkid),
			    str_dn_or_null(key->issuer, "%any", &buf));
			continue;
		}

		/*
		 * XXX: even though loop above filtered out these
		 * certs, keep this check, at some point the above
		 * loop will be deleted.
		 */
		if (!is_realtime_epoch(key->until_time) &&
		    realbefore(key->until_time, s->now)) {
			id_buf printkid;
			realtime_buf buf;
			dbg("  skipping '%s' which expired on %s",
			    str_id(&key->id, &printkid),
			    str_realtime(key->until_time, /*utc?*/false, &buf));
			continue;
		}

		id_buf printkid;
		dn_buf buf;
		dbg("  trying '%s' issued by CA '%s'",
		    str_id(&key->id, &printkid), str_dn_or_null(key->issuer, "%any", &buf));

		const char *key_id_str = str_keyid(*pubkey_keyid(key));

		s->tried_cnt++;
		logtime_t try_time = logtime_start(s->logger);
		err_t ugh = (s->try_signature)(s->hash, s->signature,
					       key, s->hash_algo,
					       s->logger);
		logtime_stop(&try_time, "%s() trying a pubkey", __func__);

		if (ugh == NULL) {
			/*
			 * Success: copy successful key into state.
			 * There might be an old one if we previously
			 * aborted this state transition.
			 */
			dbg("an %s signature check passed with *%s [%s]",
			    key->type->name, key_id_str, pubkey_description);
			s->key = key;
			return true;
		}

		llog(RC_LOG_SERIOUS, s->logger,
		     "an %s Sig check failed '%s' with *%s [%s]",
		     key->type->name, ugh + 1, key_id_str, pubkey_description);
		if (s->best_ugh == NULL || s->best_ugh[0] < ugh[0])
			s->best_ugh = ugh;
		if (ugh[0] > '0') {
			jam(&s->tried_jambuf, " *%s", key_id_str);
		}

	}
	return false;
}

stf_status check_signature_gen(struct ike_sa *ike,
			       const struct crypt_mac *hash,
			       shunk_t signature,
			       const struct hash_desc *hash_algo,
			       const struct pubkey_type *type,
			       try_signature_fn *try_signature)
{
	const struct connection *c = ike->sa.st_connection;
	struct tac_state s = {
		/* in */
		.type = type,
		.logger = ike->sa.st_logger,
		.hash = hash,
		.now = realnow(),
		.signature = signature,
		.hash_algo = hash_algo,
		.remote = &c->spd.that,
		.try_signature = try_signature,
		/* out */
		.best_ugh = NULL,
		.tried_cnt = 0,
		.key = NULL,
	};
	s.tried_jambuf = ARRAY_AS_JAMBUF(s.tried);

	/* try all appropriate Public keys */

	if (DBGP(DBG_BASE)) {
		dn_buf buf;
		DBG_log("required %s CA is '%s'",
			type->name,
			str_dn_or_null(c->spd.that.ca, "%any", &buf));
	}

	pexpect(ike->sa.st_remote_certs.processed);
	bool found = try_all_keys("remote certificates", ike->sa.st_remote_certs.pubkey_db, &s);

	/*
	 * Prune the expired public keys from the pre-loaded public
	 * key list.  But why here, and why not as a separate job?
	 * And why blame the IKE SA as it isn't really its fault?
	 */
	for (struct pubkey_list **pp = &pluto_pubkeys; *pp != NULL; ) {
		struct pubkey *key = (*pp)->key;
		if (!is_realtime_epoch(key->until_time) &&
		    realbefore(key->until_time, s.now)) {
			id_buf printkid;
			log_state(RC_LOG_SERIOUS, &ike->sa,
				  "cached %s public key '%s' has expired and has been deleted",
				  key->type->name, str_id(&key->id, &printkid));
			*pp = free_public_keyentry(*(pp));
			continue; /* continue with next public key */
		}
		pp = &(*pp)->next;
	}

	if (!found) {
		found = try_all_keys("preloaded keys", pluto_pubkeys, &s);
	}

	if (found) {
		pubkey_delref(&ike->sa.st_peer_pubkey, HERE);
		ike->sa.st_peer_pubkey = pubkey_addref(s.key, HERE);
		log_state(RC_LOG_SERIOUS, &ike->sa,
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
	str_id(&c->spd.that.id, &id_str);
	passert(id_str.buf[0] != '\0');

	if (s.best_ugh == NULL) {
		log_state(RC_LOG_SERIOUS, &ike->sa,
			  "no %s public key known for '%s'",
			  type->name, id_str.buf);
		/* ??? is this the best code there is? */
		return STF_FAIL + INVALID_KEY_INFORMATION;
	}

	if (s.tried_cnt == 1) {
		log_state(RC_LOG_SERIOUS, &ike->sa,
			  "%s Signature check (on %s) failed (wrong key?); tried%s",
			  type->name, id_str.buf, s.tried);
	} else {
		log_state(RC_LOG_SERIOUS, &ike->sa,
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
				     bool asym, struct logger *logger UNUSED)
{
	/* under certain conditions, override that_id to %ANYADDR */

	struct id rw_id;
	const struct id *const this_id = &c->spd.this.id;
	const struct id *that_id = &c->spd.that.id; /* can change */

	if (
	    /* case 1: */
	    ( remote_id_was_instantiated(c) &&
	      !(c->policy & POLICY_AGGRESSIVE) &&
	      (address_is_unset(&c->spd.that.host_addr) ||
	       address_is_any(c->spd.that.host_addr)) ) ||

	    /* case 2 */
	    ( (c->policy & POLICY_PSK) &&
	      kind == PKK_PSK &&
	      ( ( c->kind == CK_TEMPLATE &&
		  c->spd.that.id.kind == ID_NONE ) ||
		( c->kind == CK_INSTANCE &&
		  id_is_ipaddr(&c->spd.that.id) &&
		  /* Check if we are a road warrior instantiation, not a vnet: instantiation */
		  (address_is_unset(&c->spd.that.host_addr) ||
		   address_is_any(c->spd.that.host_addr)) ) ) )
		) {
		/* roadwarrior: replace that with %ANYADDR */
		rw_id.kind = address_type(&c->spd.that.host_addr)->id_ip_addr;
		rw_id.ip_addr = address_type(&c->spd.that.host_addr)->address.any;
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

	return lsw_find_secret_by_id(pluto_secrets, kind,
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

/*
 * find the appropriate preshared key (see get_secret).
 * Failure is indicated by a NULL pointer.
 * Note: the result is not to be freed by the caller.
 * Note2: this seems to be called for connections using RSA too?
 */
const chunk_t *get_connection_psk(const struct connection *c,
				  struct logger *logger)
{
	if (c->policy & POLICY_AUTH_NULL) {
		DBGF(DBG_CRYPT, "Mutual AUTH_NULL secret - returning empty_chunk");
		return &empty_chunk;
	}

	struct secret *s = lsw_get_secret(c, PKK_PSK, FALSE, logger);
	const chunk_t *psk =
		s == NULL ? NULL : &lsw_get_pks(s)->u.preshared_secret;

	if (psk != NULL) {
		if (DBGP(DBG_CRYPT)) {
			DBG_dump_hunk("PreShared Key", *psk);
		}
	} else {
		dbg("no PreShared Key Found");
	}
	return psk;
}


/* Return ppk and store ppk_id in *ppk_id */

chunk_t *get_connection_ppk(const struct connection *c, chunk_t **ppk_id,
			    struct logger *logger)
{
	struct secret *s = lsw_get_secret(c, PKK_PPK, FALSE, logger);

	if (s == NULL) {
		*ppk_id = NULL;
		return NULL;
	}

	struct private_key_stuff *pks = lsw_get_pks(s);
	*ppk_id = &pks->ppk_id;
	if (DBGP(DBG_CRYPT)) {
		DBG_log("Found PPK");
		DBG_dump_hunk("PPK_ID:", **ppk_id);
		DBG_dump_hunk("PPK:", pks->ppk);
	}
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
		if (DBGP(DBG_CRYPT)) {
			DBG_dump_hunk("Found PPK:", pks->ppk);
			DBG_dump_hunk("with PPK_ID:", *ppk_id);
		}
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
	/* is there a certificate assigned to this connection? */
	if (c->spd.this.cert.ty == CERT_X509_SIGNATURE &&
	    c->spd.this.cert.u.nss_cert != NULL) {
		const char *nickname = cert_nickname(&c->spd.this.cert);

		id_buf this_buf, that_buf;
		dbg("%s() using certificate %s to find private key for %s->%s of kind %s",
		    __func__, nickname,
		    str_id(&c->spd.this.id, &this_buf),
		    str_id(&c->spd.that.id, &that_buf),
		    type->name);

		const struct private_key_stuff *pks = NULL;
		bool load_needed;
		err_t err = find_or_load_private_key_by_cert(&pluto_secrets, &c->spd.this.cert,
							     &pks, &load_needed, logger);
		if (err != NULL) {
			dbg("private key for certificate %s not found in NSS DB",
			    nickname);
			return NULL;
		} else if (load_needed) {
			/*
			 * XXX: the private key that was pre-loaded
			 * during "whack add" may have been deleted
			 * because all secrets were thrown away.
			 *
			 * The real problem is that the connection
			 * lacks a counted reference to the private
			 * key.
			 */
			llog(RC_LOG|LOG_STREAM/*not-whack-grrr*/, logger,
				    "reloaded private key matching %s certificate '%s'",
				    c->spd.this.leftright, nickname);
		}

		/*
		 * If we don't find the right keytype (RSA, ECDSA,
		 * etc) then best will end up as NULL
		 */
		dbg("connection %s's %s private key found in NSS DB using cert",
		    c->name, type->name);
		return pks;
	}

	/* is there a CKAID assigned to this connection? */
	if (c->spd.this.ckaid != NULL) {
		ckaid_buf ckb;
		id_buf this_buf, that_buf;
		dbg("%s() using CKAID %s to find private key for %s->%s of kind %s",
		    __func__, str_ckaid(c->spd.this.ckaid, &ckb),
		    str_id(&c->spd.this.id, &this_buf),
		    str_id(&c->spd.that.id, &that_buf),
		    type->name);

		const struct private_key_stuff *pks;
		bool load_needed;
		err_t err = find_or_load_private_key_by_ckaid(&pluto_secrets, c->spd.this.ckaid,
							      &pks, &load_needed, logger);
		if (err != NULL) {
			ckaid_buf ckb;
			llog(RC_LOG_SERIOUS, logger,
				    "private key matching CKAID '%s' not found: %s",
				    str_ckaid(c->spd.this.ckaid, &ckb), err);
			return NULL;
		} else if (load_needed) {
			/*
			 * XXX: the private key that was pre-loaded
			 * during "whack add" may have been deleted
			 * because all secrets were thrown away.
			 *
			 * The real problem is that the connection
			 * lacks a counted reference to the private
			 * key.
			 */
			ckaid_buf ckb;
			llog(RC_LOG|LOG_STREAM/*not-whack-grr*/, logger,
				    "reloaded private key matching %s CKAID %s",
				    c->spd.this.leftright, str_ckaid(c->spd.this.ckaid, &ckb));
		}


		/*
		 * If we don't find the right keytype (RSA, ECDSA,
		 * etc) then best will end up as NULL
		 */
		dbg("connection %s's %s private key found in NSS DB using CKAID",
		    c->name, type->name);
		return pks;
	}

	dbg("looking for connection %s's %s private key",
	    c->name, type->name);
	struct secret *s = lsw_get_secret(c, type->private_key_kind, true, logger);
	if (s == NULL) {
		llog(RC_LOG_SERIOUS, logger, "connection %s's %s private key not found",
		    c->name, type->name);
		return NULL;
	}

	const struct private_key_stuff *pks = lsw_get_pks(s);
	passert(pks != NULL);

	dbg("connection %s's %s private key found",
	    c->name, type->name);
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

/*
 *  list all public keys in the chained list
 */
void list_public_keys(struct show *s, bool utc, bool check_pub_keys)
{
	struct pubkey_list *p = pluto_pubkeys;

	if (!check_pub_keys) {
		/*
		 * XXX: when there are no keys, the tests expect the
		 * title with blank lines either side. Using the
		 * current show_separator() would suppress that.  But
		 * should this change, or should show_separator()
		 * change to always wrap output in blank lines?
		 */
#if 0
		show_separator(s);
#else
		show_comment(s, " ");
#endif
		show_comment(s, "List of Public Keys:");
#if 0
		show_separator(s);
#else
		show_comment(s, " ");
#endif
	}

	while (p != NULL) {
		struct pubkey *key = p->key;
		const char *check_expiry_msg = check_expiry(key->until_time,
							    PUBKEY_WARNING_INTERVAL,
							    TRUE);
		if (!check_pub_keys ||
		    !startswith(check_expiry_msg, "ok")) {
			bool load_needed;
			err_t load_err = preload_private_key_by_ckaid(&key->ckaid,
								      &load_needed,
								      show_logger(s));
			SHOW_JAMBUF(RC_COMMENT, s, buf) {
				jam_realtime(buf, key->installed_time, utc);
				jam(buf, ",");
				jam(buf, " %4zd", 8 * key->size);
				jam(buf, " %s", key->type->name);
				jam(buf, " Key %s", str_keyid(key->keyid));
				jam(buf, " (%s private key),",
				    (load_err != NULL ? "no" :
				     load_needed ? "loaded" : "has"));
				jam(buf, " until ");
				jam_realtime(buf, key->until_time, utc);
				jam(buf, " %s", check_expiry_msg);
			}

			/* XXX could be ikev2_idtype_names */
			id_buf idb;
			esb_buf b;
			show_comment(s, "       %s '%s'",
				     enum_show(&ike_idtype_names, key->id.kind, &b),
				     str_id(&key->id, &idb));

			if (key->issuer.len > 0) {
				dn_buf b;
				show_comment(s, "       Issuer '%s'",
					     str_dn(key->issuer, &b));
			}
		}
		p = p->next;
	}
}

err_t preload_private_key_by_cert(const struct cert *cert, bool *load_needed, struct logger *logger)
{
	threadtime_t start = threadtime_start();
	const struct private_key_stuff *pks;
	err_t err = find_or_load_private_key_by_cert(&pluto_secrets, cert,
						     &pks, load_needed, logger);
	threadtime_stop(&start, SOS_NOBODY, "%s() loading private key %s", __func__,
			cert->u.nss_cert->nickname);
	return err;
}

err_t preload_private_key_by_ckaid(const ckaid_t *ckaid, bool *load_needed, struct logger *logger)
{
	threadtime_t start = threadtime_start();
	const struct private_key_stuff *pks;
	err_t err = find_or_load_private_key_by_ckaid(&pluto_secrets, ckaid,
						      &pks, load_needed, logger);
	threadtime_stop(&start, SOS_NOBODY, "%s() loading private key using CKAID", __func__);
	return err;
}

const struct pubkey *find_pubkey_by_ckaid(const char *ckaid)
{
	for (struct pubkey_list *p = pluto_pubkeys; p != NULL; p = p->next) {
		DBG_log("looking at a PUBKEY");
		struct pubkey *key = p->key;
		const ckaid_t *key_ckaid = pubkey_ckaid(key);
		if (ckaid_starts_with(key_ckaid, ckaid)) {
			dbg("ckaid matching pubkey");
			return key;
		}
	}
	return NULL;
}
