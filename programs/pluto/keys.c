/* interfaces to the secrets.c library functions in libswan.
 *
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2003-2008  Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2015 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2016-2022 Andrew Cagney
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
#include "whack.h"      /* for RC_LOG */
#include "timer.h"

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
#include "config_setup.h"
#include "lswnss.h"
#include "secrets.h"
#include "ike_alg_hash.h"
#include "pluto_timing.h"
#include "show.h"

static struct secret *pluto_secrets = NULL;

void load_preshared_secrets(struct logger *logger)
{
	lsw_load_preshared_secrets(&pluto_secrets, config_setup_secretsfile(), logger);
}

void free_preshared_secrets(struct logger *logger)
{
	lsw_free_preshared_secrets(&pluto_secrets, logger);
}

struct secret_context {
	struct show *s;
};

static int print_secrets(struct secret *secret,
			 enum secret_kind secret_kind,
			 unsigned secret_line,
			 struct secret_context *context)
{
	struct show *s = context->s;

	const char *kind;
	switch (secret_kind) {
	case SECRET_PSK:
		kind = "PSK";
		break;
	case SECRET_RSA:
		kind = "RSA";
		break;
	case SECRET_XAUTH:
		kind = "XAUTH";
		break;
	case SECRET_ECDSA:
		kind = "ECDSA";
		break;
	default:
		return 1;
	}

	struct id_list *ids = lsw_get_idlist(secret);

	int indent = 0;
	SHOW_JAMBUF(s, buf) {
		indent = jam(buf, "%5d:", secret_line);
		jam(buf, " %s ", kind);
		if (ids == NULL) {
			jam(buf, "%%any");
		} else {
			jam_id_bytes(buf, &ids->id, jam_sanitized_bytes);
			if (ids->next != NULL) {
				jam(buf, " ");
				jam_id_bytes(buf, &ids->next->id, jam_sanitized_bytes);
				if (ids->next->next != NULL) {
					jam(buf, " more");
				}
			}
		}
	}

	const ckaid_t *ckaid = secret_ckaid(secret); /* may be NULL */
	if (ckaid != NULL) {
		SHOW_JAMBUF(s, buf) {
			jam(buf, "%*s ckaid: ", indent, "");
			jam_ckaid(buf, ckaid);
		}
	}

	/* continue loop until end */
	return 1;
}

void list_psks(struct show *s)
{
	show_blank(s);
	show(s, "List of Pre-shared secrets (from %s)", config_setup_secretsfile());
	show_blank(s);
	struct secret_context context = {
		.s = s,
	};
	foreach_secret(pluto_secrets, print_secrets, &context);
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
	const struct pubkey_signer *signer;
	const struct crypt_mac *hash;
	shunk_t signature;
	const struct hash_desc *hash_algo;
	realtime_t now;
	struct logger *logger;
	const struct host_end *remote;
	enum cert_origin {
		PEER,
		PRELOADED,
	} cert_origin;
#define str_cert_origin(O)				\
	({						\
		enum cert_origin o_ = O;		\
		(o_ == PEER ? "peer" :			\
		 o_ == PRELOADED ? "preloaded" :	\
		 "???");				\
	})

	/*
	 * Both accumulated across calls and used to return the final
	 * result.
	 *
	 * See below.
	 */

	int tried_cnt;			/* number of keys tried */
	char tried[50];			/* keyids of tried public keys */
	struct jambuf tried_jambuf;	/* jambuf for same */
	struct pubkey *key;		/* last key tried, if any */
	diag_t fatal_diag;		/* fatal error from KEY, if any */
};

/*
 * Try all keys from PUBKEY_DB.
 *
 * Return true when searching should stop (not when it succeeded);
 * return false when searching can continue.
 *
 *   Returns  FATAL_DIAG  KEY     tried_cnt
 *    false     NULL     NULL        0      no key, try again
 *    false     NULL     NULL       >0      no key worked, try again
 *    true    <valid>   <valid>     N/A     fatal error caused by KEY
 *    true      NULL    <valid>     N/A     KEY worked
 */

static bool try_all_keys(enum cert_origin cert_origin,
			 struct pubkey_list *pubkey_db,
			 struct tac_state *s)
{
	id_buf thatid;
	ldbg(s->logger, "trying all '%s's for %s key using %s signature that matches ID: %s",
	     str_cert_origin(cert_origin),
	     s->signer->type->name, s->signer->name,
	     str_id(&s->remote->id, &thatid));
	s->cert_origin = cert_origin;

	bool described = false;
	for (struct pubkey_list *p = pubkey_db; p != NULL; p = p->next) {
		struct pubkey *key = p->key;

		if (key->content.type != s->signer->type) {
			id_buf printkid;
			dbg("  skipping '%s' with type %s",
			    str_id(&key->id, &printkid), key->content.type->name);
			continue;
		}

		struct verbose verbose = { .logger = &global_logger, };
		int wildcards; /* value ignored */
		if (!match_id(&key->id, &s->remote->id,
			      &wildcards, verbose)) {
			id_buf printkid;
			dbg("  skipping '%s' with wrong ID",
			    str_id(&key->id, &printkid));
			continue;
		}

		int pl;	/* value ignored */
		if (!trusted_ca(key->issuer, ASN1(s->remote->config->ca),
				&pl, verbose)) {
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
		    realtime_cmp(key->until_time, <, s->now)) {
			id_buf printkid;
			realtime_buf buf;
			dbg("  skipping '%s' which expired on %s",
			    str_id(&key->id, &printkid),
			    str_realtime(key->until_time, /*utc?*/false, &buf));
			continue;
		}

		id_buf printkid;
		dn_buf buf;
		const char *keyid_str = str_keyid(*pubkey_keyid(key));
		dbg("  trying '%s' aka *%s issued by CA '%s'",
		    str_id(&key->id, &printkid), keyid_str,
		    str_dn_or_null(key->issuer, "%any", &buf));
		s->tried_cnt++;

		if (!described) {
			jam(&s->tried_jambuf, " %s:",
			    str_cert_origin(cert_origin));
			described = true;
		}
		jam(&s->tried_jambuf, " *%s", keyid_str);

		logtime_t try_time = logtime_start(s->logger);
		bool passed = (s->signer->authenticate_signature)(s->hash, s->signature,
								  key, s->hash_algo,
								  &s->fatal_diag, s->logger);
		logtime_stop(&try_time, "%s() trying a pubkey", __func__);

		if (s->fatal_diag != NULL) {
			/* already logged */
			dbg("  '%s' fatal", keyid_str);
			jam(&s->tried_jambuf, "(fatal)");
			s->key = key; /* also return failing key */
			return true; /* stop searching; enough is enough */
		}

		if (passed) {
			dbg("  '%s' passed", keyid_str);
			s->key = key;
			return true; /* stop searching */
		}

		/* should have been logged */
		dbg("  '%s' failed", keyid_str);
		pexpect(s->key == NULL);
	}

	return false; /* keep searching */
}

diag_t authsig_and_log_using_pubkey(struct ike_sa *ike,
				    const struct crypt_mac *hash,
				    shunk_t signature,
				    const struct hash_desc *hash_algo,
				    const struct pubkey_signer *signer,
				    const char *signature_payload_name)
{
	const struct connection *c = ike->sa.st_connection;
	struct tac_state s = {
		/* in */
		.signer = signer,
		.logger = ike->sa.logger,
		.hash = hash,
		.now = realnow(),
		.signature = signature,
		.hash_algo = hash_algo,
		.remote = &c->remote->host,
		/* out */
		.tried_cnt = 0,
		.key = NULL,
		.fatal_diag = NULL,
	};
	s.tried_jambuf = ARRAY_AS_JAMBUF(s.tried);

	/* try all appropriate Public keys */

	dn_buf buf;
	dbg("CA is '%s' for %s key using %s signature",
	    str_dn_or_null(ASN1(c->remote->host.config->ca), "%any", &buf),
	    signer->type->name, signer->name);

	passert(ike->sa.st_remote_certs.processed);

	/*
	 * Prune the expired public keys from the pre-loaded public
	 * key list.  But why here, and why not as a separate job?
	 * And why blame the IKE SA as it isn't really its fault?
	 */
	for (struct pubkey_list **pp = &pluto_pubkeys; *pp != NULL; ) {
		struct pubkey *key = (*pp)->key;
		if (!is_realtime_epoch(key->until_time) &&
		    realtime_cmp(key->until_time, <, s.now)) {
			id_buf printkid;
			llog_sa(RC_LOG, ike,
				  "cached %s public key '%s' has expired and has been deleted",
				  key->content.type->name, str_id(&key->id, &printkid));
			*pp = free_public_keyentry(*(pp));
			continue; /* continue with next public key */
		}
		pp = &(*pp)->next;
	}

	bool stop = try_all_keys(PEER, ike->sa.st_remote_certs.pubkey_db, &s);
	if (!stop) {
		stop = try_all_keys(PRELOADED, pluto_pubkeys, &s);
	}

	if (s.fatal_diag != NULL) {
		passert(s.key != NULL);
		id_buf idb;
		return diag_diag(&s.fatal_diag, "authentication aborted: problem with '%s': ",
				 str_id(&s.key->id, &idb));
	}

	if (s.key == NULL) {
		if (s.tried_cnt == 0) {
			id_buf idb;
			return diag("authentication failed: no certificate matched %s with %s and '%s'",
				    signer->name, hash_algo->common.fqn,
				    str_id(&c->remote->host.id, &idb));
		} else {
			id_buf idb;
			return diag("authentication failed: using %s with %s for '%s' tried%s",
				    signer->name, hash_algo->common.fqn,
				    str_id(&c->remote->host.id, &idb),
				    s.tried);
		}
	}

	pexpect(s.key != NULL);
	pexpect(s.tried_cnt > 0);
	LLOG_JAMBUF(RC_LOG, ike->sa.logger, buf) {
		if (ike->sa.st_ike_version == IKEv2) {
			/*
			 * IKEv2 only; IKEv1 logs established as a
			 * separate line.
			 */
			jam(buf, "%s established IKE SA; ",
			    (ike->sa.st_sa_role == SA_INITIATOR ? "initiator" :
			     ike->sa.st_sa_role == SA_RESPONDER ? "responder" :
			     "?"));
		}
		/* all methods log this string */
		jam_string(buf, "authenticated peer ");
		switch (s.cert_origin) {
		case PEER:
			jam_string(buf, "certificate");
			break;
		case PRELOADED:
			jam_string(buf, "using preloaded certificate");
			break;
		}
		/* the peer's certificate: 'CA=.... ' */
		jam_string(buf, " '");
		jam_id_bytes(buf, &s.key->id, jam_sanitized_bytes);
		jam_string(buf, "'");
		/* the authentication method: 3048-bit RSA ... */
		jam_string(buf, " and ");
		signer->jam_auth_method(buf, signer, s.key, hash_algo);
		/* the payload name: digital signature */
		if (signature_payload_name != NULL) {
			jam(buf, " %s", signature_payload_name);
		} else {
			jam(buf, " signature");
		}
		/* this is so that the cert verified line can be deleted */
		if (s.key->issuer.ptr != NULL) {
			jam_string(buf, " issued by ");
			jam_string(buf, "'");
			jam_dn(buf, s.key->issuer, jam_sanitized_bytes);
			jam_string(buf, "'");
		}
	}
	pubkey_delref(&ike->sa.st_peer_pubkey);
	ike->sa.st_peer_pubkey = pubkey_addref(s.key);
	return NULL;
}

/*
 * Find the struct secret associated with the combination of me and
 * the peer.  We match the Id (if none, the IP address).  Failure is
 * indicated by a NULL.
 */

static struct secret *lsw_get_secret(const struct connection *c,
				     enum secret_kind kind,
				     bool asym)
{
	/* under certain conditions, override that_id to %ANYADDR */

	struct id rw_id; /* MUST BE AT SAME SCOPE AS THAT_ID */
	const struct id *const this_id = &c->local->host.id;
	const struct id *that_id = &c->remote->host.id; /* can change */

	if (
	    /* case 1: */
	    ( remote_id_was_instantiated(c) &&
	      !c->config->aggressive &&
	      !address_is_specified(c->remote->host.addr) ) ||

	    /* case 2 */
	    ( c->remote->host.config->authby.psk &&
	      kind == SECRET_PSK /*shared-secret*/ &&
	      ( ( is_template(c) &&
		  c->remote->host.id.kind == ID_NONE ) ||
		( is_instance(c) &&
		  id_is_ipaddr(&c->remote->host.id) &&
		  /* Check if we are a road warrior instantiation, not a vnet: instantiation */
		  !address_is_specified(c->remote->host.addr) ) ) ) ) {
		/*
		 * Since the remote host_addr isn't specified it's
		 * AFI isn't known; but presumably the local end
		 * is oriented and known.
		 */
		pexpect(address_is_specified(c->local->host.addr));
		/* roadwarrior: replace that with %ANYADDR */
		rw_id = (struct id) {
			.kind = address_info(c->local->host.addr)->id_ip_addr,
			.ip_addr = address_info(c->local->host.addr)->address.unspec,
		};
		id_buf old_buf, new_buf;
		dbg("%s() switching remote roadwarrier ID from %s to %s (%%ANYADDR)",
		    __func__, str_id(that_id, &old_buf), str_id(&rw_id, &new_buf));
		that_id = &rw_id;
	}

	id_buf this_buf, that_buf;
	name_buf kb;
	ldbg(c->logger, "%s() using IDs for %s->%s of kind %s",
	     __func__,
	     str_id(this_id, &this_buf),
	     str_id(that_id, &that_buf),
	     str_enum_long(&secret_kind_names, kind, &kb));

	return lsw_find_secret_by_id(pluto_secrets, kind,
				     this_id, that_id, asym);
}

/*
 * find the struct secret associated with an XAUTH username.
 */
const struct secret_preshared_stuff *xauth_secret_by_xauthname(char *xauthname)
{
	dbg("started looking for xauth secret for %s", xauthname);

	struct id xa_id = {
		.kind = ID_FQDN,
		.name = {
			.ptr = (unsigned char *)xauthname,
			.len = strlen(xauthname)
		}
	};

	struct secret *best = lsw_find_secret_by_id(pluto_secrets,
						    SECRET_XAUTH,
						    &xa_id, NULL, true);
	if (best == NULL) {
		return NULL;
	}

	return secret_preshared_stuff(best);
}

/*
 * find the appropriate preshared key (see get_secret).
 * Failure is indicated by a NULL pointer.
 * Note: the result is not to be freed by the caller.
 * Note2: this seems to be called for connections using RSA too?
 */

const struct secret_preshared_stuff *get_connection_psk(const struct connection *c)
{
	struct secret *s = lsw_get_secret(c, SECRET_PSK, false);
	if (s == NULL) {
		dbg("no PreShared Key Found");
		return NULL;
	}

	const struct secret_preshared_stuff *psk = secret_preshared_stuff(s);
	if (DBGP(DBG_CRYPT)) {
		DBG_dump_hunk("PreShared Key", *psk);
	}
	return psk;
}

/*
 * Get connection PPK and store corresponding ppk_id in *ppk_id.
 */

const struct secret_ppk_stuff *get_connection_ppk_and_ppk_id(const struct connection *c)
{
	struct shunks *ppk_ids_shunks = c->config->ppk_ids_shunks;

	if (ppk_ids_shunks == NULL) {
		/*
		 * try to find any matching PPK, if found, save the corresponding
		 * PPK_ID in ppk_id
		 */
		ldbg(c->logger, "ppk-ids conn option not specified, look for first matching secret");
		struct secret *s = lsw_get_secret(c, SECRET_PPK, false);
		if (s == NULL) {
			return NULL;
		}

		const struct secret_ppk_stuff *ppk = secret_ppk_stuff(s);
		if (DBGP(DBG_CRYPT)) {
			DBG_log("found PPK");
			DBG_dump_hunk("PPK_ID:", ppk->id);
			DBG_dump_hunk("PPK:", ppk->key);
		}
		return ppk;
	} else {
		ldbg(c->logger,
		     "ppk-ids conn option specified, find any matching PPK_ID in list: %s",
		     c->config->ppk_ids);
		/*
		 * iterate through PPK_ID (ppk-ids=) list and try to find
		 * at least one secrets entry that matches a PPK_ID from the
		 * list.
		 */
		ITEMS_FOR_EACH(ppk_id_shunk, ppk_ids_shunks) {
			ldbg(c->logger, "try to find PPK with PPK_ID:");
			ldbg_hunk(c->logger, *ppk_id_shunk);

			const struct secret_ppk_stuff *ppk =
				secret_ppk_stuff_by_id(pluto_secrets, *ppk_id_shunk);
			if (ppk != NULL) {
				return ppk;
			}
		}
	}
	return NULL;
}

/*
 * Get connection PPK, in one of the two ways:
 * - With specified PPK_ID ppk_id (if ppk_id is not NULL).
 * or
 * - With a PPK_ID that is at place 'index' in the ppk-ids=
 * conn option list.
 */
const struct secret_ppk_stuff *get_connection_ppk(const struct connection *c,
						  shunk_t ppk_id,
						  unsigned int index)
{
	struct shunks *ppk_ids_shunks = c->config->ppk_ids_shunks;

	if (ppk_id.len > 0) {
		/* try to find PPK with PPK_ID ppk_id */
		ldbg(c->logger, "looking for PPK with ID:");
		ldbg_hunk(c->logger, ppk_id);
		return secret_ppk_stuff_by_id(pluto_secrets, ppk_id);
	} else {
		passert(index < ppk_ids_shunks->len);

		ldbg(c->logger, "looking for PPK with PPK ID in list %s at place: %u",
		     c->config->ppk_ids, index);

		shunk_t id = ppk_ids_shunks->item[index];

		ldbg(c->logger, "try to find PPK with PPK_ID:");
		ldbg_hunk(c->logger, id);

		const struct secret_ppk_stuff *ppk =
			secret_ppk_stuff_by_id(pluto_secrets, id);
		if (ppk != NULL) {
			return ppk;
		}
	}
	return NULL;
}

/*
 * Find the appropriate private key (see get_secret).  Failure is
 * indicated by a NULL pointer.
 */

struct secret_pubkey_stuff *get_local_private_key(const struct connection *c,
						  const struct pubkey_type *type,
						  struct logger *logger)
{
	/* is there a certificate assigned to this connection? */
	if (c->local->host.config->cert.nss_cert != NULL) {
		const char *nickname = cert_nickname(&c->local->host.config->cert);

		id_buf this_buf, that_buf;
		dbg("%s() using certificate %s to find private key for %s->%s of kind %s",
		    __func__, nickname,
		    str_id(&c->local->host.id, &this_buf),
		    str_id(&c->remote->host.id, &that_buf),
		    type->name);

		struct secret_pubkey_stuff *pks = NULL;
		bool load_needed;
		err_t err = find_or_load_private_key_by_cert(&pluto_secrets,
							     &c->local->host.config->cert,
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
			llog(LOG_STREAM/*not-whack-grrr*/, logger,
				    "reloaded private key matching %s certificate '%s'",
				    c->local->config->leftright, nickname);
		}

		/*
		 * If we don't find the right keytype (RSA, ECDSA,
		 * etc) then best will end up as NULL
		 */
		pexpect(pks->content.type == type);
		dbg("connection %s's %s private key found in NSS DB using cert",
		    c->name, type->name);
		return pks;
	}

	/* is there a CKAID assigned to this connection? */
	if (c->local->host.config->ckaid != NULL) {
		ckaid_buf ckb;
		id_buf this_buf, that_buf;
		dbg("%s() using CKAID %s to find private key for %s->%s of kind %s",
		    __func__, str_ckaid(c->local->host.config->ckaid, &ckb),
		    str_id(&c->local->host.id, &this_buf),
		    str_id(&c->remote->host.id, &that_buf),
		    type->name);

		struct secret_pubkey_stuff *pks;
		bool load_needed;
		err_t err = find_or_load_private_key_by_ckaid(&pluto_secrets, c->local->host.config->ckaid,
							      &pks, &load_needed, logger);
		if (err != NULL) {
			ckaid_buf ckb;
			llog(RC_LOG, logger,
				    "private key matching CKAID '%s' not found: %s",
				    str_ckaid(c->local->host.config->ckaid, &ckb), err);
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
			llog(LOG_STREAM/*not-whack-grr*/, logger,
				    "reloaded private key matching %s CKAID %s",
				    c->local->config->leftright, str_ckaid(c->local->host.config->ckaid, &ckb));
		}


		/*
		 * If we don't find the right keytype (RSA, ECDSA,
		 * etc) then best will end up as NULL
		 */
		pexpect(pks->content.type == type);
		dbg("connection %s's %s private key found in NSS DB using CKAID",
		    c->name, type->name);
		return pks;
	}

	dbg("looking for connection %s's %s private key",
	    c->name, type->name);
	struct secret *s = lsw_get_secret(c, type->private_key_kind, true);
	if (s == NULL) {
		llog(RC_LOG, logger, "connection's %s private key not found",
		     type->name);
		return NULL;
	}

	struct secret_pubkey_stuff *pks = secret_pubkey_stuff(s);
	passert(pks != NULL);

	pexpect(pks->content.type == type);
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

/*
 * checks if the expiration date has been reached and warns during the
 * warning_interval of the imminent expiry.
 *
 * warning interval is in days.
 *
 * strict == TRUE: expiry yields an error message
 * strict == FALSE: expiry yields a warning message
 */

typedef struct {
	/* note: 20 is a guess at the maximum digits in an intmax_t */
	char buf[sizeof("warning (expires in %jd minutes)") + 20];
} expiry_buf;

static const char *check_expiry(realtime_t expiration_date, time_t warning_interval, expiry_buf *eb)
{
	if (is_realtime_epoch(expiration_date))
		return "ok (expires never)";

	time_t time_left = deltasecs(realtime_diff(expiration_date, realnow()));

	if (time_left < 0)
		return "fatal (expired)";

	if (time_left > warning_interval)
		return NULL;

	const char *unit;
	if (time_left > 2 * secs_per_day) {
		time_left /= secs_per_day;
		unit = "day";
	} else if (time_left > 2 * secs_per_hour) {
		time_left /= secs_per_hour;
		unit = "hour";
	} else if (time_left > 2 * secs_per_minute) {
		time_left /= secs_per_minute;
		unit = "minute";
	} else {
		unit = "second";
	}

	snprintf(eb->buf, sizeof(eb->buf), "warning (expires in %jd %s%s)",
		 (intmax_t) time_left, unit,
		 (time_left == 1) ? "" : "s");
	return eb->buf;
}

static void show_pubkey(struct show *s, struct pubkey *pubkey, bool utc, const char *expiry_message)
{
	bool load_needed;
	err_t load_err = preload_private_key_by_ckaid(&pubkey->content.ckaid,
						      &load_needed,
						      show_logger(s));
	SHOW_JAMBUF(s, buf) {
		jam_realtime(buf, pubkey->installed_time, utc);
		jam(buf, ",");
		jam(buf, " %4zd", pubkey_strength_in_bits(pubkey));
		jam(buf, " %s", pubkey->content.type->name);
		jam(buf, " Key %s", str_keyid(pubkey->content.keyid));
		jam(buf, " (%s private key),",
		    (load_err != NULL ? "no" :
		     load_needed ? "loaded" : "has"));
		jam(buf, " until ");
		jam_realtime(buf, pubkey->until_time, utc);
		jam(buf, " %s", expiry_message == NULL ? "ok" : expiry_message);
	}

	id_buf idb;
	name_buf b;
	show(s, "       %s '%s'",
		     str_enum_short(&ike_id_type_names, pubkey->id.kind, &b),
		     str_id(&pubkey->id, &idb));

	if (pubkey->issuer.len > 0) {
		dn_buf b;
		show(s, "       Issuer '%s'",
			     str_dn(pubkey->issuer, &b));
	}
}

void show_pubkeys(struct show *s, bool utc, enum keys_to_show keys_to_show)
{
	if (keys_to_show == SHOW_ALL_KEYS) {
		show_blank(s);
		show(s, "List of Public Keys:");
		show_blank(s);
	}

	for (struct pubkey_list *p = pluto_pubkeys; p != NULL; p = p->next) {
		struct pubkey *pubkey = p->key;
		expiry_buf eb;
		const char *expiry_msg = check_expiry(pubkey->until_time, PUBKEY_WARNING_INTERVAL, &eb);
		switch (keys_to_show) {
		case SHOW_ALL_KEYS:
			show_pubkey(s, pubkey, utc, expiry_msg);
			break;
		case SHOW_EXPIRED_KEYS:
			if (expiry_msg != NULL) {
				show_pubkey(s, pubkey, utc, expiry_msg);
			}
			break;
		}
	}
}

err_t preload_private_key_by_cert(const struct cert *cert, bool *load_needed, struct logger *logger)
{
	threadtime_t start = threadtime_start();
	struct secret_pubkey_stuff *pks;
	err_t err = find_or_load_private_key_by_cert(&pluto_secrets, cert,
						     &pks, load_needed, logger);
	threadtime_stop(&start, SOS_NOBODY, "%s() loading private key %s", __func__,
			cert->nss_cert->nickname);
	return err;
}

err_t preload_private_key_by_ckaid(const ckaid_t *ckaid, bool *load_needed, struct logger *logger)
{
	threadtime_t start = threadtime_start();
	struct secret_pubkey_stuff *pks;
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
