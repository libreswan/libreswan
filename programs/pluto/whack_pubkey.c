/* ipsec whack --addkey et.al., for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001,2013-2016 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2011 Mika Ilmaranta <ilmis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2014-2020 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2014-2017 Antony Antony <antony@phenome.org>
 * Copyright (C) 2019-2025 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2020 Nupur Agrawal <nupur202000@gmail.com>
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

#include "whack_pubkey.h"

#include "show.h"
#include "log.h"
#include "whack.h"
#include "secrets.h"
#include "keys.h"
#include "ttodata.h"

err_t whack_pubkey_to_chunk(enum ipseckey_algorithm_type pubkey_alg,
			    const char *pubkey_in, chunk_t *pubkey_out)
{
	unsigned base = (pubkey_alg == IPSECKEY_ALGORITHM_X_PUBKEY ? 64 /*dam-it*/ :
			 0/*figure-it-out*/);
	return ttochunk(shunk1(pubkey_in), base, pubkey_out);
}

/*
 * Handle: whack --keyid <id> [--addkey] [--pubkeyrsa <key>]\n"
 *
 *                                               key  addkey pubkey
 * whack --keyid <id>                             y      n      n
 *     delete <id> key
 * whack --keyid <id> --pubkeyrsa ...             y      n      y
 *     replace <id> key
 * whack --keyid <id> --addkey --pubkeyrsa ...    y      y      y
 *     add <id> key (keeping any old key)
 * whack --keyid <id> --addkey
 *     invalid as public key is missing (keyval.len is 0)
 */

void whack_pubkey(const struct whack_pubkey *wm_pubkey,
		  struct show *s)
{
	struct logger *logger = show_logger(s);
	err_t err;

	name_buf pkb;
	ldbg(logger, "processing key addkey=%s keyid=%s pubkey_alg=%s(%d) pubkey=%s",
	     bool_str(wm_pubkey->add),
	     (wm_pubkey->id == NULL ? "" : wm_pubkey->id),
	     str_enum_long(&ipseckey_algorithm_config_names, wm_pubkey->alg, &pkb),
	     wm_pubkey->alg,
	     (wm_pubkey->key == NULL ? "" : wm_pubkey->key));

	if (wm_pubkey->id == NULL) {
		/* must be a keyid */
		llog_pexpect(logger, HERE, "missing keyid");
		return;
	}

	if (wm_pubkey->add && wm_pubkey->key == NULL) {
		/* add requires pubkey */
		llog_pexpect(logger, HERE, "addkey missing pubkey");
		return;
	}

	/*
	 * Figure out the key type.
	 */

	const struct pubkey_type *type = pubkey_type_from_ipseckey_algorithm(wm_pubkey->alg);
	struct id keyid; /* must free_id_content() */
	diag_t d = ttoid(wm_pubkey->id, &keyid);
	if (d != NULL) {
		llog_rc(RC_BADID, logger, "bad --keyid \"%s\": %s",
			wm_pubkey->id, str_diag(d));
		pfree_diag(&d);
		return;
	}

	/*
	 * Delete old key.
	 *
	 * No --addkey with a key means replace (see below).
	 *
	 * No --addkey just means that is no existing key to delete.
	 * For instance !add with a key means replace.
	 */
	if (wm_pubkey->key == NULL) {
		/*
		 * XXX: this gets called by "add" so be
		 * silent.
		 */
		llog(LOG_STREAM/*not-whack*/, logger,
		     "delete keyid %s", wm_pubkey->id);
		delete_public_keys(&pluto_pubkeys, &keyid, type);
		free_id_content(&keyid);
		/*
		 * XXX: what about private keys; suspect not easy as
		 * not 1:1?
		 */
		return;
	}

	/*
	 * Replace old key with new.
	 *
	 * No --addkey with a key means replace.
	 */

	chunk_t raw_pubkey = NULL_HUNK;
	err = whack_pubkey_to_chunk(wm_pubkey->alg, wm_pubkey->key, &raw_pubkey);
	if (err != NULL) {
		name_buf pkb;
		llog(ERROR_STREAM, logger, "malformed %s pubkey %s: %s",
		     str_enum_long(&ipseckey_algorithm_config_names, wm_pubkey->alg, &pkb),
		     wm_pubkey->key,
		     err);
		free_id_content(&keyid);
		return;
	}

	/*
	 * A key was given: add it.
	 *
	 * XXX: this gets called by "add" so be silent.
	 */
	llog(LOG_STREAM/*not-whack*/, logger,
	     "%s keyid %s", (wm_pubkey->add ? "add" : "replace"),
	     wm_pubkey->id);
	ldbg(logger, "pubkey: %s", wm_pubkey->key);

	/* add the public key */
	struct pubkey *pubkey = NULL; /* must-delref */
	d = unpack_dns_pubkey(&keyid, PUBKEY_LOCAL, wm_pubkey->alg,
			      /*install_time*/realnow(),
			      /*until_time*/realtime_epoch,
			      /*ttl*/0,
			      HUNK_AS_SHUNK(&raw_pubkey),
			      &pubkey/*new-public-key:must-delref*/,
			      logger);
	if (d != NULL) {
		llog(RC_LOG, logger, "%s", str_diag(d));
		pfree_diag(&d);
		free_chunk_content(&raw_pubkey);
		free_id_content(&keyid);
		return;
	}

	/*
	 * XXX: why would there be multiple pubkeys with the same ID?
	 * Perhaps when they have different CKAIDs or expiration
	 * dates?
	 */
	if (wm_pubkey->add) {
		add_pubkey(pubkey, &pluto_pubkeys);
	} else {
		replace_pubkey(pubkey, &pluto_pubkeys);
	}

	/* try to pre-load the private key */
	bool load_needed;
	const ckaid_t *ckaid = pubkey_ckaid(pubkey);
	pubkey_delref(&pubkey);
	err = preload_private_key_by_ckaid(ckaid, &load_needed, logger);
	if (err != NULL) {
		ldbg(logger, "no private key: %s", err);
	} else if (load_needed) {
		ckaid_buf ckb;
		llog(LOG_STREAM/*not-whack-for-now*/, logger,
		     "loaded private key matching CKAID %s",
		     str_ckaid(ckaid, &ckb));
	}

	free_chunk_content(&raw_pubkey);
	free_id_content(&keyid);
}
