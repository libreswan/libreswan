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
	int base;
	switch (pubkey_alg) {
	case IPSECKEY_ALGORITHM_RSA:
	case IPSECKEY_ALGORITHM_ECDSA:
		base = 0; /* figure it out */
		break;
	case IPSECKEY_ALGORITHM_X_PUBKEY:
		base = 64; /* dam it */
		break;
	default:
		bad_case(pubkey_alg);
	}

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

void key_add_request(const struct whack_message *wm, struct logger *logger)
{
	err_t err;

	enum_buf pkb;
	ldbg(logger, "processing key=%s addkey=%s keyid=%s pubkey_alg=%s(%d) pubkey=%s",
	     bool_str(wm->whack_key),
	     bool_str(wm->whack_addkey),
	     (wm->keyid == NULL ? "" : wm->keyid),
	     str_enum(&ipseckey_algorithm_config_names, wm->pubkey_alg, &pkb),
	     wm->pubkey_alg,
	     (wm->pubkey == NULL ? "" : wm->pubkey));

	if (wm->keyid == NULL) {
		/* must be a keyid */
		llog_pexpect(logger, HERE, "missing keyid");
		return;
	}

	if (wm->whack_addkey && wm->pubkey == NULL) {
		/* add requires pubkey */
		llog_pexpect(logger, HERE, "addkey missing pubkey");
		return;
	}

	/*
	 * Figure out the key type.
	 */

	const struct pubkey_type *type = pubkey_alg_type(wm->pubkey_alg);
	struct id keyid; /* must free_id_content() */
	err = atoid(wm->keyid, &keyid);
	if (err != NULL) {
		llog(RC_BADID, logger, "bad --keyid \"%s\": %s", wm->keyid, err);
		return;
	}

	/*
	 * Delete any old key.
	 *
	 * No --addkey with a key means replace.
	 *
	 * No --addkey just means that is no existing key to delete.
	 * For instance !add with a key means replace.
	 */
	if (!wm->whack_addkey) {
		if (wm->pubkey == NULL) {
			/*
			 * XXX: this gets called by "add" so be
			 * silent.
			 */
			llog(LOG_STREAM/*not-whack*/, logger,
			     "delete keyid %s", wm->keyid);
		}
		delete_public_keys(&pluto_pubkeys, &keyid, type);
		/*
		 * XXX: what about private keys; suspect not easy as
		 * not 1:1?
		 */
	}

	/*
	 * Add the new key.
	 *
	 * No --addkey with a key means replace.
	 */
 	if (wm->pubkey != NULL) {

		chunk_t rawkey = NULL_HUNK;
		err = whack_pubkey_to_chunk(wm->pubkey_alg, wm->pubkey, &rawkey);
		if (err != NULL) {
			enum_buf pkb;
			llog_error(logger, 0, "malformed %s pubkey %s: %s",
				   str_enum(&ipseckey_algorithm_config_names, wm->pubkey_alg, &pkb),
				   wm->pubkey,
				   err);
			free_id_content(&keyid);
			return;
		}

		/*
		 * A key was given: add it.
		 *
		 * XXX: this gets called by "add" so be silent.
		 */
		llog(LOG_STREAM/*not-whack*/, logger, "add keyid %s", wm->keyid);
		ldbg(logger, "pubkey: %s", wm->pubkey);

		/* add the public key */
		struct pubkey *pubkey = NULL; /* must-delref */
		diag_t d = unpack_dns_pubkey(&keyid, PUBKEY_LOCAL, wm->pubkey_alg,
					     /*install_time*/realnow(),
					     /*until_time*/realtime_epoch,
					     /*ttl*/0,
					     HUNK_AS_SHUNK(rawkey),
					     &pubkey/*new-public-key:must-delref*/,
					     logger);
		if (d != NULL) {
			llog(RC_LOG, logger, "%s", str_diag(d));
			pfree_diag(&d);
			free_chunk_content(&rawkey);
			free_id_content(&keyid);
			return;
		}

		/* possibly deleted above */
		add_pubkey(pubkey, &pluto_pubkeys);

		/* try to pre-load the private key */
		bool load_needed;
		const ckaid_t *ckaid = pubkey_ckaid(pubkey);
		pubkey_delref(&pubkey);
		err = preload_private_key_by_ckaid(ckaid, &load_needed, logger);
		if (err != NULL) {
			dbg("no private key: %s", err);
		} else if (load_needed) {
			ckaid_buf ckb;
			llog(LOG_STREAM/*not-whack-for-now*/, logger,
			     "loaded private key matching CKAID %s",
			     str_ckaid(ckaid, &ckb));
		}

		free_chunk_content(&rawkey);
	}
	free_id_content(&keyid);
}
