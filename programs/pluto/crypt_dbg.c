/*
 * SYMKEY debug functions, for libreswan
 *
 * Copyright (C) 2015, 2016 Andrew Cagney <cagney@gnu.org>
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

#include "libreswan.h"
#include "lswalloc.h"
#include "lswlog.h"
#include "ike_alg.h"
#include "crypt_dbg.h"
#include "crypt_symkey.h"

#include "crypto.h"
#include "lswnss.h"
#include "lswfips.h"

static PK11SymKey *ephemeral_symkey(int debug)
{
	static int tried;
	static PK11SymKey *ephemeral_key;
	if (!tried) {
		tried = 1;
		/* get a secret key */
		PK11SlotInfo *slot = PK11_GetBestSlot(CKM_AES_KEY_GEN,
						      lsw_return_nss_password_file_info());
		if (slot == NULL) {
			loglog(RC_LOG_SERIOUS, "NSS: ephemeral slot error");
			return NULL;
		}
		ephemeral_key = PK11_KeyGen(slot, CKM_AES_KEY_GEN,
					    NULL, 128/8, NULL);
		PK11_FreeSlot(slot); /* reference counted */
	}
	DBG(debug, DBG_symkey("ephemeral_key", ephemeral_key));
	return ephemeral_key;
}

/*
 * For testing/debugging, return a symkey.
 */
PK11SymKey *chunk_to_symkey(chunk_t raw_key)
{
	PK11SymKey *ephemeral_key = ephemeral_symkey(DBG_CRYPT);
	return symkey_from_chunk(ephemeral_key, raw_key);
}

void DBG_dump_symkey(const char *prefix, PK11SymKey *key)
{
	DBG_symkey(prefix, key);
	if (key != NULL) {
		if (DBGP(DBG_PRIVATE)) {
#ifdef FIPS_CHECK
			if (libreswan_fipsmode()) {
				DBG_log("%s secured by FIPS", prefix);
				return;
			}
#else
			void *bytes = symkey_bytes(prefix, key, 0);
			/* NULL suppresses the dump header */
			DBG_dump(NULL, bytes, sizeof_symkey(key));
			pfreeany(bytes);
#endif
		}
	}
}
