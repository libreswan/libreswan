/*
 * NSS boilerplate stuff, for libreswan.
 *
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
 */

#include <nspr.h>
#include <nss.h>
#include <pk11pub.h>
#include <keyhi.h>

#include "lswconf.h"
#include "lswnss.h"
#include "lswalloc.h"
#include "lswlog.h"

bool lsw_nss_setup(const char *configdir, unsigned flags,
		   PK11PasswordFunc get_nss_password, lsw_nss_buf_t err)
{
	/*
	 * According to the manual, not needed, and all parameters are
	 * ignored.  Does no harm?
	 */
	PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 1);

	if (configdir) {
		const char sql[] = "sql:";
		char *nssdb;
		if (strncmp(sql, configdir, strlen(sql)) == 0) {
			nssdb = strdup(configdir);
		} else {
			nssdb = alloc_bytes(strlen(configdir) + strlen(sql) + 1, "nssdb");
			strcpy(nssdb, sql);
			strcat(nssdb, configdir);
		}
		SECStatus rv = NSS_Initialize(nssdb, "", "", SECMOD_DB,
					      (flags & LSW_NSS_READONLY) ? NSS_INIT_READONLY : 0);
		if (rv != SECSuccess) {
			snprintf(err, sizeof(lsw_nss_buf_t),
				 "%s initialization of NSS database '%s' failed (%d)\n",
				 (flags & LSW_NSS_READONLY) ? "read-only" : "read-write",
				 nssdb, PR_GetError());
			pfree(nssdb);
			return FALSE;
		}
	} else {
		NSS_NoDB_Init(".");
	}

	if (get_nss_password) {
		PK11_SetPasswordFunc(get_nss_password);
	}

	return TRUE;
}

void lsw_nss_shutdown(unsigned flags)
{
	NSS_Shutdown();
	if (flags & LSW_NSS_CLEANUP) {
		PR_Cleanup();
	}
#if 0
	if (NSSPassword) {
		pfree(NSSPassword->data);
		pfree(NSSPassword);
	}
	NSSPassword = NULL;
#endif
}

static void fill_RSA_public_key(struct RSA_public_key *rsa, SECKEYPublicKey *pubkey)
{
	passert(SECKEY_GetPublicKeyType(pubkey) == rsaKey);
	rsa->e = clone_secitem_as_chunk(pubkey->u.rsa.publicExponent, "e");
	rsa->n = clone_secitem_as_chunk(pubkey->u.rsa.modulus, "n");
	form_keyid(rsa->e, rsa->n, rsa->keyid, &rsa->k);
}

struct private_key_stuff *lsw_nss_foreach_private_key_stuff(secret_eval func,
							    void *uservoid,
							    lsw_nss_buf_t err)
{
	/*
	 * So test for error with "if (err[0]) ..." works.
	 */
	err[0] = '\0';

	PK11SlotInfo *slot = PK11_GetInternalKeySlot();
	if (slot == NULL) {
		snprintf(err, sizeof(lsw_nss_buf_t), "no slot");
		return NULL;
	}

	SECKEYPrivateKeyList *list = PK11_ListPrivateKeysInSlot(slot);
	if (list == NULL) {
		snprintf(err, sizeof(lsw_nss_buf_t), "no list");
		PK11_FreeSlot(slot);
		return NULL;
	}

	int line = 1;

	struct private_key_stuff *result = NULL;

	SECKEYPrivateKeyListNode *node;
	for (node = PRIVKEY_LIST_HEAD(list);
             !PRIVKEY_LIST_END(node, list);
	     node = PRIVKEY_LIST_NEXT(node)) {

		if (SECKEY_GetPrivateKeyType(node->key) != rsaKey) {
			/* only rsa for now */
			continue;
		}

		struct private_key_stuff pks = {
			.kind = PPK_RSA,
			.on_heap = TRUE,
		};

		{
			SECItem *nss_ckaid
				= PK11_GetLowLevelKeyIDForPrivateKey(node->key);
			if (nss_ckaid == NULL) {
				// fprintf(stderr, "ckaid not found\n");
				continue;
			}
			const char *err = form_ckaid_nss(nss_ckaid,
							 &pks.u.RSA_private_key.pub.ckaid);
			SECITEM_FreeItem(nss_ckaid, PR_TRUE);
			if (err) {
				// fprintf(stderr, "ckaid not found\n");
				continue;
			}
		}

		{
			SECKEYPublicKey *pubkey = SECKEY_ConvertToPublicKey(node->key);
			if (pubkey != NULL) {
				fill_RSA_public_key(&pks.u.RSA_private_key.pub, pubkey);
				SECKEY_DestroyPublicKey(pubkey);
			}
		}

		/*
		 * Only count private keys that get processed.
		 */
		pks.line = line++;

		int ret = func(NULL, &pks, uservoid);
		if (ret == 0) {
			/*
			 * save/return the result.
			 *
			 * XXX: Potential Memory leak.
			 *
			 * lsw_foreach_secret() + lsw_get_pks()
			 * returns an object that must not be freed
			 * BUT lsw_nss_foreach_private_key_stuff()
			 * returns an object that must be freed.
			 *
			 * For moment ignore this - as only caller is
			 * showhostkey.c which quickly exits.
			 */
			result = clone_thing(pks, "pks");
			break;
		}

		freeanyckaid(&pks.u.RSA_private_key.pub.ckaid);
		freeanychunk(pks.u.RSA_private_key.pub.e);
		freeanychunk(pks.u.RSA_private_key.pub.n);

		if (ret < 0) {
			break;
		}
	}

	SECKEY_DestroyPrivateKeyList(list);
	PK11_FreeSlot(slot);

	return result;
}
