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
}

struct private_key_stuff *lsw_nss_foreach_private_key_stuff(secret_eval func,
							    void *uservoid,
							    lsw_nss_buf_t err)
{
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

	struct private_key_stuff *result = NULL;

	SECKEYPrivateKeyListNode *node;
	for (node = PRIVKEY_LIST_HEAD(list);
             !PRIVKEY_LIST_END(node, list);
	     node = PRIVKEY_LIST_NEXT(node)) {

		struct private_key_stuff pks = {
			.kind = PPK_RSA,
		};

		{
			SECItem *nss_ckaid
				= PK11_GetLowLevelKeyIDForPrivateKey(node->key);
			if (nss_ckaid == NULL) {
				fprintf(stderr, "ckaid not found\n");
				continue;
			}
			const char *err = form_ckaid_nss(nss_ckaid,
							 &pks.u.RSA_private_key.pub.ckaid);
			SECITEM_FreeItem(nss_ckaid, PR_TRUE);
			if (err) {
				fprintf(stderr, "ckaid not found\n");
				continue;
			}
		}

#if 0
		{
			CERTCertificate *cert
				= PK11_GetCertFromPrivateKey(node->key);
			if (cert == NULL) {
				fprintf(stderr, "cert not found\n");
				continue;
			}
			SECKEYPublicKey *pubkey = CERT_ExtractPublicKey(cert);
			if (pubkey == NULL) {
				fprintf(stderr, "pubkey not found\n");
				CERT_DestroyCertificate(cert);
				continue;
			}
			if (SECKEY_GetPublicKeyType(pubkey) != rsaKey) {
				SECKEY_DestroyPublicKey(pubkey);
				CERT_DestroyCertificate(cert);
			}
			pks.u.RSA_private_key.pub.e = clone_secitem_as_chunk(pubkey->u.rsa.publicExponent, "e");
			pks.u.RSA_private_key.pub.n = clone_secitem_as_chunk(pubkey->u.rsa.modulus, "n");
			form_keyid(pks.u.RSA_private_key.pub.e,
				   pks.u.RSA_private_key.pub.n,
				   pks.u.RSA_private_key.pub.keyid,
				   &pks.u.RSA_private_key.pub.k);
			SECKEY_DestroyPublicKey(pubkey);
			CERT_DestroyCertificate(cert);
		}
#endif

		int ret = func(NULL, &pks, uservoid);
		if (ret == 0) {
			result = clone_thing(pks, "pks");
			break;
		}

		freeanyckaid(&pks.u.RSA_private_key.pub.ckaid);
		freeanychunk(pks.u.RSA_private_key.pub.e);
		freeanychunk(pks.u.RSA_private_key.pub.n);
	}

	SECKEY_DestroyPrivateKeyList(list);
	PK11_FreeSlot(slot);

	return result;
}
