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

#if 0
#define MAX_CKA_ID_STR_LEN 40

void for_all_nss_keys(void)
{
	PK11SlotInfo *slot = PK11_GetInternalKeySlot();
	if (slot == NULL) {
		fprintf(stderr, "no slot\n");
		return;
	}

	SECKEYPrivateKeyList *list = PK11_ListPrivateKeysInSlot(slot);
	if (list == NULL) {
		fprintf(stderr, "no list\n");
		PK11_FreeSlot(slot);
		return;
	}

	SECKEYPrivateKeyListNode *node;
	for (node = PRIVKEY_LIST_HEAD(list);
             !PRIVKEY_LIST_END(node, list);
	     node = PRIVKEY_LIST_NEXT(node)) {
		SECKEYPrivateKey *key = node->key;
		fprintf(stderr, "nickname %s\n", PK11_GetPrivateKeyNickname(key));
		SECItem *ckaid = PK11_GetLowLevelKeyIDForPrivateKey(key);
		if (ckaid == NULL) {
			fprintf(stderr, "no ckaid\n");
		} else {
			char ckaIDbuf[MAX_CKA_ID_STR_LEN + 4];
			datatot(ckaid->data, ckaid->len, 16, ckaIDbuf, sizeof(ckaIDbuf));
			fprintf(stderr, "ckaid: %s\n", ckaIDbuf);
			SECITEM_FreeItem(ckaid, PR_TRUE);

		}
	}

	SECKEY_DestroyPrivateKeyList(list);
	PK11_FreeSlot(slot);
}
#endif
