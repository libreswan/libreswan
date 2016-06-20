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

static unsigned flags;

bool lsw_nss_setup(const char *configdir, unsigned setup_flags,
		   PK11PasswordFunc get_password, lsw_nss_buf_t err)
{
	/*
	 * save for cleanup
	 */
	flags = setup_flags;

	/*
	 * According to the manual, not needed, and all parameters are
	 * ignored.  Does no harm?
	 */
	PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 1);

	libreswan_log("Initializing NSS");
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
		libreswan_log("Opening NSS database \"%s\" %s", nssdb,
			      (flags & LSW_NSS_READONLY) ? "read-only" : "read-write");
		SECStatus rv = NSS_Initialize(nssdb, "", "", SECMOD_DB,
					      (flags & LSW_NSS_READONLY) ? NSS_INIT_READONLY : 0);
		if (rv != SECSuccess) {
			snprintf(err, sizeof(lsw_nss_buf_t),
				 "Initialization of NSS with %s database \"%s\" failed (%d)",
				 (flags & LSW_NSS_READONLY) ? "read-only" : "read-write",
				 nssdb, PR_GetError());
			pfree(nssdb);
			return FALSE;
		}
	} else {
		NSS_NoDB_Init(".");
	}

	if (PK11_IsFIPS() && get_password == NULL) {
		snprintf(err, sizeof(lsw_nss_buf_t),
			 "on FIPS mode a password is required");
		return FALSE;
	}

	if (get_password) {
		PK11_SetPasswordFunc(get_password);
	}

	if (!(flags & LSW_NSS_SKIP_AUTH)) {
		PK11SlotInfo *slot = lsw_nss_get_authenticated_slot(err);
		if (slot == NULL) {
			return FALSE;
		}
		PK11_FreeSlot(slot);
	}

	return TRUE;
}

void lsw_nss_shutdown(void)
{
	NSS_Shutdown();
	if (!(flags & LSW_NSS_SKIP_PR_CLEANUP)) {
		PR_Cleanup();
	}
}

static void fill_RSA_public_key(struct RSA_public_key *rsa, SECKEYPublicKey *pubkey)
{
	passert(SECKEY_GetPublicKeyType(pubkey) == rsaKey);
	rsa->e = clone_secitem_as_chunk(pubkey->u.rsa.publicExponent, "e");
	rsa->n = clone_secitem_as_chunk(pubkey->u.rsa.modulus, "n");
	form_keyid(rsa->e, rsa->n, rsa->keyid, &rsa->k);
}

PK11SlotInfo *lsw_nss_get_authenticated_slot(lsw_nss_buf_t err)
{
	PK11SlotInfo *slot = PK11_GetInternalKeySlot();
	if (slot == NULL) {
		snprintf(err, sizeof(lsw_nss_buf_t), "no internal key slot");
		return NULL;
	}

	if (PK11_IsFIPS() || PK11_NeedLogin(slot)) {
		SECStatus status = PK11_Authenticate(slot, PR_FALSE,
						     lsw_return_nss_password_file_info());
		if (status != SECSuccess) {
			const char *token = PK11_GetTokenName(slot);
			snprintf(err, sizeof(lsw_nss_buf_t), "authentication of \"%s\" failed", token);
			PK11_FreeSlot(slot);
			return NULL;
		}
	}
	return slot;
}

struct private_key_stuff *lsw_nss_foreach_private_key_stuff(secret_eval func,
							    void *uservoid,
							    lsw_nss_buf_t err)
{
	/*
	 * So test for error with "if (err[0]) ..." works.
	 */
	err[0] = '\0';

	PK11SlotInfo *slot = lsw_nss_get_authenticated_slot(err);
	if (slot == NULL) {
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

char *lsw_nss_get_password(PK11SlotInfo *slot, PRBool retry, void *arg UNUSED)
{
	if (retry) {
		/* nothing changed */
		return NULL;
	}

	if (slot == NULL) {
		/* nothing to secure */
		return NULL;
	}

	/*
	 * Get a name.
	 *
	 * TOKEN tied to slot so does not need to be freed.
	 */
	const char *token = PK11_GetTokenName(slot);
	if (token == NULL) {
		libreswan_log("NSS Password slot has no token name");
		return NULL;
	}

	if (PK11_ProtectedAuthenticationPath(slot)) {
		libreswan_log("NSS Password for token \"%s\" failed, slot has protected authentication path",
			      token);
		return NULL;
	}

	const struct lsw_conf_options *oco = lsw_init_options();

	/*
	 * Easy case, passsword specified on the command line.
	 */
	if (oco->nsspassword != NULL) {
		char *password = PORT_Strdup(oco->nsspassword);
		libreswan_log("NSS Password for token \"%s\" with length %zu passed to NSS",
			      token, strlen(password));
		return password;
	}
	/*
	 * Hard case, password in a file.  Look for TOKEN:password.
	 *
	 * Do not free the TOKEN.
	 */
	const int max_password_file_size = 4096;
	char *passwords = PORT_ZAlloc(max_password_file_size);
	if (passwords == NULL) {
		libreswan_log("NSS Password file \"%s\" for token \"%s\" could not be loaded, NSS memory allocate failed",
			      oco->nsspassword_file, token);
		return NULL;
	}

	/*
	 * From here on, every return must be preceded by
	 * PORT_Free(passwords).
	 */
	size_t passwords_len;
	{
		PRFileDesc *fd = PR_Open(oco->nsspassword_file, PR_RDONLY, 0);
		if (fd == NULL) {
			libreswan_log("NSS Password file \"%s\" for token \"%s\" could not be opened for reading",
				      oco->nsspassword_file, token);
			PORT_Free(passwords);
			return NULL;
		}
		passwords_len = PR_Read(fd, passwords, max_password_file_size);
		PR_Close(fd);
	}

	size_t i;
	for (i = 0; i < passwords_len; ) {
		/*
		 * examine a line of the password file
		 * token_name:password
		 */
		int start = i;
		char *p;

		/* find end of line */
		while (i < passwords_len &&
		       (passwords[i] != '\0' &&
			passwords[i] != '\r' &&
			passwords[i] != '\n'))
			i++;

		if (i == passwords_len) {
			libreswan_log("NSS Password file \"%s\" for token \"%s\" ends with a partial line (ignored)",
				      oco->nsspassword_file, token);
			break;	/* no match found */
		}

		size_t linelen = i - start;

		/* turn delimiter into NUL and skip over it */
		passwords[i++] = '\0';

		p = &passwords[start];

		size_t toklen = PORT_Strlen(token);
		if (linelen >= toklen + 1 &&
		    PORT_Strncmp(p, token, toklen) == 0 &&
		    p[toklen] == ':') {
			/* we have a winner! */
			p = PORT_Strdup(&p[toklen + 1]);
			libreswan_log("NSS Password from file \"%s\" for token \"%s\" with length %zu passed to NSS",
				      oco->nsspassword_file, token, PORT_Strlen(p));
			PORT_Free(passwords);
			return p;
		}
	}

	/* no match found in password file */
	libreswan_log("NSS Password file \"%s\" does not contain token \"%s\"",
		      oco->nsspassword_file, token);
	PORT_Free(passwords);
	return NULL;
}
