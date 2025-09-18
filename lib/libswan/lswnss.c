/*
 * NSS boilerplate stuff, for libreswan.
 *
 * Copyright (C) 2016, Andrew Cagney <cagney@gnu.org>
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
 */

#include <nspr.h>
#include <pk11pub.h>
#include <secmod.h>
#include <keyhi.h>
#include <nss.h>	/* for NSS_Initialize() */

#include "ipsecconf/config_setup.h"
#include "lswnss.h"
#include "lswalloc.h"
#include "lswlog.h"
#include "fips_mode.h"

static char *get_nss_password(PK11SlotInfo *slot, PRBool retry, void *arg);
static char *get_nss_file_password(const char *token, const char *password_file, struct logger *logger);

static struct nss_flags shutdown_flags;
static const char *nss_password;

static diag_t setup(const char *configdir, struct nss_flags flags, struct logger *logger)
{
	/*
	 * Turn (possibly NULL) CONFIGDIR into (possibly NULL) nssdir
	 * so it can be used in error messages.
	 */
#define SQL "sql:"
	char *nssdir;
	if (configdir == NULL) {
		nssdir = NULL;
	} else if (startswith(configdir, SQL)) {
		nssdir = clone_str(configdir, "nssdir");
	} else {
		nssdir = alloc_printf(SQL"%s", configdir);
	}

	/*
	 * Always log what is about to happen.
	 */
	if (nssdir == NULL) {
		llog(RC_LOG, logger, "Initializing NSS");
	} else {
		llog(RC_LOG, logger, "Initializing NSS using %s database \"%s\"",
		     (flags.open_readonly ? "read-only" : "read-write"),
		     nssdir);
	}

	/*
	 * save for cleanup
	 */
	shutdown_flags = flags;

	/*
	 * According to the manual, not needed, and all parameters are
	 * ignored.  Does no harm?
	 */
	PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 1);

	/*
	 * Initialize NSS, possibly flipping it to the correct mode.
	 */
	enum fips_mode fips_mode;
	if (nssdir != NULL) {
		SECStatus rv = NSS_Initialize(nssdir, "", "", SECMOD_DB,
					      (flags.open_readonly ? NSS_INIT_READONLY : 0));
		if (rv != SECSuccess) {
			/* NSS: <message...>: <error-string> (SECERR: N) */
			diag_t d = diag_nss_error("initialization using %s database \"%s\" failed",
						  (flags.open_readonly ? "read-only" : "read-write"),
						  nssdir);
			pfree(nssdir);
			return d;
		}
		fips_mode = get_fips_mode(logger);
	} else {
		NSS_NoDB_Init(".");
		fips_mode = get_fips_mode(logger);
		if (fips_mode == FIPS_MODE_ON && !PK11_IsFIPS()) {
			/*
			 * Happens when set_fips_mode(FIPS_MODE_ON) is
			 * called before calling this function.  For
			 * instance, in algparse.  Need to flip NSS's
			 * mode so that it matches.
			 */
			SECMODModule *internal = SECMOD_GetInternalModule();
			if (internal == NULL) {
				return diag_nss_error("SECMOD_GetInternalModule() failed");
			}
			if (SECMOD_DeleteInternalModule(internal->commonName) != SECSuccess) {
				return diag_nss_error("SECMOD_DeleteInternalModule(%s) failed",
						      internal->commonName);
			}
			if (!PK11_IsFIPS()) {
				return diag("NSS: toggling to FIPS mode failed");
			}
		}
	}

	if (fips_mode == FIPS_MODE_UNSET) {
		pfreeany(nssdir);
		return diag("NSS: FIPS mode could not be determined");
	}

	/*
	 * The wrapper lsw_nss_get_password_context(LOGGER) must be
	 * passed as the the final argument to any NSS call that might
	 * call lsw_nss_get_password().  NSS will then pass the
	 * context along.
	 *
	 * It is currently the logger but it might change.
	 */
	PK11_SetPasswordFunc(get_nss_password);

	if (nssdir != NULL) {
		PK11SlotInfo *slot = lsw_nss_get_authenticated_slot(logger);
		if (slot == NULL) {
			/* already logged */
			pfreeany(nssdir);
			return diag("NSS: could not authenticate slot");
		}
		PK11_FreeSlot(slot);
	}

	pfreeany(nssdir);
	return NULL;
}

void init_nss(const char *configdir, struct nss_flags flags, struct logger *logger)
{
	nss_password = flags.password;
	diag_t d = setup(configdir, flags, logger);
	if (d != NULL) {
		LLOG_FATAL_JAMBUF(PLUTO_EXIT_FAIL, logger, buf) {
			jam_string(buf, str_diag(d));
			pfree_diag(&d);
		}
	}
}

void shutdown_nss(void)
{
	NSS_Shutdown();
	/* this flag is never set anywhere */
	if (!shutdown_flags.skip_pr_cleanup) {
		PR_Cleanup();
	}
}

PK11SlotInfo *lsw_nss_get_authenticated_slot(struct logger *logger)
{
	PK11SlotInfo *slot = PK11_GetInternalKeySlot(); /* refcnt_add() */
	if (slot == NULL) {
		llog(ERROR_STREAM, logger,
		     "no internal key slot");
		return NULL;
	}

	if (PK11_IsFIPS() || PK11_NeedLogin(slot)) {
		SECStatus status = PK11_Authenticate(slot, PR_FALSE,
						     lsw_nss_get_password_context(logger));
		if (status != SECSuccess) {
			const char *token = PK11_GetTokenName(slot);
			llog(ERROR_STREAM, logger,
			     "authentication of \"%s\" failed", token);
			PK11_FreeSlot(slot); /* refcnt_del() */
			return NULL;
		}
	}
	return slot;
}

static char *get_nss_password(PK11SlotInfo *slot, PRBool retry, void *arg)
{
	struct logger *logger = arg;
	pexpect(logger != NULL);

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
		llog(RC_LOG, logger, "NSS Password slot has no token name");
		return NULL;
	}

	if (PK11_ProtectedAuthenticationPath(slot)) {
		llog(RC_LOG, logger,
		     "NSS Password for token \"%s\" failed, slot has protected authentication path",
		     token);
		return NULL;
	}

	/*
	 * Easy case, password specified on the command line.
	 */
	if (nss_password != NULL) {
		char *password = PORT_Strdup(nss_password);
		llog(RC_LOG, logger,
		     "NSS Password for token \"%s\" with length %zu passed to NSS",
		     token, strlen(password));
		return password;
	}

	/*
	 * Hard case, password in a file.  Look for TOKEN:password.
	 *
	 * Do not free the TOKEN.
	 */
	char *password_file = alloc_printf("%s/nsspassword", config_setup_ipsecdir()); /* must free */
	char *file_password = get_nss_file_password(token, password_file, logger);
	pfreeany(password_file);

	return file_password;
}

static char *get_nss_file_password(const char *token, const char *password_file, struct logger *logger)
{
	const int max_password_file_size = 4096;
	char *passwords = PORT_ZAlloc(max_password_file_size);
	if (passwords == NULL) {
		llog(RC_LOG, logger,
		     "NSS Password file \"%s\" for token \"%s\" could not be loaded, NSS memory allocate failed",
		     password_file, token);
		return NULL;
	}

	/*
	 * From here on, every return must be preceded by
	 * PORT_Free(passwords).
	 */
	size_t passwords_len;
	{
		PRFileDesc *fd = PR_Open(password_file, PR_RDONLY, 0);
		if (fd == NULL) {
			llog(RC_LOG, logger,
			     "NSS Password file \"%s\" for token \"%s\" could not be opened for reading",
			     password_file, token);
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
			llog(RC_LOG, logger,
			     "NSS Password file \"%s\" for token \"%s\" ends with a partial line (ignored)",
			     password_file, token);
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
			llog(RC_LOG, logger,
			     "NSS Password from file \"%s\" for token \"%s\" with length %zu passed to NSS",
			     password_file, token, PORT_Strlen(p));
			PORT_Free(passwords);
			return p;
		}
	}

	/* no match found in password file */
	llog(RC_LOG, logger,
	     "NSS Password file \"%s\" does not contain token \"%s\"",
	     password_file, token);
	PORT_Free(passwords);
	return NULL;
}
