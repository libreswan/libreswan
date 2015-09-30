/* PAM Authentication and Autherization related functions
 *
 * Copyright (C) 2001-2002 Colubris Networks
 * Copyright (C) 2003 Sean Mathews - Nu Tech Software Solutions, inc.
 * Copyright (C) 2003-2004 Xelerance Corporation
 * Copyright (C) 2009 Ken Wilson <Ken_Wilson@securecomputing.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012-2013 Philippe Vouters <philippe.vouters@laposte.net>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
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
 *
 * This code originally written by Colubris Networks, Inc.
 * Extraction of patch and porting to 1.99 codebases by Xelerance Corporation
 * Porting to 2.x by Sean Mathews
 */

#ifdef XAUTH_HAVE_PAM
#include <string.h>
#include <stdlib.h>
#include <security/pam_appl.h> /* needed for pam_handle_t */

#include "defs.h"
#include "lswlog.h"
#include "pam_conv.h"

/* BEWARE: This code is multi-threaded.
 *
 * Any static object is likely shared and probably has to be protected by
 * a lock.
 * Any other shared object needs to be protected.
 * Beware of calling functions that are not thread-safe.
 *
 * Non-thread-safe functions:
 * - ??? pam_*?
 */

/*
 * PAM conversation
 *
 * @param num_msg Int.
 * @param msgm Pam Message Struct
 * @param response Where PAM will put the results
 * @param appdata_ptr Pointer to data struct (as we are using threads)
 * @return int PAM Return Code (possibly fudged)
 */
int pam_conv(int num_msg,
		const struct pam_message **msgm,
		struct pam_response **response,
		void *appdata_ptr)
{
	struct pam_thread_arg *const arg = appdata_ptr;
	int count = 0;
	struct pam_response *reply;

	if (num_msg <= 0)
		return PAM_CONV_ERR;

	/*
	 *   According to pam_conv(3), caller will free(3) reply
	 *   so we must allocate it with malloc.
	 */
	reply = malloc(num_msg * sizeof(struct pam_response));

	for (count = 0; count < num_msg; ++count) {
		const char *s = NULL;

		switch (msgm[count]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
			s = arg->password;
			break;
		case PAM_PROMPT_ECHO_ON:
			s = arg->name;
			break;
		}

		reply[count].resp_retcode = 0;
		reply[count].resp = NULL;       /* for unhandled case */

		if (s != NULL) {
			/*
			 * Add s to list of responses.
			 * According to pam_conv(3), our caller will
			 * use free(3) to free these arguments so
			 * we must allocate them with malloc,
			 * not our own allocators.
			 */
			size_t len = strlen(s) + 1;
			char *t = malloc(len);	/* must be malloced */

			memcpy(t, s, len);
			reply[count].resp = t;
		}
	}

	*response = reply;
	return PAM_SUCCESS;
}

/*
 * Do IKEv2 second authentication via PAM (Plugable Authentication Modules)
 *
 * @return bool success
 */
/* IN AN AUTH THREAD */
bool ikev2_do_pam_authentication(void *varg)
{
	struct pam_thread_arg *arg = varg;
	int retval;
	pam_handle_t *pamh = NULL;
	struct pam_conv conv;
	const char *what;

	/* This do-while structure is designed to allow a logical cascade
	 * without excessive indentation.  No actual looping happens.
	 * Failure is handled by "break".
	 */
	do {
		conv.conv = pam_conv;
		conv.appdata_ptr = varg;

		what = "pam_start";
		retval = pam_start("pluto", arg->name, &conv, &pamh);
		if (retval != PAM_SUCCESS)
			break;

		DBG(DBG_CONTROL, DBG_log("pam_start SUCCESS"));

		/* Send the remote host address to PAM */
		what = "pam_set_item";
		retval = pam_set_item(pamh, PAM_RHOST, arg->ra);
		if (retval != PAM_SUCCESS)
			break;

		DBG(DBG_CONTROL, DBG_log("pam_set_item SUCCESS"));

		/* Two factor authentication - Check that the user is valid,
		 * and then check if they are permitted access
		 */
		what = "pam_authenticate";
		retval = pam_authenticate(pamh, PAM_SILENT); /* is user really user? */

		if (retval != PAM_SUCCESS)
			break;

		DBG(DBG_CONTROL, DBG_log("pam_authenticate SUCCESS"));

		what = "pam_acct_mgmt";
		retval = pam_acct_mgmt(pamh, 0); /* permitted access? */
		if (retval != PAM_SUCCESS)
			break;

		/* success! */
		libreswan_log("IKEv2: PAM_SUCCESS");
		pam_end(pamh, PAM_SUCCESS);
		return TRUE;
	} while (FALSE);

	/* common failure code */

	DBG(DBG_CONTROL,
	    DBG_log("%s failed with '%s", what, pam_strerror(pamh, retval)));
	libreswan_log("IKEv2 : %s failed with '%s'", what, pam_strerror(pamh, retval));
	pam_end(pamh, retval);
	return FALSE;
}
#endif /* XAUTH_HAVE_PAM */
