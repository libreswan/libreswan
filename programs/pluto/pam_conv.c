/* PAM Authentication and Authorization related functions
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
 * Copyright (C) 2013-2015 Antony Antony <antony@phenome.org>
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
 * This code originally written by Colubris Networks, Inc.
 * Extraction of patch and porting to 1.99 codebases by Xelerance Corporation
 * Porting to 2.x by Sean Mathews
 */

#include <string.h>
#include <stdlib.h>
#include <security/pam_appl.h>		/* rpm:pam-devel deb:libpam0g-dev */

#include "defs.h"
#include "log.h"
#include "pam_conv.h"

/*
 * PAM conversation
 *
 * @param num_msg Int.
 * @param msgm Pam Message Struct
 * @param response Where PAM will put the results
 * @param appdata_ptr Pointer to data struct (as we are using threads)
 * @return int PAM Return Code (possibly fudged)
 */

static int pam_conversation(int nr_messages,
			    const struct pam_message **messages,
			    struct pam_response **responses,
			    void *appdata_ptr)
{
	struct pam_thread_arg *const arg = appdata_ptr;
	int count = 0;
	struct pam_response *reply;

	if (nr_messages <= 0) {
		return PAM_CONV_ERR;
	}

	/*
	 * According to pam_conv(3), caller will free(3) reply so we
	 * must allocate it with malloc.
	 */
	reply = calloc(nr_messages, sizeof(struct pam_response)); /* i.e., malloc() */

	for (count = 0; count < nr_messages; ++count) {

		const struct pam_message *message = messages[count];
		struct pam_response *response = &reply[count];

		const char *s = NULL;
		switch (message->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
			s = arg->password;
			break;
		case PAM_PROMPT_ECHO_ON:
			s = arg->name;
			break;
		case PAM_ERROR_MSG:
			/* YES, stderr, points at stdout */
			fprintf(stderr, "%s\n", message->msg);
			fflush(stdout); /* redundant */
			break;
		case PAM_TEXT_INFO:
			fprintf(stdout, "%s\n", message->msg);
			/* else next fork()/exec() prints it again */
			fflush(stdout);
			break;
		}

		if (s != NULL) {
			/*
			 * Add s to list of responses.
			 *
			 * According to pam_conv(3), our caller will
			 * use free(3) to free these arguments so we
			 * must allocate them with malloc() et.al.,
			 * not our own allocators.
			 */
			response->resp = strdup(s); /* i.e., malloc() */
		}
	}

	*responses = reply;
	return PAM_SUCCESS;
}

static void dbg_pam_step(const struct pam_thread_arg *arg, const char *what)
{
	dbg("%s helper thread %s for state "PRI_SO", %s[%lu] user=%s.",
	    arg->atype, what,
	    pri_so(arg->st_serialno), arg->c_name,
	    arg->c_instance_serial, arg->name);
}

/*
 * PAM (Pluggable Authentication Modules) interaction with external module
 * NO locks/mutex here all data is copied already
 *
 * @return bool success
 */
/* IN AN AUTH PROCESS */
bool do_pam_authentication(struct pam_thread_arg *arg, struct logger *logger)
{
	int retval;
	pam_handle_t *pamh = NULL;
	const char *what;

	/*
	 * This do-while structure is designed to allow a logical
	 * cascade without excessive indentation.  No actual looping
	 * happens.  Failure is handled by "break".
	 */
	do {
		struct pam_conv conv = {
			.conv = pam_conversation,
			.appdata_ptr = arg,
		};

		what = "pam_start";
		retval = pam_start("pluto", arg->name, &conv, &pamh);
		if (retval != PAM_SUCCESS)
			break;
		dbg_pam_step(arg, what);

		/* Send the remote host address to PAM */
		what = "pam_set_item";
		address_buf rhb;
		retval = pam_set_item(pamh, PAM_RHOST, str_address(&arg->rhost, &rhb));
		if (retval != PAM_SUCCESS)
			break;
		dbg_pam_step(arg, what);

		/* Two factor authentication - Check that the user is valid,
		 * and then check if they are permitted access
		 */
		what = "pam_authenticate";
		retval = pam_authenticate(pamh, PAM_SILENT); /* is user really user? */
		if (retval != PAM_SUCCESS)
			break;
		dbg_pam_step(arg, what);

		what = "pam_acct_mgmt";
		retval = pam_acct_mgmt(pamh, 0); /* permitted access? */
		if (retval != PAM_SUCCESS)
			break;
		dbg_pam_step(arg, what);

		/* success! */
		pam_end(pamh, PAM_SUCCESS);
		return true;
	} while (false);

	/* common failure code */
	llog(RC_LOG, logger,
	     "%s FAILED during %s with '%s' for state "PRI_SO", %s[%lu] user=%s.",
	     arg->atype, what, pam_strerror(pamh, retval),
	     pri_so(arg->st_serialno), arg->c_name, arg->c_instance_serial,
	     arg->name);
	pam_end(pamh, retval);
	return false;
}
