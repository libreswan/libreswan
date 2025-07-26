/* PAM Authentication and Authorization related
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

#ifndef PAM_CONV_H
#define PAM_CONV_H

#ifndef USE_PAM_AUTH
#error USE_PAM_AUTH
#endif

#include "ip_address.h"

struct pam_thread_arg {
	char *name;
	char *password;
	so_serial_t st_serialno;
	ip_address peer_addr;
	const char *atype;  /* string XAUTH or IKEv2 */
	struct {
		char *base_name;
		co_serial_t instance_serial;
	} connection;
};

extern bool do_pam_authentication(struct pam_thread_arg *arg, struct logger *logger);

#endif
