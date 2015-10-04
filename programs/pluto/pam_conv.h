/* PAM Authentication and Autherization related
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
struct pam_thread_arg {
	char *name;
	char *password;
	char *c_name;
	char *ra;
	so_serial_t st_serialno;
	unsigned long c_instance_serial;
	char *atype;  /* string XAUTH or IKEv2 */
};

extern bool do_pam_authentication(struct pam_thread_arg *arg);
int pam_conv(int num_msg, const struct pam_message **msgm,
					  struct pam_response **response, void
					  *appdata_ptr);
#endif /* XAUTH_HAVE_PAM */
