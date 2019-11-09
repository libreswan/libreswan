
/* simple test program from https://github.com/beatgammit/simple-pam */

/* "gooduser60" will just sleep for 60 seconds and return success */
/* "gooduser90" will just sleep for 90 secods and return success */
/* "gooduser" will always succeed with "right" password - everything else fails */
/* "@road" will always succeed with "right" password - everything else fails */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

/* expected hook */
PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	printf("Acct mgmt\n");
	return PAM_SUCCESS;
}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
	int retval;

	const char* pUsername;
	retval = pam_get_user(pamh, &pUsername, "Username: ");

	printf("Welcome %s\n", pUsername);

	if (retval != PAM_SUCCESS) {
		return retval;
	}

	if (strcmp(pUsername, "gooduser60") == 0)
		sleep(60);
	if (strcmp(pUsername, "gooduser90") == 0)
		sleep(90);
	else if (strcmp(pUsername, "@road") == 0)
		return PAM_SUCCESS;
	else if (strcmp(pUsername, "gooduser") != 0)
		return PAM_AUTH_ERR;

	return PAM_SUCCESS;
}
