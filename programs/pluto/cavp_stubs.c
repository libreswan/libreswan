#include <stdlib.h>

#include "constants.h"
#include "libreswan/passert.h"

/*
 * Crud to get main to link.
 */
enum kernel_interface kern_interface;
extern char *pluto_listen;
char *pluto_listen = NULL;
u_int16_t secctx_attr_type = 0;
deltatime_t crl_check_interval = { 0 };

static void cavp_passert_fail(const char *pred_str,
			      const char *file_str,
			      unsigned long line_no) NEVER_RETURNS;
static void cavp_passert_fail(const char *pred_str,
			      const char *file_str,
			      unsigned long line_no)
{
	fprintf(stderr, "%s:%lu: %s\n", file_str, line_no, pred_str);
	exit(1);
}
libreswan_passert_fail_t libreswan_passert_fail = cavp_passert_fail;

extern void show_setup_plutomain(void);
void show_setup_plutomain(void) { }

extern void exit_pluto(int status);
void exit_pluto(int status) {
	fprintf(stderr, "exit: %d\n", status);
	exit(status);
}
