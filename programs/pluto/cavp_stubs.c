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

extern void show_setup_plutomain(void);
void show_setup_plutomain(void) { }

extern void exit_pluto(int status);
void exit_pluto(int status) {
	fprintf(stderr, "exit: %d\n", status);
	exit(status);
}
