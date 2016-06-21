#include <stdlib.h>

#include "constants.h"
#include "libreswan/passert.h"

/*
 * Crud to get main to link.
 */
libreswan_passert_fail_t libreswan_passert_fail;
enum kernel_interface kern_interface;
extern void exit_pluto(int status);
void exit_pluto(int status UNUSED) { }
extern void show_setup_plutomain(void);
void show_setup_plutomain(void) { }
extern char *pluto_listen;
char *pluto_listen = NULL;
u_int16_t secctx_attr_type = 0;
deltatime_t crl_check_interval = { 0 };
