/* SPDX-License-Identifier: MIT-0 */

/* Implement the systemd notify protocol without external dependencies.
 * Supports both readiness notification on startup and on reloading,
 * according to the protocol defined at:
 * https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html
 * This protocol is guaranteed to be stable as per:
 * https://systemd.io/PORTABILITY_AND_STABILITY/ */

#ifndef LSWSYSTEMD_H

#include <stdint.h>		/* for uint64_t */

#include "lswcdefs.h"		/* for PRINTF_LIKE */

extern int lswsd_watchdog_enabled(uintmax_t *usecs);
extern int lswsd_notify(const char *string);
extern int lswsd_notifyf(const char *string, ...) PRINTF_LIKE(1);

#endif
