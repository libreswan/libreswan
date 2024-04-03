/* SPDX-License-Identifier: MIT-0 */

/* Implement the systemd notify protocol without external dependencies.
 * Supports both readiness notification on startup and on reloading,
 * according to the protocol defined at:
 * https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html
 * This protocol is guaranteed to be stable as per:
 * https://systemd.io/PORTABILITY_AND_STABILITY/ */

#include "stdlib.h"	/* for getenv() */
#include "unistd.h"	/* for getpid() */

#include "lswsd.h"
#include "lswalloc.h"
#include "shunk.h"	/* for robust string conversions */

int lswsd_watchdog_enabled(uintmax_t *usec)
{
	/*
	 * Spec says that either WATCHDOG_PID is NULL or matches
	 * getpid().
	 */
	const char *watchdog_pid = getenv("WATCHDOG_PID");
	if (watchdog_pid != NULL) {
		uintmax_t pid;
		if (shunk_to_uintmax(shunk1(watchdog_pid), NULL/*all*/, 10/*base*/, &pid) != NULL) {
			return -1;
		}
		if ((pid_t)pid != getpid()) {
			return -1;
		}
	}

	/*
	 * Spec when WATCHDOG_USEC isn't set things aren't enabled.
	 */
	const char *watchdog_usec = getenv("WATCHDOG_USEC");
	if (watchdog_usec == NULL) {
		return 0; /* not enabled */
	}

	if (shunk_to_uintmax(shunk1(watchdog_usec), NULL/*all*/, 10/*base*/, usec) != NULL) {
		return -1; /* invalid */
	}

	return 1; /* enabled */
}
