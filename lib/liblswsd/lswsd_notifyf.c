/* SPDX-License-Identifier: MIT-0 */

/* Implement the systemd notify protocol without external dependencies.
 * Supports both readiness notification on startup and on reloading,
 * according to the protocol defined at:
 * https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html
 * This protocol is guaranteed to be stable as per:
 * https://systemd.io/PORTABILITY_AND_STABILITY/ */

#include "lswsd.h"
#include "lswalloc.h"

int lswsd_notifyf(const char *string, ...)
{
	va_list ap;
	va_start(ap, string);
	char *notify = alloc_vprintf(string, ap);
	va_end(ap);

	int result = lswsd_notify(notify);
	pfree(notify);
	return result;
}
