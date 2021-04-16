/* diagnostic return type, for libreswan
 *
 * Copyright (C) 2020  Andrew Cagney
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
 */

#ifndef DIAG_H
#define DIAG_H

#include <stdarg.h>

#include "lswcdefs.h"
#include "lset.h"

struct jambuf;
struct logger;
enum pluto_exit_code;

typedef struct diag *diag_t;

diag_t diag(const char *message, ...) PRINTF_LIKE(1) MUST_USE_RESULT;
diag_t diag_va_list(const char *fmt, va_list ap) PRINTF_LIKE_VA(1) MUST_USE_RESULT;
diag_t diag_jambuf(struct jambuf *buf);

diag_t diag_diag(diag_t *d, const char *message, ...) PRINTF_LIKE(2) MUST_USE_RESULT;
void llog_diag(lset_t rc_flags, struct logger *logger, diag_t *diag,
	       const char *fmt, ...) PRINTF_LIKE(4);

void fatal_diag(enum pluto_exit_code rc, struct logger *logger, diag_t *diag,
		const char *message, ...) PRINTF_LIKE(4) NEVER_RETURNS;

const char *str_diag(diag_t diag);
size_t jam_diag(struct jambuf *buf, diag_t diag);

diag_t clone_diag(struct diag *diag);
void pfree_diag(struct diag **diag);

#endif
