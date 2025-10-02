/* show backend functions, for libreswan
 *
 * Copyright (C) 2025 Daiki Ueno <dueno@redhat.com>
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
 */

#ifndef SHOW_OPS_H
#define SHOW_OPS_H

#include <stdarg.h>
#include <stdbool.h>

struct jambuf;

struct show_ops {
	void (*raw_va_list)(struct jambuf *buf, const char *message, va_list ap);
	void (*string_va_list)(struct jambuf *buf, const char *message, va_list ap);
	void (*member_start)(struct jambuf *buf, const char *name);
	void (*member_end)(struct jambuf *buf);
	void (*array_start)(struct jambuf *buf);
	void (*array_end)(struct jambuf *buf);
	void (*object_start)(struct jambuf *buf);
	void (*object_end)(struct jambuf *buf);
	void (*separator)(struct jambuf *buf);
};

#endif
