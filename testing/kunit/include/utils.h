/*

   Copyright (c) 2003,2004 Rusty Russell

   This file is part of nfsim.

   nfsim is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   nfsim is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with nfsim; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _STDRUSTY_H
#define _STDRUSTY_H
#include <stdbool.h>
#include <string.h>
#include <stdint.h>

/* Is A == B ? */
#define streq(a, b) (strcmp((a), (b)) == 0)

/* Does A start with B ? */
#define strstarts(a, b) (strncmp((a), (b), strlen(b)) == 0)

/* Does A end in B ? */
static inline bool strends(const char *a, const char *b)
{
	if (strlen(a) < strlen(b))
		return false;

	return streq(a + strlen(a) - strlen(b), b);
}

void barf(const char *fmt, ...) __attribute__((noreturn));
void barf_perror(const char *fmt, ...) __attribute__((noreturn));

void *grab_file(int fd, unsigned long *size);
void release_file(void *data, unsigned long size);

/* Paste two tokens together. */
#define ___cat(a, b) a ## b
#define __cat(a, b) ___cat(a, b)

/* Try to give a unique identifier: this comes close, iff used as static. */
#define __unique_id(stem) __cat(__cat(__uniq, stem), __LINE__)

extern void kernelenv_init(void);
#endif /* _STDRUSTY_H */
