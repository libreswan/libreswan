/*
 * seccomp support for Linux kernel using seccomp
 *
 * Copyright (c) 2016 Paul Wouters <pwouters@redhat.com>
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

#ifndef PLUTO_SECCOMP_H
#define PLUTO_SECCOMP_H

#include <seccomp.h>
#include <stdint.h>		/* for uint32_t */

void init_seccomp_main(uint32_t def_action);
void init_seccomp_cryptohelper(uint32_t def_action);

#endif
