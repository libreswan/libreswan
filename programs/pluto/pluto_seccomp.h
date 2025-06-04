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

#include "seccomp_mode.h"

struct config_setup;
struct logger;
struct show;
struct whack_message;

void init_seccomp_main(const struct config_setup *oco, struct logger *logger);
void init_seccomp_cryptohelper(int helpernum, struct logger *logger);

void whack_seccomp_crashtest(const struct whack_message *wm, struct show *s);
void show_seccomp(const struct config_setup *oco, struct show *s);
void seccomp_sigsys_handler(struct logger *logger);

#endif
