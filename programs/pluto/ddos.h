/* Distributed Denial Of Server config, for libreswan
 *
 * Copyright (C) 1998-2001,2013  D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2019 Andrew Cagney
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
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

#ifndef DDOS_H
#define DDOS_H

#include <stdbool.h>

#include "err.h"
#include "ddos_mode.h"

struct show;
struct whack_message;
struct logger;
struct jambuf;
struct config_setup;

extern void set_ddos_mode(enum ddos_mode mode, struct logger *logger);

void whack_ddos(const struct whack_message *wm, struct show *s);
#if 0
void show_ddos(struct show *s);
#endif

bool require_ddos_cookies(void);
err_t drop_new_exchanges(struct logger *logger);

void init_ddos(const struct config_setup *oco, struct logger *logger);

#endif

