/*
 * IKEv1 msgid handling
 * Copyright (C) 2014 Paul Wouters <paul@libreswan.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#include <sys/types.h>

/* msgid_t defined in defs.h */
#include "defs.h"

extern void reserve_msgid(struct state *st, msgid_t msgid);
extern bool unique_msgid(const struct state *st, msgid_t msgid);
extern msgid_t generate_msgid(const struct state *st);
extern void ikev1_clear_msgid_list(const struct state *st);

