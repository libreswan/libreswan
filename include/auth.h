/* AUTH constants, for libreswan
 *
 * Copyright (C) 2020, 2022 Andrew Cagney
 * Copyright (C) 2021 Paul Wouters <paul.wouters@aiven.io>
 * Copyright (C) 2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2018 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2017 Antony Antony <antony@phenome.org>
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

#ifndef AUTH_H
#define AUTH_H

enum auth {
	AUTH_UNSET = 0,
#define AUTH_FLOOR AUTH_NEVER
	AUTH_NEVER,
	AUTH_PSK,
	AUTH_RSASIG,
	AUTH_ECDSA,
	AUTH_EDDSA,
	AUTH_NULL,
	AUTH_EAPONLY,
#define AUTH_ROOF (AUTH_EAPONLY+1)
};

extern const struct enum_names auth_names;

#endif
