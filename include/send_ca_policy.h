/* Send CA policy, for libreswan
 *
 * Copyright (C) 2014 Matt Rogers <mrogers@redhat.com>
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

#ifndef SEND_CA_POLICY_H
#define SEND_CA_POLICY_H

enum send_ca_policy {
	CA_SEND_NONE = 0,
	CA_SEND_ISSUER = 1,
	CA_SEND_ALL = 2,
};

extern const struct enum_names send_ca_policy_names;

#endif
