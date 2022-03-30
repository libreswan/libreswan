/* Authentication, for libreswan
 *
 * Copyright (C) 2022 Andrew Cagney
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

#ifndef AUTHBY_H
#define AUTHBY_H

#include <stdbool.h>

#include "lset.h"

enum keyword_auth;
struct jambuf;

struct authby {
	bool psk;
	bool null;
	bool never;
	bool rsasig;
	bool ecdsa;
	bool rsasig_v1_5;
};

#define AUTHBY_RSASIG (struct authby) { .rsasig = true, .rsasig_v1_5 = true, }
#define AUTHBY_ECDSA (struct authby) { .ecdsa = true, }
#define AUTHBY_NEVER (struct authby) { .never = true, }
#define AUTHBY_NULL (struct authby) { .null = true, }
#define AUTHBY_PSK (struct authby) { .psk = true, }

#define AUTHBY_NONE (struct authby) {0}
#define AUTHBY_ALL (struct authby) { true, true, true, true, true, true }

struct authby authby_intersection(struct authby lhs, struct authby rhs);
struct authby authby_union(struct authby lhs, struct authby rhs);
bool authby_le(struct authby lhs, struct authby rhs);
bool authby_is_set(struct authby authby);
bool authby_eq(struct authby, struct authby);

bool authby_has_rsasig(struct authby);
bool authby_has_ecdsa(struct authby);
bool authby_has_digsig(struct authby);

lset_t policy_from_authby(struct authby authby);
enum keyword_auth auth_from_authby(struct authby authby);
struct authby authby_from_auth(enum keyword_auth auth);

typedef struct {
	char buf[sizeof("RSA+NULL+NEVER+RSASIG+ECDSA+RSASIG_v1_5") + 1/*canary*/];
} authby_buf;

const char *str_authby(struct authby authby, authby_buf *buf);

size_t jam_authby(struct jambuf *buf, struct authby authby);

#endif
