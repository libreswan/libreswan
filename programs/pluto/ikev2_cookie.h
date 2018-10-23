/* IKEv2 cookie calculation, for Libreswan
 *
 * Copyright (C) 2018 Andrew Cagney
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

#ifndef IKEV2_COOKIE_H
#define IKEV2_COOKIE_H

#include <stdint.h>
#include <stdbool.h>

struct msg_digest;

/*
 * That the cookie size of 32-bytes happens to match
 * SHA2_256_DIGEST_SIZE is just a happy coincidence.
 */
typedef struct {
	uint8_t bytes[32];
} v2_cookie_t;

bool compute_v2_cookie_from_md(v2_cookie_t *cookie, struct msg_digest *md);

void refresh_v2_cookie_secret(void);

#endif
