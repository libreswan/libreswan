/* randomness machinery
 * Copyright (C) 1998, 1999  D. Hugh Redelmeier.
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
 */

#ifndef PLUTO_RND_H
#define PLUTO_RND_H

/* for SHA1_DIGEST_SIZE */
#include "constants.h"
#include "ietf_constants.h"

extern u_char secret_of_the_day[SHA1_DIGEST_SIZE];
extern u_char ikev2_secret_of_the_day[SHA1_DIGEST_SIZE];

extern void get_rnd_bytes(u_char *buffer, int length);
extern void init_rnd_pool(void);
extern void init_secret(void);
#endif
