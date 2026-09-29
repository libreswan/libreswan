/* PSK authentication variations
 *
 * Copyright (C) 2026 Andrew Cagney
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

#ifndef PSK_AUTH_METHOD_H
#define PSK_AUTH_METHOD_H

enum psk_auth_method {
	PSK_AUTH_NULL = 1,
	PSK_AUTH_SHARED_KEY,
};

extern const struct names psk_auth_method_names;
/* the name that auth= would call the method */
extern const struct names psk_auth_method_stories;

#endif
