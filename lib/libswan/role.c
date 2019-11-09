/* sa_role names, for libreswan
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

#include "keywords.h"
#include "constants.h"

struct keyword sa_role_keywords[] = {
#define S(E, H) [SA_##E] = { .name = "SA_" #E, .sname = #E, .value = SA_##E, .details = H, }
	S(INITIATOR, "SA initiator"),
	S(RESPONDER, "SA responder"),
#undef S
};

struct keywords sa_role_names =
	SPARSE_KEYWORDS("SA role", sa_role_keywords);

struct keyword message_role_keywords[] = {
#define S(E, H) [MESSAGE_##E] = { .name = "MESSAGE_" #E, .sname = #E, .value = MESSAGE_##E, .details = H, }
	S(REQUEST, "message request"),
	S(RESPONSE, "message response"),
#undef S
};

struct keywords message_role_names =
	SPARSE_KEYWORDS("message role", message_role_keywords);
