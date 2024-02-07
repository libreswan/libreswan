/* message_role names, for libreswan
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

#include "lswcdefs.h"		/* for ARRAY_REF() */
#include "enum_names.h"
#include "message_role.h"

const char *message_role_name[] = {
#define S(E) [E - MESSAGE_ROLE_FLOOR] = #E
	S(NO_MESSAGE),
	S(MESSAGE_REQUEST),
	S(MESSAGE_RESPONSE),
#undef S
};

const struct enum_names message_role_names = {
	MESSAGE_ROLE_FLOOR, MESSAGE_ROLE_ROOF-1,
	ARRAY_REF(message_role_name),
	"MESSAGE_",
	NULL,
};
