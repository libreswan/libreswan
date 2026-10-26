/* direction of travel, for libreswan
 *
 * Copyright (C) 2022,2026  Andrew Cagney
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

#include "kernel_policy_op.h"
#include "enum_names.h"
#include "names.h"

/* enum kernel_policy_op_names */

static const char *kernel_policy_op_name[] = {
#define S(E) [E] = #E
	S(KERNEL_POLICY_OP_ADD),
	S(KERNEL_POLICY_OP_REPLACE),
#undef S
};

static const struct enum_names kernel_policy_op_enum_names = {
	0, elemsof(kernel_policy_op_name)-1,
	ARRAY_PTR(kernel_policy_op_name),
	.en_prefix = "KERNEL_POLICY_OP_",
};

const struct names kernel_policy_op_names = {
	.enum_names = &kernel_policy_op_enum_names,
};
