/* compute rekey time for libreswan
 *
 * Copyright (C) 2022 Antony Antony <antony@phenome.org>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/lgpl-2.1.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 *
 */

#ifndef REKEYFUZZ_H
#define REKEYFUZZ_H

#include <stdint.h>

struct logger;
enum sa_role;

extern uintmax_t fuzz_soft_limit(const char *what, enum sa_role,
				 uintmax_t hard_limit, unsigned soft_limit_percent,
				 struct logger *logger);

extern uint64_t fuzz_margin(bool initiator, unsigned long marg,  unsigned long fuzz);

#endif
