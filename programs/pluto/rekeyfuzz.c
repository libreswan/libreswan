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

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#include "rekeyfuzz.h"

uint64_t fuzz_margin(bool initiator, unsigned long marg,  unsigned long fuzz)
{
	/*
	 * Important policy lies buried here. For example, we favour the
	 * initiator over the responder by making the initiator start
	 * rekeying sooner.
	 */

	if (initiator) {
		marg += marg * fuzz / 100.E0 * (rand() / (RAND_MAX + 1.E0));
	} else {
		marg /= 2;
	}

	return marg;
}

uint64_t soft_limit(bool initiator, uint64_t max, unsigned long marg,
				   unsigned long fuzz)
{
	uint64_t new_marg = fuzz_margin(initiator, marg, fuzz);
	uint64_t ret = (max > new_marg) ? (max - new_marg) : max;
	return ret;
}
