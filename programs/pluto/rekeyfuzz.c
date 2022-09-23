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
#include <limits.h>

#include "constants.h"		/* for enum sa_role */
#include "lswlog.h"
#include "rnd.h"

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

uintmax_t fuzz_soft_limit(const char *what, enum sa_role role,
			  uintmax_t hard_limit, unsigned soft_limit_percentage,
			  struct logger *logger)
{
	/*
	 * Can't use c->sa_rekey_fuzz as configuration allows values
	 * >100%.  For a limit calculation that is a disaster.
	 */
	if (!pexpect(hard_limit > 1)) {
		return hard_limit;
	}
	passert(soft_limit_percentage >= 1);
	passert(soft_limit_percentage <= 100);

	/*
	 * XXX: this math is horrible.
	 *
	 * When HARD_FLOAT is small H*P/100 is best as H/100*P
	 * underflows.
	 *
	 * When HARD_FLOAT is huge H/100*P is best as H*P/100
	 * overflows (even when using double).
	 */

	uintmax_t soft_limit;
	if (hard_limit < 100*100) {
		/* avoid underflow */
		soft_limit = hard_limit * soft_limit_percentage / 100;
	} else {
		/* avoid overflow */
		soft_limit = (hard_limit / 100) * soft_limit_percentage;
	}

	uintmax_t quarter_limit = soft_limit / 4;
	if (quarter_limit == 0) {
		/* give up */
		return hard_limit - 1;
	}

	uintmax_t actual_limit;

	const char *role_name;
	switch (role) {
	case SA_INITIATOR:
		/*
		 * Make the initiator rekey first by giving it the
		 * smaller limitL 25%-50% of SOFT_LIMIT.
		 */
		role_name = "initiator";
		actual_limit = quarter_limit + get_rnd(/*roof*/quarter_limit);
		break;
	case SA_RESPONDER:
		/*
		 * Make the responder rekey last by giving it a larger
		 * limit: 75%-100% of SOFT_LIMIT.
		 */
		role_name = "responder";
		actual_limit = soft_limit - get_rnd(/*roof*/quarter_limit);
		break;
	default:
		bad_case(role);
	}

	/* just don't reduce a hard-limit to 0 */
	if (actual_limit == 0 && hard_limit > 0) {
		actual_limit = 1;
	}

	if (DBGP(DBG_BASE)) {
		ldbg(logger, "%s %s: hard-limit=%ju soft-limit=%ju actual-limit=%ju",
		     role_name, what, hard_limit, soft_limit, actual_limit);
	}

	return actual_limit;

}
