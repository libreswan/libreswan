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

#include "constants.h"		/* for enum sa_role */
#include "lswlog.h"
#include "rnd.h"

#include "rnd.h"		/* for fips get_rnd() */
#include "constants.h"		/* for enum sa_role */
#include "lswlog.h"		/* for bad_case() */

#include "rekeyfuzz.h"
#include "sa_role.h"

/*
 * Important policy lies buried here.
 *
 * The initiator is made to rekey earlier, either with a smaller limit
 * or bigger margin before a replace.
 */

deltatime_t fuzz_rekey_margin(enum sa_role role, deltatime_t marg,  unsigned fuzz_percent)
{

	switch (role) {
	case SA_INITIATOR:
	{
		/*
		 * Give the initiator a larger margin so that its
		 * rekey event is scheduled earlier (relative to the
		 * replace event).
		 */
		uintmax_t fuzz = get_rnd_uintmax() % (fuzz_percent + 1);
		return deltatime_scale(marg, 100 + fuzz, 100);
	}
	case SA_RESPONDER:
		/*
		 * Give the responder a smaller margin so that its
		 * rekey event is scheduled later (relative to the
		 * replace event).
		 */
		return deltatime_scale(marg, 1, 2);
	default:
		bad_case(role);
	}
}

uintmax_t fuzz_soft_limit(const char *what, enum sa_role role,
			  uintmax_t hard_limit, unsigned soft_limit_percentage,
			  struct logger *logger)
{
	/*
	 * Can't use c->sa_rekey_fuzz as configuration allows values
	 * >100%.  For a limit calculation that would be a disaster.
	 */
	if (!pexpect(hard_limit > 1)) {
		return hard_limit;
	}
	passert(soft_limit_percentage >= 1);
	passert(soft_limit_percentage <= 100);

	/*
	 * Convert the HARD_LIMIT into a soft limit; being careful of
	 * underflow and overflow:
	 *
	 * - when HARD_LIMIT is small use H*P/100 as H/100 in H/100*P
	 * will underflow
	 *
	 * - when HARD_LIMIT is large compute H/100*P as HP*P in
	 * H*P/100 will overflow
	 */
	uintmax_t soft_limit;
	if (hard_limit < 1000*100) {
		soft_limit = hard_limit * soft_limit_percentage / 100;
	} else {
		soft_limit = (hard_limit / 100) * soft_limit_percentage;
	}

	/*
	 * Give the SOFT_LIMIT a little fuzz in the range
	 * [SOFT_LIMIT..SOFT_LIMIT/8], however don't fuzz small values
	 * (i.e., make the value deterministic, presumably it is for
	 * testing).
	 *
	 * SOFT_LIMIT/8 is somewhat arbitrary, it ensures that
	 * SOFT_LIMIT/2+FUZZ < SOFT_LIMIT-FUZZ.
	 *
	 * +1 is not arbitrary, without it get_rnd_uintmax()
	 * would barf when soft_limit/8==0.
	 */
	uintmax_t fuzz;
	if (hard_limit < 16384/*magic*/) {
		fuzz = 0;
	} else {
		fuzz = get_rnd_uintmax() % (soft_limit / 8 + 1);
	}

	const char *role_name;
	uintmax_t softer_limit;
	uintmax_t actual_limit;
	switch (role) {
	case SA_INITIATOR:
		/*
		 * Make the initiator rekey first by further dividing
		 * the soft limit.
		 */
		role_name = "initiator";
		softer_limit = soft_limit/2;
		actual_limit = softer_limit + fuzz;
		break;
	case SA_RESPONDER:
		/*
		 * Make the responder rekey last by giving it
		 * the larger ~SOFT_LIMIT.
		 */
		role_name = "responder";
		softer_limit = soft_limit;
		actual_limit = softer_limit - fuzz;
		break;
	default:
		bad_case(role);
	}

	/* just don't reduce a hard-limit to 0 */
	if (actual_limit == 0) {
		actual_limit = 1;
	}

	if (DBGP(DBG_BASE)) {
		ldbg(logger, "%s %s: hard-limit=%ju soft-limit=%ju softer-limit=%ju fuzz=%ju actual-limit=%ju",
		     role_name, what, hard_limit, soft_limit, softer_limit, fuzz, actual_limit);
	}

	return actual_limit;

}
