/* some MP utilities */

#ifndef _MP_H
#define _MP_H

#include <gmp.h>

extern void n_to_mpz(MP_INT *mp, const u_char *nbytes, size_t nlen);

extern chunk_t mpz_to_n_autosize(const MP_INT *mp);

/* var := mod(base ** exp, mod), ensuring var is mpz_inited */
#define mpz_init_powm(flag, var, base, exp, mod) { \
		if (!(flag)) \
			mpz_init(&(var)); \
		(flag) = TRUE; \
		mpz_powm(&(var), &(base), &(exp), (mod)); \
}

#endif /* _MP_H */
