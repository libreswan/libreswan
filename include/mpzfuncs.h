/* some MP utilities */

#ifndef _MP_H
#define _MP_H

#include <gmp.h>

extern void n_to_mpz(MP_INT *mp, const u_char *nbytes, size_t nlen);

extern chunk_t mpz_to_n_autosize(const MP_INT *mp);

#endif /* _MP_H */
