/* some MP utilities */

#ifndef _MP_H
#define _MP_H

#include <gmp.h>

extern chunk_t mpz_to_n_autosize(const MP_INT *mp);

#endif /* _MP_H */
