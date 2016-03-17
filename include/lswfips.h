/* FIPS functions to determine FIPS status
 *
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#ifndef _LSW_FIPS_H
#define _LSW_FIPS_H

#ifdef FIPS_CHECK

int libreswan_has_fips_product(bool force);
int libreswan_has_fips_kernel(bool force);

void libreswan_set_fips_mode(bool fips_mode);

int libreswan_fipsmode(void);
int libreswan_fipsproduct(void);
int libreswan_fipskernel(void);
#endif

#endif /* _LSW_FIPS_H_ */
