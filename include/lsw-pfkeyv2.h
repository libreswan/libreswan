/* Wrapper for <net/pfkeyv2.h>, for libreswan
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

#ifndef LSW_PFKEYv2_H
#define LSW_PFKEYv2_H

/*
 * See: https://tools.ietf.org/html/rfc2367
 *
 * This header pulls in all the SADB_* and sadb_* declarations
 * described by RFC 2368 (along with any extensions which use the
 * prefix SADB_X_... or sadb_x_...).
 *
 * This header also tries to define macros that flag any divergence
 * from the origin PF_KEY v2 spec.
 */

#if defined(KERNEL_BSDKAME) || defined(KERNEL_PFKEYV2)
# ifdef __linux__
#  include <stdint.h>
#  include <linux/pfkeyv2.h>
# else
#  include <sys/types.h>
#  include <net/pfkeyv2.h>
# endif
#endif

#endif
