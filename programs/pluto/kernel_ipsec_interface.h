/* Kernel interace to IPsec Interface, for libreswan
 *
 * Copyright (C) 2024 Andrew Cagney
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
 *
 */

#ifndef KERNEL_IPSEC_INTERFACE_H
#define KERNEL_IPSEC_INTERFACE_H

struct kernel_ipsec_interface {
	const char *name;
	/*
	 * On XFRMi IF_ID 0 is invalid; hence remap ipsec-interface=0
	 * to some other value; is this all about preserving old VTI
	 * code?
	 */
	uint32_t map_if_id_zero;
};

extern const struct kernel_ipsec_interface kernel_ipsec_interface_xfrm;
extern const struct kernel_ipsec_interface kernel_ipsec_interface_bsd;

#endif
