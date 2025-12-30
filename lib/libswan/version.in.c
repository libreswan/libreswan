/*
 * return IPsec version information
 * Copyright (C) 2001  Henry Spencer.
 * Copyright (C) 2013  Paul Wouters
 * Copyright (C) 2025  Andrew Cagney
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

#include "lswversion.h"

#define V "@@IPSECVERSION@@"	/* substituted in by Makefile */
static const char libreswan_string[] = "Libreswan " V;

const char libreswan_version[] =
	"@@IPSECVERSION@@";			/* substituted in by Makefile */
const char libreswan_vendorid[] =
	"OE-Libreswan-@IPSECVIDVERSION@";	/* substituted in by Makefile */

const char *ipsec_version_string(void)
{
	return libreswan_string;
}
