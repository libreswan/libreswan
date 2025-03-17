/* OCSP method, for libreswan
 *
 * Copyright (C) 2016 Paul Wouters <pwouters@redhat.com>
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

#ifndef OCSP_METHOD_H
#define OCSP_METHOD_H

enum ocsp_method {
	OCSP_METHOD_GET = 1, /* really GET plus POST - see NSS code */
	OCSP_METHOD_POST = 2, /* only POST */
};

extern const struct sparse_names ocsp_method_names;

#endif
