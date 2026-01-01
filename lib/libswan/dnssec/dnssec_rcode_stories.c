/* Official DNS RCODE names, for libreswan
 *
 * Copyright (C) 2025 Andrew Cagney
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

#include "dnssec.h"
#include "sparse_names.h"

const struct sparse_names dnssec_rcode_stories = {
	.list = {

		/*RCODE,Name,Description,Reference*/

		SPARSE("No Error", 0 /*NoError,[RFC1035]*/),
		SPARSE("Format Error", 1 /*FormErr,[RFC1035]*/),
		SPARSE("Server Failure", 2 /*ServFail,[RFC1035]*/),
		SPARSE("Non-Existent Domain", 3 /*NXDomain,[RFC1035]*/),
		SPARSE("Not Implemented", 4 /*NotImp,[RFC1035]*/),
		SPARSE("Query Refused", 5 /*Refused,[RFC1035]*/),
		SPARSE("Name Exists when it should not", 6 /*YXDomain,[RFC2136][RFC6672]*/),
		SPARSE("RR Set Exists when it should not", 7 /*YXRRSet,[RFC2136]*/),
		SPARSE("RR Set that should exist does not", 8 /*NXRRSet,[RFC2136]*/),
		SPARSE("Server Not Authoritative for zone", 9 /*NotAuth,[RFC2136]*/),
		SPARSE("Not Authorized", 9 /*NotAuth,[RFC8945]*/),
		SPARSE("Name not contained in zone", 10 /*NotZone,[RFC2136]*/),
		SPARSE("DSO-TYPE Not Implemented", 11 /*DSOTYPENI,[RFC8490]*/),
		/*12-15,Unassigned,,*/
		SPARSE("Bad OPT Version", 16 /*BADVERS,[RFC6891]*/),
		SPARSE("TSIG Signature Failure", 16 /*BADSIG,[RFC8945]*/),
		SPARSE("Key not recognized", 17 /*BADKEY,[RFC8945]*/),
		SPARSE("Signature out of time window", 18 /*BADTIME,[RFC8945]*/),
		SPARSE("Bad TKEY Mode", 19 /*BADMODE,[RFC2930]*/),
		SPARSE("Duplicate key name", 20 /*BADNAME,[RFC2930]*/),
		SPARSE("Algorithm not supported", 21 /*BADALG,[RFC2930]*/),
		SPARSE("Bad Truncation", 22 /*BADTRUNC,[RFC8945]*/),
		SPARSE("Bad/missing Server Cookie", 23 /*BADCOOKIE,[RFC7873]*/),

		/*24-3840,Unassigned,,*/
		/*3841-4095,Reserved for Private Use,,[RFC6895]*/
		/*4096-65534,Unassigned,,*/
		/*65535,"Reserved, can be allocated by Standards Action",,[RFC6895]*/

		SPARSE_NULL
	},
};
