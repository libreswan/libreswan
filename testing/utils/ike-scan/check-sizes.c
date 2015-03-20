/*
 * The IKE Scanner (ike-scan) is Copyright (C) 2003-2005 Roy Hills,
 * NTA Monitor Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * If this license is unacceptable to you, I may be willing to negotiate
 * alternative licenses (contact ike-scan@nta-monitor.com).
 *
 * You are encouraged to send comments, improvements or suggestions to
 * me at ike-scan@nta-monitor.com.
 *
 * $Id: check-sizes.c,v 1.1.1.1 2005/01/13 18:45:14 mcr Exp $
 *
 * check-sizes -- Check sizes of structures and types
 *
 * Author:	Roy Hills
 * Date:	30 December 2003
 *
 *      Check that the sizes of the various structs are what we expect them
 *      to be.  If they are not, then we return with a failure status.
 *
 *      There are several places in the ike-scan code where we copy structs
 *      to character arrays and vice versa.  E.g. send_packet().
 *
 *      Although this is not condoned in C, it is OK in practice
 *      providing that the sizes of the fields is correct and there is no
 *      padding between fields (e.g. for alignment purposes).  This function
 *      checks for both of these problems.
 */

#include "ike-scan.h"

#define EXPECTED_ISAKMP_HDR 28
#define EXPECTED_ISAKMP_SA 12
#define EXPECTED_ISAKMP_PROPOSAL 8
#define EXPECTED_ISAKMP_TRANSFORM 8
#define EXPECTED_ISAKMP_VID 4
#define EXPECTED_ISAKMP_NOTIFICATION 12
#define EXPECTED_ISAKMP_KX 4
#define EXPECTED_ISAKMP_NONCE 4
#define EXPECTED_ISAKMP_ID 8

#define EXPECTED_UINT8_T 1
#define EXPECTED_UINT16_T 2
#define EXPECTED_UINT32_T 4

int main()
{
	unsigned octets_per_char; /* Almost always 1 */
	int error = 0;

	if (CHAR_BIT % 8)
		err_msg("CHAR_BIT is not a multiple of 8");

	octets_per_char = CHAR_BIT / 8;

	printf("Structure\t\tExpect\tObserved\n\n");

	printf("isakmp_hdr\t\t%u\t%lu\t", EXPECTED_ISAKMP_HDR,
	       (unsigned long) (octets_per_char * sizeof(struct isakmp_hdr)));
	if (octets_per_char * sizeof(struct isakmp_hdr) !=
	    EXPECTED_ISAKMP_HDR) {
		error++;
		printf("ERROR\n");
	} else {
		printf("ok\n");
	}

	printf("isakmp_sa\t\t%u\t%lu\t", EXPECTED_ISAKMP_SA,
	       (unsigned long) (octets_per_char * sizeof(struct isakmp_sa)));
	if (octets_per_char * sizeof(struct isakmp_sa) != EXPECTED_ISAKMP_SA) {
		error++;
		printf("ERROR\n");
	} else {
		printf("ok\n");
	}

	printf("isakmp_proposal\t\t%u\t%lu\t", EXPECTED_ISAKMP_PROPOSAL,
	       (unsigned long) (octets_per_char *
				sizeof(struct isakmp_proposal)));
	if (octets_per_char * sizeof(struct isakmp_proposal) !=
	    EXPECTED_ISAKMP_PROPOSAL) {
		error++;
		printf("ERROR\n");
	} else {
		printf("ok\n");
	}

	printf("isakmp_transform\t%u\t%lu\t", EXPECTED_ISAKMP_TRANSFORM,
	       (unsigned long) (octets_per_char *
				sizeof(struct isakmp_transform)));
	if (octets_per_char * sizeof(struct isakmp_transform) !=
	    EXPECTED_ISAKMP_TRANSFORM) {
		error++;
		printf("ERROR\n");
	} else {
		printf("ok\n");
	}

	printf("isakmp_vid\t\t%u\t%lu\t", EXPECTED_ISAKMP_VID,
	       (unsigned long) (octets_per_char * sizeof(struct isakmp_vid)));
	if (octets_per_char * sizeof(struct isakmp_vid) !=
	    EXPECTED_ISAKMP_VID) {
		error++;
		printf("ERROR\n");
	} else {
		printf("ok\n");
	}

	printf("isakmp_notification\t%u\t%lu\t", EXPECTED_ISAKMP_NOTIFICATION,
	       (unsigned long) (octets_per_char *
				sizeof(struct isakmp_notification)));
	if (octets_per_char * sizeof(struct isakmp_notification) !=
	    EXPECTED_ISAKMP_NOTIFICATION) {
		error++;
		printf("ERROR\n");
	} else {
		printf("ok\n");
	}

	printf("isakmp_kx\t\t%u\t%lu\t", EXPECTED_ISAKMP_KX,
	       (unsigned long) (octets_per_char * sizeof(struct isakmp_kx)));
	if (octets_per_char * sizeof(struct isakmp_kx) != EXPECTED_ISAKMP_KX) {
		error++;
		printf("ERROR\n");
	} else {
		printf("ok\n");
	}

	printf("isakmp_nonce\t\t%u\t%lu\t", EXPECTED_ISAKMP_NONCE,
	       (unsigned long) (octets_per_char *
				sizeof(struct isakmp_nonce)));
	if (octets_per_char * sizeof(struct isakmp_nonce) !=
	    EXPECTED_ISAKMP_NONCE) {
		error++;
		printf("ERROR\n");
	} else {
		printf("ok\n");
	}

	printf("isakmp_id\t\t%u\t%lu\t", EXPECTED_ISAKMP_ID,
	       (unsigned long) (octets_per_char * sizeof(struct isakmp_id)));
	if (octets_per_char * sizeof(struct isakmp_id) != EXPECTED_ISAKMP_ID) {
		error++;
		printf("ERROR\n");
	} else {
		printf("ok\n");
	}

	printf("\nType\t\t\tExpect\tObserved\n\n");

	printf("uint8_t\t\t\t%u\t%lu\t", EXPECTED_UINT8_T,
	       (unsigned long) (octets_per_char * sizeof(uint8_t)));
	if (octets_per_char * sizeof(uint8_t) != EXPECTED_UINT8_T) {
		error++;
		printf("ERROR\n");
	} else {
		printf("ok\n");
	}

	printf("uint16_t\t\t%u\t%lu\t", EXPECTED_UINT16_T,
	       (unsigned long) (octets_per_char * sizeof(uint16_t)));
	if (octets_per_char * sizeof(uint16_t) != EXPECTED_UINT16_T) {
		error++;
		printf("ERROR\n");
	} else {
		printf("ok\n");
	}

	printf("uint32_t\t\t%u\t%lu\t", EXPECTED_UINT32_T,
	       (unsigned long) (octets_per_char * sizeof(uint32_t)));
	if (octets_per_char * sizeof(uint32_t) != EXPECTED_UINT32_T) {
		error++;
		printf("ERROR\n");
	} else {
		printf("ok\n");
	}

	if (error)
		return EXIT_FAILURE;
	else
		return EXIT_SUCCESS;
}
