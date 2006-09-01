/*
 * process a pcap file and adjust nonce, KE and ID=IPv4
 *
 * Copyright (C) 2006 Michael Richardson <mcr@xelerance.com>
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
 *
 * RCSID $Id: ikeping.c,v 1.13 2005/07/08 02:56:38 paul Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <assert.h>
#include <poll.h>

#include <openswan.h>
#include <pcap.h>

#include "pfkeyv2.h"

#include "constants.h"
#include "packet.h"

#include "natt_defines.h"
#include "hexdump.c"

unsigned int csum_partial(const unsigned char * buff, int len, unsigned int sum);

static inline unsigned int csum_fold(unsigned int sum)
{
	__asm__(
		"addl %1, %0		;\n"
		"adcl $0xffff, %0	;\n"
		: "=r" (sum)
		: "r" (sum << 16), "0" (sum & 0xffff0000)
	);
	return (~sum) >> 16;
}

static inline unsigned long csum_tcpudp_nofold(unsigned long saddr,
						   unsigned long daddr,
						   unsigned short len,
						   unsigned short proto,
						   unsigned int sum)
{
    __asm__(
	"addl %1, %0	;\n"
	"adcl %2, %0	;\n"
	"adcl %3, %0	;\n"
	"adcl $0, %0	;\n"
	: "=r" (sum)
	: "g" (daddr), "g"(saddr), "g"((ntohs(len)<<16)+proto*256), "0"(sum));
    return sum;
}

/*
 * computes the checksum of the TCP/UDP pseudo-header
 * returns a 16-bit checksum, already complemented
 */
static inline unsigned short int csum_tcpudp_magic(unsigned long saddr,
						   unsigned long daddr,
						   unsigned short len,
						   unsigned short proto,
						   unsigned int sum)
{
	return csum_fold(csum_tcpudp_nofold(saddr,daddr,len,proto,sum));
}

/*
 * this routine is used for miscellaneous IP-like checksums, mainly
 * in icmp.c
 */

static inline unsigned short ip_compute_csum(unsigned char * buff, int len)
{
    return csum_fold (csum_partial(buff, len, 0));
}

static void usage(void)
{
    fprintf(stderr,
	"Usage:\n\n"
	"ike-aggr-dos input.pcap output.pcap"
	    "\n"
	"Openswan %s\n",
	ipsec_version_code());
}


/*
 *

0000: 00 e0 81 40  1a ed 00 e0  81 41 4c 80  08 00         <- ethernet
                                                   45 00   <- IP header
0010: 01 68 55 61  00 00 40 11  8f a7 ac 12  1e 37 ac 12 
0020: 1e 21
            01 f4  01 f4 01 54  c9 67                      <- UDP header
	                              98 6d  39 46 1f 09   <- IKE header
0030: 4b 21                                                <- initiator cookie
            00 00  00 00 00 00  00 00                      <- responder cookie
	                              01 10  04 00         <- various
				                   00 00   <- msg id
0040: 00 00
            00 00  01 4c                                   <- length
	                 04 00  00 38 00 00  00 01 00 00 
0050: 00 01 00 00  00 2c 00 01  00 01 00 00  00 24 00 01 
0060: 00 00 80 0b  00 01 80 0c  0e 10 80 01  00 07 80 02 
0070: 00 02 80 03  00 03 80 04  00 05 80 0e  00 80
                                                   0a 00   <- KE payload
0080: 00 c4
            93 6f  e6 d7 be ae  9f 03 a5 d3  42 e3 26 2e   <- 192 bytes KE ***
0090: a9 36 25 34  b5 81 86 63  85 3f 96 95  e2 f1 9c 0f 
00a0: 07 e4 09 f8  5d 3b 30 dd  55 39 81 bd  f0 7e e7 07 
00b0: db 92 fc 7c  46 82 df a3  37 e9 ba 22  24 49 0f 61 
00c0: dc 4e b1 f2  83 b1 34 c9  f5 04 df ce  75 c9 e8 4d 
00d0: 1d a1 79 de  64 c4 fe 67  21 bd 80 d5  7f ef 3b dd 
00e0: 5a 75 ee 89  35 3c 29 7f  fb 83 32 f0  2f a5 f9 e2 
00f0: 0f 26 9d 07  3e 3b 71 de  ba 0d e1 01  a4 f3 ca fd 
0100: 88 ff a7 46  80 42 55 0a  9c 46 18 b8  da 0e 92 75 
0110: 93 1c e3 28  be 54 f9 d0  e5 f6 3a 0b  d3 7a 07 7b 
0120: af 36 ff d8  19 c6 90 6e  e3 aa a1 9f  8b fd d3 d5 
0130: 9f 13 b4 5f  65 f4 01 2f  ba 5f b0 ea  b5 f9 d2 19 
0140: 3a 5d
            05 00  00 14                                  <- NONCE payload
	                 98 07  7d c4 13 93  cf c4 59 14  <- 16 bytes NONCE
0150: 4c a9 22 e7  10 6b
                         0d 00  00 0c 01 00  00 00        <- ID payload
			                           ac 12  <- 4 bytes IPv4
0160: 1e 37
            00 00  00 14 af ca  d7 13 68 a1  f1 c9 6b 86  <- VID (DPD)
0170: 96 fc 77 57  01 00 00 00 

*/

void molest_ike_params(u_char *user,
		       const struct pcap_pkthdr *h,
		       const u_char *bytes)
{
    static unsigned char molest_index1=0x12;
    static unsigned char molest_index2=0x34;
    unsigned char newbytes[8192];
    unsigned short chksum;

    int i;
    memcpy(newbytes, bytes, h->len);

    for(i=0; i<256; i++) {

	/* HACK the cookie */
	newbytes[0x30] = molest_index1++;
	newbytes[0x31] = molest_index1++;
	
	/* HACK the KE */
	newbytes[0x82] = molest_index1++;
	newbytes[0x82] = molest_index2++;

	/* HACK the NONCE */
	newbytes[0x146] = molest_index2++;
	newbytes[0x149] = molest_index2++;
	
	/* HACK the IPv4 (last octet) */
	//newbytes[0x161] = i;

	/* FIX UDP checksum... to zero. */
	newbytes[0x28]=0;
	newbytes[0x29]=0;
	//chksum = csum_partial(newbytes+0x22, h->len-0x22, 0);

	newbytes[0x28]=chksum >> 8;
	newbytes[0x29]=chksum && 0xff;

	pcap_dump(user, h, newbytes);
    }
}

int
main(int argc, char **argv)
{
	char *filein, *fileout;
	pcap_t         *in;
	pcap_dumper_t *out;
	char errbuf[PCAP_ERRBUF_SIZE];

	if(argc!=3) {
		usage();
		exit(10);
	}
	
	filein  = argv[1];
	fileout = argv[2];

	in  = pcap_open_offline(filein, errbuf);
	out = pcap_dump_open(in, fileout);

	pcap_dispatch(in, -1, molest_ike_params, (u_char *)out);
	
	pcap_dump_close(out);
	pcap_close(in);

	exit(0);
}

/*
 * Local variables:
 * c-file-style: "pluto"
 * c-basic-offset: 4
 * End:
 *
 */
