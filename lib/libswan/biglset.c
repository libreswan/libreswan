/*
 * support for larger bit fields
 * Copyright (C) 2005  Michael Richardson <mcr@xelerance.com>
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/lgpl.txt>.
 * 
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 */
#include "internal.h"
#include "libreswan.h"
#include "constants.h"
#include "biglset.h"
#include "oswlog.h"

void biglset_format(char *buf, size_t blen, biglset_t b)
{
    int i,j;
    char sep='{';

    buf[0]='{'; buf[1]='\0'; 
    blen-=2; /* reserve space for } */

    for(i=0; i<BLMULTI; i++) {
	int base=(i<<BLSHIFT);
	for(j=0; j<(1 << BLSHIFT); j++) {
	    if(LHAS(b.lsts[i],j)) {
		int len = snprintf(buf, blen, "%c%d", sep, base+j);
		buf += len;
		blen-= len;
		sep=',';
	    }
	}
    }

    strcat(buf, "}");
}

/*
 * all routines are actually inline, but we still need a place for
 * the testing code.
 */
#ifdef BIGLSET_MAIN

int bits1_on[]={1,4,12,23,45,63,64,65,67,77,90,127,128,129,510,511,512,513};
char bits1_on_out[]="{1,4,12,23,45,63,64,65,67,77,90,127,128,129,510,511}";

int bits2_off[]={1,9,12,45,64,67,90,49,128,510,512,513};
char bits2_off_out[]="{1,9,12,45,49,64,67,90,128,510}";
char bits2_int_out[]="{1,12,45,64,67,90,128,510}";

int bits3_on[]={127,128,129,510,511,512,513};
char bits3_off_out[]="";

main()
{
    biglset_t a = BLEMPTY;
    biglset_t a2 = BLEMPTY;
    int i, fails=0;
    char out[512];

    for(i=0; i< elemsof(bits1_on); i++) {
	biglset_t d = BLUNION(a, BLELEM(bits1_on[i]));
	a = d;
    }
    biglset_format(out, 512, a);
    if(strcmp(out, bits1_on_out)!=0) {
	printf("1 failure: %s <=> %s \n", out, bits1_on_out);
	fails++;
    }
    for(i=0; i< elemsof(bits2_off); i++) {
	biglset_t d = BLUNION(a2, BLELEM(bits2_off[i]));
	a2 = d;
    }
    biglset_format(out, 512, a2);
    if(strcmp(out, bits2_off_out)!=0) {
	printf("2 failure: %s <=> %s \n", out, bits2_off_out);
	fails++;
    }

    {
	biglset_t o = BLINTERSECT(a, a2);

	biglset_format(out, 512, o);
	if(strcmp(out, bits2_int_out)!=0) {
	    printf("3 failure: %s <=> %s \n", out, bits2_int_out);
	    fails++;
	}
    }

    exit(fails);
}
#endif

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */

