/* TCL Pluto Mix (TPM)
 * Copyright (C) 2005 Michael C. Richardson <mcr@xelerance.com.
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
 */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#include <libreswan.h>
#include <errno.h>

#include <tcl.h>
#include "lswlog.h"
#include "lswalloc.h"
#include "tpm.h"
#include "tpm_int.h"
#include "paths.h"
#include "packet.h"

int pbs_peek(pb_stream *pbs, int offset)
{
    if(offset < pbs_room(pbs)) {
	return pbs->start[offset];
    } else {
	return 0;
    }
}

void pbs_poke(pb_stream *pbs, int offset, int value)
{
    if(offset < pbs_room(pbs)) {
	pbs->start[offset] = value;

	if(pbs->cur < pbs->start + offset) {
	    pbs->cur = pbs->start + offset;
	}
    } else {
	libreswan_log("pbs_peek offset:%d < pbs_room(pbs):%d", offset, pbs_room(pbs));
	pexpect(offset < pbs_room(pbs));
    }
}

/*    %cstring_output_maxsize(char *outx, int *max) */

void pbs_bytes(pb_stream *pbs, char *out, int *max)
{
    if(max) {
	if(*max > pbs_offset(pbs)) {
	    *max = pbs_offset(pbs);
	}
    }
    memcpy(out, pbs->start, *max);
}

int pbs_offset_get(pb_stream *pbs) {
    return pbs_offset(pbs);
}

int pbs_room_get(pb_stream *pbs) {
    return pbs_room(pbs);
}

int pbs_left_get(pb_stream *pbs) {
    return pbs_left(pbs);
}

int pbs_append(pb_stream *dest, int destoffset
		, pb_stream *src, int offset, int length)
{
    /* -1 means end of destination stream */
    if(destoffset == -1) {
	destoffset = pbs_offset(dest);
    }

    if(destoffset > pbs_room(dest) ||
       destoffset + length > pbs_room(dest)) {
	return 0;
    }
    
    if(offset > pbs_room(src) ||
       offset + length > pbs_room(src)) {
	return 0;
    }

    memcpy(&dest->start[destoffset], &src->start[offset], length);

    if(dest->cur < (dest->start + destoffset + length)) {
	dest->cur = dest->start + (destoffset + length);
    }
}
 
pb_stream *pbs_create(int size)
{
    pb_stream *n;
    void *mem;

    n = alloc_thing(*n, "pbs_create");
    mem=alloc_bytes(size, "pbs_memory");
    init_pbs(n, mem, size, "tpm_pbs");

    return n;
}      

void pbs_delete(pb_stream *pbs)
{
    pfree(pbs->start);
    pfree(pbs);
}

void pbs_free(pb_stream *pbs)
{
    free(pbs);
}

/*
 * walk through the PBS (containing an IKEv1 message) and find the
 * location of the hash space.
 */
void tpm_findID(struct packet_byte_stream *pbs, pb_stream *idpbs)
{
    unsigned char *load;
    void *here;
    int payload, np;
    int paylen;

    /* 28 is size of isakmphdr */
    load = pbs->start + 28;
    payload = pbs->start[16];

    while(payload != 0 && load < pbs->cur) {
	np     = load[0];
	paylen = load[2]*256 + load[3];
	here   = &load[4];
	
	if(payload == ISAKMP_NEXT_ID) {
	    idpbs->start = load;
	    idpbs->cur = (load + paylen);
	    idpbs->roof = (load+ paylen);
	    return;
	}
	
	payload = np;
	load = load + paylen;
	passert(load >= pbs->start && load <= pbs->cur);
    }

    return;
}
	
/*
 * walk through the PBS (containing an IKEv1 message) and find the
 * location of the hash space.
 */
void *tpm_relocateHash(struct packet_byte_stream *pbs)
{
    unsigned char *load;
    void *here;
    int payload, np;
    int paylen;

    /* 28 is size of isakmphdr */
    load = pbs->start + 28;
    payload = pbs->start[16];

    while(payload != 0 && load < pbs->cur) {
	np     = load[0];
	paylen = load[2]*256 + load[3];
	here   = &load[4];
	
	if(payload == ISAKMP_NEXT_HASH) {
	    return here;
	}
	
	payload = np;
	load = load + paylen;
	passert(load >= pbs->start && load <= pbs->cur);
    }

    /* probably going to fail after this */
    return NULL;
}
	
