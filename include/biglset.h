#ifndef _BIGLSET_H
#define _BIGLSET_H 

#include <libreswan/passert.h>
/* set type with room for at least 64*8 = 512 options */
#define BLMULTI 8
typedef struct { lset_t lsts[BLMULTI]; } biglset_t;
#define BLEMPTY { {LEMPTY,LEMPTY,LEMPTY,LEMPTY,LEMPTY,LEMPTY,LEMPTY,LEMPTY}}
#define BLSHIFT 6
#define BLMASK  ((1ULL << BLSHIFT)-1)

static inline biglset_t BLELEM(int opt)
{
    biglset_t b = BLEMPTY;
    int which = opt >> BLSHIFT;  /* 2^6 = 64bits/long long */
    if(which < BLMULTI) {
	b.lsts[which] = LELEM(opt & BLMASK);
    }
    return b;
}

static inline biglset_t BLUNION(biglset_t set, biglset_t add)
{
    int i;
    for(i=0; i<BLMULTI; i++) {
	set.lsts[i] = set.lsts[i] | add.lsts[i];
    }
    return set;
}  

static inline biglset_t BLINTERSECT(biglset_t set, biglset_t sub)
{
    int i;
    for(i=0; i<BLMULTI; i++) {
	set.lsts[i] = set.lsts[i] & sub.lsts[i];
    }
    return set;
}  

/* this is definitely sub-optimal, but that's tough for now */
static inline biglset_t BLRANGE(int lwb, int upb)
{
    biglset_t r = BLEMPTY;
    int i;
    for(i=lwb; i<=upb; i++) {
	BLUNION(r, BLELEM(i));
    }
    return r;
}

static inline bool BLCHECK(biglset_t b, int elem)
{
    int which = elem >> BLSHIFT;
    return b.lsts[which]&LELEM(elem & BLMASK);
}

extern void biglset_format(char *buf, size_t blen, biglset_t b);

#endif /* _BIGLSET_H */
