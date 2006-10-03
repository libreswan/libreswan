#include "vulcan/vulcanpk_funcs.c"

unsigned char *vulcanpk_mapping = NULL;
bool please_use_vulcan_hack = FALSE;

/**
 * Compute DH shared secret from our local secret and the peer's public value.
 * 
 * Do this by talking directly to the Vulcan PK accelerator through
 * an mmap()'ing of the registers.
 */
void
calc_dh_shared_vulcanpk(chunk_t *shared, const chunk_t g
			, const chunk_t *secchunk
			, const struct oakley_group_desc *group)
{
    struct timeval tv0, tv1;
    unsigned long tv_diff;
    struct pkprogram expModP;
    unsigned char sharedbytes[384];
    int chunksize, modlen, explen;
    int areg,breg,mreg;

    if(group->raw_modulus.len > 384) {
	/* too big for PK engine, use software */
	DBG(DBG_CONTROL, DBG_log("exponent too big (%d), using software\n"
				 , group->raw_modulus.len*8));
	calc_dh_shared_gmp(shared, g, secchunk, group);
	return;
    }

    memset(&expModP, 0, sizeof(expModP));

    gettimeofday(&tv0, NULL);

    expModP.valuesLittleEndian = FALSE;

    /* mod exp calculates A^B mod M */

    /*
     * 384 bytes is chunksize, so, set B at
     * 6*64 = 384.
     */

    /* point to peer's calculated (g^x) */
    areg = 0;
    expModP.aValues[0]  = g.ptr;
    expModP.aValueLen[0]= g.len;

    /* point to our secret value, ^y */
    breg = 1;
    expModP.aValues[1]  = secchunk->ptr;
    expModP.aValueLen[1]= secchunk->len;

    /* need to find exponent length, in bits */
    {
	unsigned char *secval = secchunk->ptr;
	unsigned int seclen   = secchunk->len;

	explen = seclen * 8;
	while(*secval == 0 && seclen > 0) {
	    secval++;
	    seclen--;
	    explen-=8;
	}

	if((*secval & 0x80) == 0) {
	    explen--;

	    if((*secval & 0x40) == 0) {
		explen--;

		if((*secval & 0x20) == 0) {
		    explen--;

		    if((*secval & 0x10) == 0) {
			explen--;

			if((*secval & 0x08) == 0) {
			    explen--;

			    if((*secval & 0x04) == 0) {
				explen--;

				if((*secval & 0x02) == 0) {
				    explen--;

				    if((*secval & 0x01) == 0) {
					explen--;
				    }
				}
			    }
			}
		    }
		}
	    }
	}
    }
    

    /* register 2 is result. */
    /* register 3 is scratch */
       
    /* M = modulus */
    mreg = 4;
    expModP.aValues[4]  = group->raw_modulus.ptr;
    expModP.aValueLen[4]= group->raw_modulus.len;

    /* reciprocal M(1) */
    expModP.aValues[5]  = group->rec_modulus->ptr;
    expModP.aValueLen[5]= group->rec_modulus->len;

    /* registers 6,7,8 is M(2),M(3),M(4), scratch */

    expModP.oOffset = 2;  /* B(1) is result */
    expModP.oValue    = sharedbytes;
    expModP.oValueLen = group->raw_modulus.len;


    /*
     * now figure out appropriate chunksize to use.
     * the chunksize has to be equal to the length of the
     * modulus.
     */

    /* modlen is in units of 32-bits, or 4 bytes */
    modlen = group->raw_modulus.len / 4;

    /* chunksize is units of 64 bytes */
    chunksize = group->raw_modulus.len / 64;
    expModP.chunksize = chunksize;
	

    /* ask to have the exponentiation done now! */
    /* sizes are ModLen=96(*32=3072), EXP_len=1, RED_len=0*/
    expModP.pk_program[0]=(0<<24)|((explen-1)<<8)|(modlen&0x7f);

    /* now that we know the chunksize, we can calculate offsets */
    areg = (areg * chunksize);
    breg = (breg * chunksize);
    mreg = (mreg * chunksize);
	
    expModP.pk_program[1]=/* opcode 1100=0xC (mod-exp),
			     with A=0, B=1(6),M=4(24)*/
	(0xC<<24)|(mreg << 16)|(breg << 8)|(areg << 0);

    expModP.pk_proglen=2;

    execute_pkprogram(vulcanpk_mapping, &expModP);

    /* recover calculated shared value */
    clonetochunk(*shared, sharedbytes, group->raw_modulus.len, "DH shared value");

    gettimeofday(&tv1, NULL);
    tv_diff=(tv1.tv_sec  - tv0.tv_sec) * 1000000 + (tv1.tv_usec - tv0.tv_usec);
    DBG(DBG_CRYPT, 
    	DBG_log("calc_dh_shared_vulcanpk(): time elapsed (%s): %ld usec"
		, enum_show(&oakley_group_names, group->group)
		, tv_diff);
       );
    /* if took more than 200 msec ... */
    if (tv_diff > 200000) {
	loglog(RC_LOG_SERIOUS, "WARNING: calc_dh_shared(): for %s took "
			"%ld usec"
		, enum_show(&oakley_group_names, group->group)
		, tv_diff);
    }

    DBG_cond_dump_chunk(DBG_CRYPT, "DH shared-secret:\n", *shared);
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */

