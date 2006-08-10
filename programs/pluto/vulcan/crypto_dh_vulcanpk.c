#include "vulcan/vulcanpk_funcs.c"

/**
 * Compute DH shared secret from our local secret and the peer's public value.
 * 
 * Do this by talking directly to the Vulcan PK accelerator through
 * an mmap()'ing of the registers.
 */
static void
calc_dh_shared_vulcanpk(chunk_t *shared, const chunk_t g
			, const chunk_t *secchunk
			, const struct oakley_group_desc *group)
{
    struct timeval tv0, tv1;
    unsigned long tv_diff;
    unsigned char *mapping = mapvulcanpk();
    struct pkprogram expmodP;
    unsigned char sharedbytes[384];

    memset(&expmodP, 0, sizeof(expModP));

    gettimeofday(&tv0, NULL);

    expModP.valuesLittleEndian = TRUE;

    /* mod exp calculates A^B mod M */

    /*
     * 384 bytes is chunksize, so, set B at
     * 6*64 = 384.
     */

    /* point to peer's calculated g^x */
    expModP.aValues[0]  = g.ptr;
    expModP.aValueLen[0]= g.len;

    /* point to our secret value */
    expModP.aValues[1]  = secchunk->ptr;
    expModP.aValueLen[1]= secchunk->len;

    /* modulus */
    expModP.aValues[4]  = group->raw_modulus.ptr;
    expModP.aValueLen[4]= group->raw_modulus.len;

    /* reciprocal */
    expModP.aValues[5]  = group->rec_modulus.ptr;
    expModP.aValueLen[5]= group->rec_modulus.len;

    expModP.oOffset = 2;  /* B(1) is result */
    expModP.oValue  = sharedbytes;
    expModP.oValue  = sizeof(sharedbytes);

    /* ask to have the exponentiation done now! */

    expModP.pk_program[0]=/* sizes are ModLen=96(*32=3072),
			     EXP_len=1,RED_len=0*/
			(0<<24)|(1<<8)|(96);
    expModP.pk_program[1]=/* opcode 1100=0xC (mod-exp),
			     with A=0, B=1(6),M=4(24)*/
			(1<<18)|(6<<6)|(24<<0);

    execute_pkprogram(&expModP);

    /* recover shared value */
    
    *shared = mpz_to_n(&mp_shared, group->bytes);
    mpz_clear(&mp_shared);

    gettimeofday(&tv1, NULL);
    tv_diff=(tv1.tv_sec  - tv0.tv_sec) * 1000000 + (tv1.tv_usec - tv0.tv_usec);
    DBG(DBG_CRYPT, 
    	DBG_log("calc_dh_shared(): time elapsed (%s): %ld usec"
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

