/*
 * this needs to pretend to satisfy the side-effect of allocating
 * the SPI#s
 */
bool out_sa(pb_stream *outs,
	    struct db_sa *sadb,
	    struct state *st,
	    bool oakley_mode,
	    bool aggressive_mode UNUSED,
	    u_int8_t np)
{
	fprintf(stderr, "need to allocate SPI#\n");
}
