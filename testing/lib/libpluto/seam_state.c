/* state.c SEAM */
bool states_use_connection(struct connection *c)
{
	return FALSE;
}
void delete_states_by_connection(struct connection *c, bool relations)
{
}
struct state *state_with_serialno(so_serial_t sn)
{
	return NULL;
}
void delete_state(struct state *st)
{
}
void delete_states_by_peer(ip_address *peer)
{
}

u_int16_t pluto_port = 500;             /* Pluto's port */
u_int16_t pluto_nat_float_port = 4500;  /* Pluto's NATT port */

