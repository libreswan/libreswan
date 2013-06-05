/* log.c SEAM */
void close_peerlog(void)
{
}
void daily_log_reset(void)
{
}
const ip_address *cur_from = NULL;      /* source of current current message */
u_int16_t cur_from_port;                /* host order */

struct state *cur_state = NULL;         /* current state, for diagnostics */

void extra_debugging(const struct connection *c)
{
	set_debugging(cur_debugging | c->extra_debugging);
}

void pexpect_log(const char *pred_str, const char *file_str,
		 unsigned long line_no)
{
	/* we will get a possibly unplanned prefix.  Hope it works */
	loglog(RC_LOG_SERIOUS, "EXPECTATION FAILED at %s:%lu: %s", file_str,
	       line_no, pred_str);
}

void daily_log_event(void)
{
}

