void flush_pending_by_state(struct state *st)
{
}
void show_pending_phase2(const struct connection *c, const struct state *st)
{
}

static struct connection *pending_c;
static int pending_whack_sock;
static lset_t pending_policy;

void add_pending(int whack_sock,
		 struct state *isakmp_sa,
		 struct connection *c,
		 lset_t policy,
		 unsigned long try,
		 so_serial_t replacing)
{
	pending_c = c;
	pending_policy = policy;
	pending_whack_sock = whack_sock;
}

void update_pending(struct state *os, struct state *ns)
{
	/* nothing */
}

struct connection *first_pending(const struct state *st, lset_t *policy,
				 int *p_whack_sock)
{

	*policy = pending_policy;
	*p_whack_sock = pending_whack_sock;
	return pending_c;
}

