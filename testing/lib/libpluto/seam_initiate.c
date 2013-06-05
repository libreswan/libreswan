
bool compare_and_swap_interface(struct connection *c, struct iface_port *p)
{
	struct spd_route *sr;

	for (sr = &c->spd; sr; sr = sr->next) {
		for (;; ) {
			/* check if this interface matches this end */
			if (sameaddr(&sr->this.host_addr, &p->ip_addr) &&
			    (kern_interface != NO_KERNEL ||
			     sr->this.host_port == pluto_port)) {
				if (oriented(*c)) {
					if (c->interface->ip_dev ==
					    p->ip_dev) {
						loglog(RC_LOG_SERIOUS,
						       "both sides of \"%s\" are our interface %s!",
						       c->name,
						       p->ip_dev->id_rname);
					} else {
						loglog(RC_LOG_SERIOUS,
						       "two interfaces match \"%s\" (%s, %s)",
						       c->name, c->interface->ip_dev->id_rname,
						       p->ip_dev->id_rname);
					}
					c->interface = NULL;    /* withdraw orientation */
					return FALSE;
				}

				DBG_log("interface \"%s\" matched %s side",
					p->ip_dev->id_rname,
					(sr->this.left ? "left" : "right"));
				c->interface = p;
			}

			/* done with this interface if it doesn't match that end */
			if (!(sameaddr(&sr->that.host_addr, &p->ip_addr) &&
			      (kern_interface != NO_KERNEL ||
			       sr->that.host_port == pluto_port)))
				break;

			/* swap ends and try again.
			 * It is a little tricky to see that this loop will stop.
			 * Only continue if the far side matches.
			 * If both sides match, there is an error-out.
			 */
			{
				struct end t = sr->this;

				sr->this = sr->that;
				sr->that = t;
			}
		}
	}
	return TRUE;
}

bool orient(struct connection *c)
{
	compare_and_swap_interface(c, &if1);

	return TRUE;
}

void connection_check_phase2(void)
{
}

