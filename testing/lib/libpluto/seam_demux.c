#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

time_t packet_time = 0;
pcap_dumper_t *packet_save;

void send_packet_setup_pcap(char *file)
{
	pcap_t *pt;

	pt = pcap_open_dead(DLT_NULL, 9000);
	packet_save = pcap_dump_open(pt, file);
}

bool send_packet(struct state *st, const char *where, bool verbose)
{
	u_int8_t *ptr;
	unsigned long len;
	ipstr_buf b;

	ptr = st->st_tpacket.ptr;
	len = (unsigned long) st->st_tpacket.len;

	fprintf(stderr,
		"sending %lu bytes for %s through %s:%d to %s:%u (using #%lu)\n",
		(unsigned long) st->st_tpacket.len,
		where,
		st->st_interface->ip_dev->id_rname,
		st->st_interface->port,
		ipstr(&st->st_remoteaddr, &b),
		st->st_remoteport,
		st->st_serialno);

	DBG_dump(NULL, ptr, len);

	if (packet_save) {
		char buf[9000];
		struct pcap_pkthdr pp;
		struct iphdr  *ip;
		struct udphdr *udp;
		u_int32_t *dlt;
		int caplen = sizeof(struct iphdr) + sizeof(struct udphdr) +
			     len;

		dlt = (u_int32_t*)buf;
		*dlt = PF_INET;

		ip  = (struct iphdr *)&buf[4];
		ip->version = 4;
		ip->ihl     = 5;
		ip->tos     = 0;
		ip->tot_len = htons(caplen);
		ip->id      = 0;
		ip->frag_off = 0;
		ip->ttl     = 64;
		ip->protocol = IPPROTO_UDP;
		ip->check   = 0;
		ip->saddr   = st->st_interface->ip_addr.u.v4.sin_addr.s_addr;
		ip->daddr   = st->st_remoteaddr.u.v4.sin_addr.s_addr;
		udp = (struct udphdr *)&buf[sizeof(struct iphdr) + 4];
		udp->source = htons(500);
		udp->dest   = htons(st->st_remoteport);
		udp->len    = htons(sizeof(struct udphdr) + len);
		udp->check  = 0;

		memcpy(&buf[sizeof(struct iphdr) + sizeof(struct udphdr) + 4],
		       ptr, len);

		packet_time  = packet_time + 86400;
		pp.ts.tv_sec = packet_time;
		pp.ts.tv_usec = 0;
		pp.caplen = caplen + 4;
		pp.len    = caplen + 4;
		pcap_dump((u_char *)packet_save, &pp, buf);
	}
}

bool check_msg_errqueue(const struct iface_port *ifp, short interest)
{
	return TRUE;
}

void complete_state_transition(struct msg_digest **mdp, stf_status result)
{
	fprintf(stderr, "transitioning on result: %s\n",
		enum_name(&stfstatus_name, result));
}
