/*
 * PARENT R2 test case actually invokes the parent R1 test case
 * to get all of the states into the right order.
 *
 */

#define LEAK_DETECTIVE
#define DEBUG 1
#define PRINT_SA_DEBUG 1
#define USE_KEYRR 1

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include "constants.h"
#include "lswalloc.h"
#include "whack.h"
#include "../../programs/pluto/rcv_whack.h"

#include "../../programs/pluto/connections.c"

#include "whackmsgtestlib.c"
#include "seam_timer.c"
#include "seam_vendor.c"
#include "seam_pending.c"
#include "seam_ikev1.c"
#include "seam_crypt.c"
#include "seam_kernel.c"
#include "seam_rnd.c"
#include "seam_log.c"
#include "seam_xauth.c"
#include "seam_east.c"
#include "seam_initiate.c"
#include "seam_terminate.c"
#include "seam_spdbstruct.c"
#include "seam_demux.c"
#include "seam_whack.c"
#include "seam_natt.c"
#include "seam_exitlog.c"
#include "seam_gi_sha1.c"
#include "seam_kernelalgs.c"
#include "seam_dns.c"
#include "seam_connections.c"
#include "seam_defs.c"
#include "seam_oscp.c"

#include "seam_commhandle.c"

#include "seam_recv1r.c"

void recv_pcap_packet2(u_char *user,
		       const struct pcap_pkthdr *h,
		       const u_char *bytes)
{
	struct state *st;
	struct pcr_kenonce *kn = &r->pcr_d.kn;

	recv_pcap_packet_gen(user, h, bytes);

	/* find st involved */
	st = state_with_serialno(1);
	st->st_connection->extra_debugging = DBG_PRIVATE | DBG_CRYPT |
					     DBG_PARSING | DBG_EMITTING |
					     DBG_CONTROL | DBG_CONTROLMORE;

	run_continuation(r);

}

deltatime_t crl_check_interval = { 0 };

main(int argc, char *argv[]){
	int len;
	char *infile;
	char *conn_name;
	int lineno = 0;
	struct connection *c1;
	pcap_t *pt;
	char eb1[256];

	EF_PROTECT_BELOW = 1;
	EF_PROTECT_FREE = 1;
	EF_FREE_WIPES  = 1;

	progname = argv[0];
	printf("Started %s\n", progname);

	leak_detective = 1;

	/* not sure if these works all case east.crt should be in cwd */
	pluto_shared_secrets_file =
		"../../../baseconfigs/east/etc/ipsec.secrets";
	lsw_init_ipsecdir("../../../baseconfigs/east/etc/ipsec.d");
	lsw_init_rootdir("../../../baseconfigs/east");

	init_crypto();
	init_seam_kernelalgs();

	load_authcerts("CA cert",
		       "../../../baseconfigs/east/etc/ipsec.d/cacerts",
		       AUTH_CA);

	if (argc != 4) {
		fprintf(stderr,
			"Usage: %s <whackrecord> <conn-name> <pcapin>\n",
			progname);
		exit(10);
	}
	/* argv[1] == "-r" */

	tool_init_log();
	init_fake_vendorid();

	infile = argv[1];
	conn_name = argv[2];

	readwhackmsg(infile);

	send_packet_setup_pcap("parentR2x509.pcap");
	pt = pcap_open_offline(argv[3], eb1);
	if (!pt) {
		perror(argv[3]);
		exit(50);
	}

	c1 = con_by_name(conn_name, TRUE);
	show_one_connection(c1);

	pt = pcap_open_offline(argv[3], eb1);

	cur_debugging = DBG_EMITTING | DBG_CONTROL | DBG_CONTROLMORE;
	/* process first packet */
	pcap_dispatch(pt, 1, recv_pcap_packet1, NULL);

	/* process second packet */
	pcap_dispatch(pt, 1, recv_pcap_packet2, NULL);

	{
		struct state *st;

		/* find st involved */
		st = state_with_serialno(1);
		delete_state(st);
	}

	report_leaks();

	tool_close_log();
	exit(0);
}
