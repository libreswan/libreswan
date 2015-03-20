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
#include "seam_x509.c"
#include "seam_spdbstruct.c"
#include "seam_demux.c"
#include "seam_whack.c"
#include "seam_natt.c"
#include "seam_keys.c"
#include "seam_exitlog.c"
#include "seam_gi_sha1.c"

#include "seam_commhandle.c"

void recv_pcap_packet(u_char *user,
		      const struct pcap_pkthdr *h,
		      const u_char *bytes)
{
	struct state *st;
	struct pcr_kenonce *kn = &r->pcr_d.kn;

	recv_pcap_packet_gen(user, h, bytes);

	/* find st involved */
	st = state_with_serialno(1);
	st->st_connection->extra_debugging = DBG_EMITTING | DBG_CONTROL |
					     DBG_CONTROLMORE;

	run_continuation(r);
}

main(int argc, char *argv[]){
	int len;
	char *infile;
	char *outfile;
	char *conn_name;
	int lineno = 0;
	struct connection *c1;
	pcap_t *pt;
	char eb1[256];

	EF_PROTECT_BELOW = 1;
	EF_PROTECT_FREE = 1;
	EF_FREE_WIPES  = 1;

	progname = argv[0];
	leak_detective = 1;

	init_crypto();

	if (argc != 5) {
		fprintf(stderr,
			"Usage: %s <whackrecord> <conn-name> <pcapin> <pcpout>\n",
			progname);
		exit(10);
	}
	/* argv[1] == "-r" */

	tool_init_log();
	init_fake_vendorid();

	infile = argv[1];
	conn_name = argv[2];
	outfile = argv[4];

	readwhackmsg(infile);
	force_busy = TRUE;
	send_packet_setup_pcap(outfile);

	c1 = con_by_name(conn_name, TRUE);

	show_one_connection(c1);

	pt = pcap_open_offline(argv[3], eb1);
	if (!pt) {
		perror(argv[3]);
		exit(50);
	}

	cur_debugging = DBG_PARSING | DBG_EMITTING | DBG_PRIVATE |
			DBG_CONTROL | DBG_CONTROLMORE;
	pcap_dispatch(pt, 1, recv_pcap_packet, NULL);

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
