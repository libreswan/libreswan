#define LEAK_DETECTIVE
#define DEBUG 1
#define PRINT_SA_DEBUG 1
#define USE_KEYRR 1

#include "constants.h"
#include "lswalloc.h"
#include "whack.h"
#include "../../programs/pluto/rcv_whack.h"

#include "../../programs/pluto/connections.c"

#include "whackmsgtestlib.c"
#include "seam_vendor.c"
#include "seam_pending.c"
#include "seam_ikev1.c"
#include "seam_crypt.c"
#include "seam_kernel.c"
#include "seam_rnd.c"
#include "seam_log.c"
#include "seam_xauth.c"
#include "seam_west.c"
#include "seam_initiate.c"
#include "seam_terminate.c"
#include "seam_x509.c"
#include "seam_spdbstruct.c"
#include "seam_demux.c"
#include "seam_whack.c"
#include "seam_keys.c"
#include "seam_exitlog.c"
#include "seam_natt.c"
#include "seam_dpd.c"

u_int8_t reply_buffer[MAX_OUTPUT_UDP_SIZE];

#include "seam_gi_sha1.c"

#include "ikev2sendI1.c"

extern unsigned int maximum_retransmissions_initial;

main(int argc, char *argv[]){
	int len;
	char *infile;
	char *conn_name;
	int lineno = 0;
	struct connection *c1;
	struct state *st;

	EF_PROTECT_FREE = 1;
	EF_FREE_WIPES  = 1;

	progname = argv[0];
	leak_detective = 1;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s <whackrecord> <conn-name>\n",
			progname);
		exit(10);
	}
	/* argv[1] == "-r" */

	tool_init_log();
	init_fake_vendorid();

	infile = argv[1];
	conn_name = argv[2];

	readwhackmsg(infile);

	send_packet_setup_pcap("parentI1.pcap");

	c1 = con_by_name(conn_name, TRUE);
	c1->sa_keying_tries = 0; /* for this test case, make retries infinite */
	maximum_retransmissions_initial = 2;

	show_one_connection(c1);

	st = sendI1(c1,
		    DBG_EMITTING | DBG_CONTROL | DBG_CONTROLMORE |
		    DBG_WHACKWATCH);

	run_continuation(r);

	/* after three-retransmits, we fallback to trying IKEv1, if necessary */
	handle_next_timer_event();
	run_continuation(r);
	handle_next_timer_event();
	run_continuation(r);
	handle_next_timer_event();
	run_continuation(r);
	handle_next_timer_event();
	run_continuation(r);
	handle_next_timer_event();
	run_continuation(r);
	handle_next_timer_event();
	run_continuation(r);
	handle_next_timer_event();
	run_continuation(r);
	handle_next_timer_event();
	run_continuation(r);
	handle_next_timer_event();
	run_continuation(r);

	/* after three more retransmits, we go back to IKEv2 */
	handle_next_timer_event();
	run_continuation(r);
	handle_next_timer_event();
	run_continuation(r);
	handle_next_timer_event();
	run_continuation(r);

	/* as the state will have been renewed, it's hard to clean up */
	report_leaks();

	tool_close_log();
	exit(0);
}
