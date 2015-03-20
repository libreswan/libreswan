#define LEAK_DETECTIVE
#define DEBUG 1
#define PRINT_SA_DEBUG 1
#define USE_KEYRR 1

#include "constants.h"
#include "lswalloc.h"
#include "whack.h"
#include "rcv_whack.h"

#include "../../programs/pluto/connections.c"

#include "whackmsgtestlib.c"
#include "seam_x509.c"
#include "seam_log.c"
#include "seam_timer.c"
#include "seam_state.c"
#include "seam_west.c"
#include "seam_initiate.c"
#include "seam_terminate.c"
#include "seam_xauth.c"
#include "seam_alg.c"
#include "seam_spdb.c"
#include "seam_keys.c"
#include "seam_exitlog.c"
#include "seam_whack.c"
#include "seam_kernel.c"

main(int argc, char *argv[]){
	int len;
	char *infile;

	EF_PROTECT_FREE = 1;
	EF_FREE_WIPES  = 1;

	progname = argv[0];
	leak_detective = 1;

	if (argc > 2 ) {
		fprintf(stderr, "Usage: %s <whackrecord>\n", progname);
		exit(10);
	}
	/* argv[1] == "-r" */

	tool_init_log();

	infile = argv[1];

	readwhackmsg(infile);

	report_leaks();

	tool_close_log();
	exit(0);
}
