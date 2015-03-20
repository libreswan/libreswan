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
#include "seam_x509.c"
#include "seam_timer.c"
#include "seam_ipsecdoi.c"
#include "seam_pending.c"
#include "seam_crypt.c"
#include "seam_kernel.c"
#include "seam_rnd.c"
#include "seam_log.c"
#include "seam_xauth.c"
#include "seam_east.c"
#include "seam_initiate.c"
#include "seam_terminate.c"
#include "seam_alg.c"
#include "seam_keys.c"
#include "seam_exitlog.c"
#include "seam_whack.c"

main(int argc, char *argv[]){
	int len;
	char *infile;
	FILE *idfile;
	char idbuf[256];
	int lineno = 0;

	EF_PROTECT_FREE = 1;
	EF_FREE_WIPES  = 1;

	lsw_init_rootdir("../../../baseconfigs/all");

	progname = argv[0];
	leak_detective = 1;

	if (argc != 3 ) {
		fprintf(stderr, "Usage: %s <whackrecord> <idfile>\n",
			progname);
		exit(10);
	}
	/* argv[1] == "-r" */

	tool_init_log();

	infile = argv[1];

	readwhackmsg(infile);

	idfile = fopen(argv[2], "r");
	if (!idfile) {
		perror(argv[2]);
		exit(11);
	}

	cur_debugging = DBG_CONTROL | DBG_CONTROLMORE;

	while (fgets(idbuf, sizeof(idbuf), idfile) != NULL) {
		struct state *st1;
		struct connection *nc;
		struct id peer_id;
		int aggrmode, initiate;
		char id1[256];

		/* ignore comments */
		if (idbuf[0] == '#')
			continue;

		st1 = new_state();

		sscanf(idbuf, "%s %u %u", id1, &initiate, &aggrmode);

		/* set it to the first connection, there may be only one?? */
		st1->st_connection = connections;
		st1->st_oakley.auth = OAKLEY_RSA_SIG;

		passert(connections != NULL);

		atoid(id1, &peer_id, TRUE);

		nc = refine_host_connection(st1, &peer_id, initiate, aggrmode);

		printf("%u: %s -> conn: %s\n", ++lineno, id1,
		       nc ? nc->name : "<none>");
	}

	report_leaks();

	tool_close_log();
	exit(0);
}
