#define PRINT_SA_DEBUG 1
#include <stdlib.h>
#include "libreswan.h"
#include "constants.h"
#include "defs.h"
#include "state.h"
#include "plutoalg.h"
#include "spdb.h"
#include "ike_alg.h"
#include "alg_info.h"

#include "seam_exitlog.c"
#include "seam_whack.c"


char *progname;

bool can_do_IPcomp = TRUE;

//#include "../../../lib/libswan/lswlog.c"

struct state *state_with_serialno(so_serial_t sn)
{
	lsw_abort();
	return NULL;
}

const chunk_t *get_preshared_secret(const struct connection *c)
{
	lsw_abort();
	return NULL;
}

struct spd_route;
ipsec_spi_t get_my_cpi(struct spd_route *sr, bool tunnel)
{
	return 10;
}

ipsec_spi_t get_ipsec_spi(ipsec_spi_t avoid, int proto, struct spd_route *sr,
			  bool tunnel)
{
	return 10;
}

ipsec_spi_t uniquify_his_cpi(ipsec_spi_t cpi, struct state *st)
{
	return 12;
}

const char *ip_str(const ip_address *src)
{
	static char buf[ADDRTOT_BUF];

	addrtot(src, 0, buf, sizeof(buf));
	return buf;
}

main(int argc, char *argv[]){
	int i;
	struct db_sa *gsp = NULL;
	struct db_sa *sa1 = NULL;
	struct db_sa *sa2 = NULL;
	struct alg_info_ike *aii;
	err_t ugh;

	progname = argv[0];
	leak_detective = 1;

	tool_init_log();
	init_crypto();

	aii = alg_info_ike_create_from_str("3des", &ugh);

	gsp = oakley_alg_makedb(aii,
				&oakley_sadb[POLICY_RSASIG >>
					     POLICY_ISAKMP_SHIFT],
				-1);

	sa_print(gsp);

	tool_close_log();
	exit(0);
}
