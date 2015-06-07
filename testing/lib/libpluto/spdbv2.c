#define LEAK_DETECTIVE
#define PRINT_SA_DEBUG 1
#include <stdlib.h>
#include "libreswan.h"
#include "constants.h"
#include "defs.h"
#include "state.h"
#include "alg_info.h"
#include "plutoalg.h"
#include "spdb.h"
#include "ike_alg.h"

#include "seam_exitlog.c"

#include "efencedef.h"

char *progname;

bool can_do_IPcomp = TRUE;

struct state *state_with_serialno(so_serial_t sn)
{
	lsw_abort();
	return NULL;
}

void whack_log(int rc, const char *msg, ...)
{
	lsw_abort();
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

main(int argc, char *argv[]){
	int i;
	struct db_sa *gsp = NULL;
	struct db_sa *sa1 = NULL;
	struct db_sa *sa2 = NULL;
	struct alg_info_ike *aii;
	char err_buf[256];	/* ??? big enough? */

	EF_PROTECT_FREE = 1;
	EF_FREE_WIPES  = 1;

	progname = argv[0];
	leak_detective = 1;

	tool_init_log();
	init_crypto();

	aii = alg_info_ike_create_from_str("3des", err_buf, sizeof(err_buf));

	gsp = oakley_alg_makedb(aii,
				&oakley_sadb[POLICY_RSASIG >>
					     POLICY_ISAKMP_SHIFT],
				FALSE);
	sa_print(gsp);

	sa_v2_convert(&gsp);

	sa_v2_print(gsp);

	tool_close_log();

	free_sa(&gsp);
	exit(0);
}
