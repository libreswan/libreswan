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
#include "kernel_alg.h"

#include "efencedef.h"

char *progname;

bool can_do_IPcomp = TRUE;

void exit_log(const char *msg, ...)
{
	lsw_abort();
}

struct state *state_with_serialno(so_serial_t sn)
{
	lsw_abort();
	return NULL;
}

void whack_log(int rc, const char *msg, ...)
{
	lsw_abort();
}

void exit_tool(int stat)
{
	exit(stat);
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

main(int argc, char *argv[]) {
	int i;
	struct db_sa *gsp = NULL;
	struct db_sa *sa1 = NULL;
	struct db_sa *sa2 = NULL;
	struct alg_info_esp *aii;
	char err_buf[100];

	EF_PROTECT_FREE = 1;
	EF_FREE_WIPES  = 1;
	EF_PROTECT_BELOW = 1;

	progname = argv[0];
	leak_detective = 1;

	tool_init_log();
	init_crypto();

	{
		int algo;
		for (algo = 1; algo <= K_SADB_EALG_MAX; algo++)
			esp_ealg[(algo)].sadb_alg_id = (algo);
	}
	{
		int algo;
		for (algo = 1; algo <= K_SADB_AALG_MAX; algo++)
			esp_aalg[(algo)].sadb_alg_id = (algo);
	}
	esp_ealg_num = 10;
	esp_aalg_num = 10;

	aii = alg_info_esp_create_from_str("aes128-sha1", &err_buf, sizeof(err_buf));

	gsp = kernel_alg_makedb(POLICY_ENCRYPT | POLICY_AUTHENTICATE,
				aii,
				TRUE);
	sa_print(gsp);

	sa_v2_convert(&gsp);

	sa_v2_print(gsp);

	tool_close_log();

	free_sa(&gsp);
	exit(0);
}
