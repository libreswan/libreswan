#define LEAK_DETECTIVE
#define AGGRESSIVE 1
#define XAUTH 1
#define PRINT_SA_DEBUG 1
#include <stdlib.h>
#include "openswan.h"
#include "constants.h"
#include "defs.h"
#include "state.h"
#include "plutoalg.h"
#include "spdb.h"
#include "ike_alg.h"

char *progname;

bool can_do_IPcomp = TRUE;  

void exit_log(const char *msg, ...)
{
    abort();
}

struct state *
state_with_serialno(so_serial_t sn)
{
    abort();
    return NULL;
}

void whack_log(int rc, const char *msg, ...)
{
    abort();
}

void exit_tool(int stat)
{
    exit(stat);
}

const chunk_t *
get_preshared_secret(const struct connection *c)
{
    abort();
    return NULL;
}

struct spd_route;
ipsec_spi_t
get_my_cpi(struct spd_route *sr, bool tunnel)
{
    return 10;
}

ipsec_spi_t
get_ipsec_spi(ipsec_spi_t avoid, int proto, struct spd_route *sr, bool tunnel)
{
    return 10;
}

ipsec_spi_t
uniquify_his_cpi(ipsec_spi_t cpi, struct state *st)
{
    return 12;
}

const char *
ip_str(const ip_address *src)
{
    static char buf[ADDRTOT_BUF];

    addrtot(src, 0, buf, sizeof(buf));
    return buf;
}

main(int argc, char *argv[])
{
    int i;
    struct db_sa *gsp = NULL;
    struct db_sa *sa1 = NULL;
    struct db_sa *sa2 = NULL;
    struct alg_info_ike *aii;
    err_t ugh;

    progname = argv[0];

    tool_init_log();
    init_crypto();
    
    aii = alg_info_ike_create_from_str("3des", &ugh);

    gsp = oakley_alg_makedb(aii
			    , &oakley_sadb[POLICY_RSASIG >> POLICY_ISAKMP_SHIFT]
			    , -1);

    sa_print(gsp);

    tool_close_log();
    exit(0);
}

/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * End:
 */
