#define LEAK_DETECTIVE
#define PRINT_SA_DEBUG 1
#include "../../programs/pluto/spdb.c"

#define AD(x) x, elemsof(x)     /* Array Description */
#define AD_NULL NULL, 0
/*
 * empty structure, for clone use.
 */
static struct db_attr otempty[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, -1 },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM,       -1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, -1 },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,    -1 },
};

static struct db_trans oakley_trans_empty[] = {
	{ AD_TR(KEY_IKE, otempty) },
};

static struct db_prop oakley_pc_empty[] =
{ { AD_PR(PROTO_ISAKMP, oakley_trans_empty) } };

static struct db_prop_conj oakley_props_empty[] =
{ { AD_PC(oakley_pc_empty) } };

char *progname;

void exit_tool(int stat)
{
	exit(stat);
}

main(int argc, char *argv[]){
	int i;
	struct db_sa *sa1 = NULL;

	progname = argv[0];
	leak_detective = 1;

	tool_init_log();

	for (i = 0; i < elemsof(oakley_sadb); i++) {
		/* make sure that leak reports and EFence reports get
		 * placed in the right order.
		 */
		fflush(stdout);
		fflush(stderr);
		printf("\nmain mode oakley: %u\n", i);
		sa_print(&oakley_sadb[i]);
		sa1 = sa_copy_sa_first(&oakley_sadb[i]);

		sa_print(sa1);

		free_sa(&sa1);

		fflush(stdout);
		report_leaks();
	}

	tool_close_log();
	exit(0);
}
