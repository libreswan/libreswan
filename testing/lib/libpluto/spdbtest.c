#define LEAK_DETECTIVE
#define PRINT_SA_DEBUG 1
#include "../../programs/pluto/spdb.c"

char *progname;

void exit_tool(int stat)
{
	exit(stat);
}

main(int argc, char *argv[]){
	int i;
	struct db_sa *sa1 = NULL;
	struct db_sa *sa2 = NULL;

	progname = argv[0];
	leak_detective = 1;

	tool_init_log();

	for (i = 0; i < elemsof(oakley_sadb); i++) {
		printf("\nmain mode oakley: %u\n", i);
		sa_print(&oakley_sadb[i]);
		sa1 = sa_copy_sa(&oakley_sadb[i]);

		free_sa(&sa2);
		sa2 = sa_copy_sa(sa1);
		free_sa(&sa1);

		printf("copy 2\n");
		sa_print(sa2);
	}

	for (i = 0; i < elemsof(oakley_am_sadb); i++) {
		printf("\naggr mode oakley: %u\n", i);
		sa_print(&oakley_am_sadb[i]);
		sa1 = sa_copy_sa(&oakley_am_sadb[i]);

		free_sa(&sa2);
		sa2 = sa_copy_sa(sa1);
		free_sa(&sa1);

		printf("copy 2\n");
		sa_print(sa2);
	}

	free_sa(&sa2);

	report_leaks();
	tool_close_log();
	exit(0);
}
