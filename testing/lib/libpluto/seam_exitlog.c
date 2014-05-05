/* LINK seams */
void lsw_abort()
{
	exit(1);
}

void exit_log(const char *msg, ...)
{
	fprintf(stderr,msg);
	exit(1);
}

void exit_tool(int status)
{
	exit(status);
}

void exit_pluto(int status)
{
	exit(status);
}

