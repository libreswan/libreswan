/* LINK seams */
void exit_log(const char *msg, ...)
{
    lsw_abort();
}

void exit_tool(int status)
{
    exit(status);
}

void exit_pluto(int status)
{
    exit(status);
}

