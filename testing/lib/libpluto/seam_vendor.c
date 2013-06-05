#define PLUTO_VENDORID_SIZE 12

void init_fake_vendorid()
{
	strcpy(pluto_vendorid, "OEplutounit0");
	pluto_vendorid[PLUTO_VENDORID_SIZE] = '\0';
}

