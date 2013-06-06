void get_rnd_bytes(u_char *buffer, int length)
{
	int i;

	for (i = 0; i < length; i++)
		buffer[i] = i;
}

u_char secret_of_the_day[SHA1_DIGEST_SIZE] = "abcdabcdabcd";
u_char ikev2_secret_of_the_day[SHA1_DIGEST_SIZE] = "abcdabcdabcd";

void init_secret(void)
{

}
