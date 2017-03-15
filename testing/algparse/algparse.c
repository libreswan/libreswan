#define AGGRESSIVE 1
#define PRINT_SA_DEBUG 1
#include "../../../lib/libswan/alg_info.c"

#if 0
/* work in progress */
#include "../../../programs/pluto/plutoalg.c"
#include "../../../programs/pluto/ike_alg.c"
#endif

char *progname;

void exit_tool(int stat)
{
	exit(stat);
}

void do_test(const char *algstr, int ttype) {
	struct alg_info *aie;
	char err_buf[256];	/* ??? big enough? */
	char algbuf[256];

	printf("[%*s] ", 20, algstr);
	switch (ttype) {
	case PROTO_IPSEC_ESP:
		aie = (struct alg_info *)alg_info_esp_create_from_str(
			algstr, err_buf, sizeof(err_buf));
		break;
	case PROTO_IPSEC_AH:
		aie = (struct alg_info *)alg_info_ah_create_from_str(
			algstr, err_buf, sizeof(err_buf));
		break;
#ifdef WORK_IN_PROGRESS
	case PROTO_ISAKMP:
		aie = (struct alg_info *)alg_info_ike_create_from_str(
			algstr, err_buf, sizeof(err_buf));
		break;
#endif
	}
	algbuf[0] = '\0';
	if (aie != NULL)
		alg_info_snprint(algbuf, sizeof(algbuf), aie);
	if (err_buf[0] != '\0') {
		printf("ERROR: alg=%s  error=%s\n", algbuf, err_buf);
	} else {
		passert(aie != NULL);
		printf("   OK: alg=%s\n", algbuf);
	}
	if (aie != NULL)
		alg_info_free(aie);
}

int main(int argc, char *argv[]) {

	progname = argv[0];

	tool_init_log();

	/* esp= */
	fprintf(stdout, "\n---- ESP tests that should succeed ----\n");

	do_test("aes_gcm_a-128-null", PROTO_IPSEC_ESP);
	do_test("3des-sha1;modp1024", PROTO_IPSEC_ESP);
	do_test("3des-sha1;modp1536", PROTO_IPSEC_ESP);
	do_test("3des-sha1;modp2048", PROTO_IPSEC_ESP);
	do_test("3des-sha1;dh22", PROTO_IPSEC_ESP);
	do_test("3des-sha1;dh23", PROTO_IPSEC_ESP);
	do_test("3des-sha1;dh24", PROTO_IPSEC_ESP);
	do_test("3des-sha1", PROTO_IPSEC_ESP);
	do_test("null-sha1", PROTO_IPSEC_ESP);
	do_test("aes", PROTO_IPSEC_ESP);
	do_test("aes_cbc", PROTO_IPSEC_ESP);
	do_test("aes-sha", PROTO_IPSEC_ESP);
	do_test("aes-sha1", PROTO_IPSEC_ESP);
	do_test("aes-sha2", PROTO_IPSEC_ESP);
	do_test("aes-sha256", PROTO_IPSEC_ESP);
	do_test("aes-sha384", PROTO_IPSEC_ESP);
	do_test("aes-sha512", PROTO_IPSEC_ESP);
	do_test("aes128-sha1", PROTO_IPSEC_ESP);
	do_test("aes128-aes_xcbc", PROTO_IPSEC_ESP);
	do_test("aes192-sha1", PROTO_IPSEC_ESP);
	do_test("aes256-sha1", PROTO_IPSEC_ESP);
	do_test("aes256-sha", PROTO_IPSEC_ESP);
	do_test("aes256-sha2", PROTO_IPSEC_ESP);
	do_test("aes256-sha2_256", PROTO_IPSEC_ESP);
	do_test("aes256-sha2_384", PROTO_IPSEC_ESP);
	do_test("aes256-sha2_512", PROTO_IPSEC_ESP);
	do_test("camellia", PROTO_IPSEC_ESP);
	do_test("camellia128", PROTO_IPSEC_ESP);
	do_test("camellia192", PROTO_IPSEC_ESP);
	do_test("camellia256", PROTO_IPSEC_ESP);
	do_test("aes_ccm_a-128-null", PROTO_IPSEC_ESP);
	do_test("aes_ccm_a-192-null", PROTO_IPSEC_ESP);
	do_test("aes_ccm_a-256-null", PROTO_IPSEC_ESP);
	do_test("aes_ccm_b-128-null", PROTO_IPSEC_ESP);
	do_test("aes_ccm_b-192-null", PROTO_IPSEC_ESP);
	do_test("aes_ccm_b-256-null", PROTO_IPSEC_ESP);
	do_test("aes_ccm_c-128-null", PROTO_IPSEC_ESP);
	do_test("aes_ccm_c-192-null", PROTO_IPSEC_ESP);
	do_test("aes_ccm_c-256-null", PROTO_IPSEC_ESP);
	do_test("aes_gcm_a-128-null", PROTO_IPSEC_ESP);
	do_test("aes_gcm_a-192-null", PROTO_IPSEC_ESP);
	do_test("aes_gcm_a-256-null", PROTO_IPSEC_ESP);
	do_test("aes_gcm_b-128-null", PROTO_IPSEC_ESP);
	do_test("aes_gcm_b-192-null", PROTO_IPSEC_ESP);
	do_test("aes_gcm_b-256-null", PROTO_IPSEC_ESP);
	do_test("aes_gcm_c-128-null", PROTO_IPSEC_ESP);
	do_test("aes_gcm_c-192-null", PROTO_IPSEC_ESP);
	do_test("aes_gcm_c-256-null", PROTO_IPSEC_ESP);
	do_test("aes_ccm-null", PROTO_IPSEC_ESP);
	do_test("aes_gcm-null", PROTO_IPSEC_ESP);
	do_test("aes_ccm-256-null", PROTO_IPSEC_ESP);
	do_test("aes_gcm-192-null", PROTO_IPSEC_ESP);
#if 0
	/* these are caught using "aliasing" and rewritten to the above syntax */
	do_test("aes_ccm_8-128-null", PROTO_IPSEC_ESP);
	do_test("aes_ccm_8-192-null", PROTO_IPSEC_ESP);
	do_test("aes_ccm_8-256-null", PROTO_IPSEC_ESP);
	do_test("aes_ccm_12-128-null", PROTO_IPSEC_ESP);
	do_test("aes_ccm_12-192-null", PROTO_IPSEC_ESP);
	do_test("aes_ccm_12-256-null", PROTO_IPSEC_ESP);
	do_test("aes_ccm_16-128-null", PROTO_IPSEC_ESP);
	do_test("aes_ccm_16-192-null", PROTO_IPSEC_ESP);
	do_test("aes_ccm_16-256-null", PROTO_IPSEC_ESP);
	do_test("aes_gcm_8-128-null", PROTO_IPSEC_ESP);
	do_test("aes_gcm_8-192-null", PROTO_IPSEC_ESP);
	do_test("aes_gcm_8-256-null", PROTO_IPSEC_ESP);
	do_test("aes_gcm_12-128-null", PROTO_IPSEC_ESP);
	do_test("aes_gcm_12-192-null", PROTO_IPSEC_ESP);
	do_test("aes_gcm_12-256-null", PROTO_IPSEC_ESP);
	do_test("aes_gcm_16-128-null", PROTO_IPSEC_ESP);
	do_test("aes_gcm_16-192-null", PROTO_IPSEC_ESP);
	do_test("aes_gcm_16-256-null", PROTO_IPSEC_ESP);
#endif
	/* other */
	do_test("aes_ctr", PROTO_IPSEC_ESP);
	do_test("aesctr", PROTO_IPSEC_ESP);
	do_test("aes_ctr128", PROTO_IPSEC_ESP);
	do_test("aes_ctr192", PROTO_IPSEC_ESP);
	do_test("aes_ctr256", PROTO_IPSEC_ESP);
	do_test("serpent", PROTO_IPSEC_ESP);
	do_test("twofish", PROTO_IPSEC_ESP);
	do_test("mars", PROTO_IPSEC_ESP);
	/*
	 * should this be supported - for now man page says not
	 * do_test("modp1536", PROTO_IPSEC_ESP);
	 */

	fprintf(stdout, "\n---- ESP tests that should fail----\n");

	do_test("3des168-sha1", PROTO_IPSEC_ESP); /* should get rejected */
	do_test("3des-null", PROTO_IPSEC_ESP); /* should get rejected */
	do_test("aes128-null", PROTO_IPSEC_ESP); /* should get rejected */
	do_test("aes224-sha1", PROTO_IPSEC_ESP); /* should get rejected */
	do_test("aes512-sha1", PROTO_IPSEC_ESP); /* should get rejected */
	do_test("aes-sha1555", PROTO_IPSEC_ESP); /* should get rejected */
	do_test("camellia666-sha1", PROTO_IPSEC_ESP); /* should get rejected */
	do_test("blowfish", PROTO_IPSEC_ESP); /* obsoleted */
	do_test("des-sha1", PROTO_IPSEC_ESP); /* obsoleted */
	do_test("aes_ctr666", PROTO_IPSEC_ESP); /* bad key size */
	do_test("aes128-sha2_128", PROTO_IPSEC_ESP); /* _128 does not exist */
	do_test("aes256-sha2_256-4096", PROTO_IPSEC_ESP); /* double keysize */
	do_test("aes256-sha2_256-128", PROTO_IPSEC_ESP); /* now what?? */
	do_test("vanitycipher", PROTO_IPSEC_ESP);
	do_test("ase-sah", PROTO_IPSEC_ESP); /* should get rejected */
	do_test("aes-sah1", PROTO_IPSEC_ESP); /* should get rejected */
	/* we no longer support IDxxx because we cannot know block/key sizes */
	do_test("id3", PROTO_IPSEC_ESP); /* alternative spelling for 3DES */
	do_test("id12", PROTO_IPSEC_ESP); /* alternative spelling for AES */
	do_test("aes_gcm-md5", PROTO_IPSEC_ESP); /* AEAD must have auth null */

	/* ah= */
	fprintf(stdout, "\n---- AH tests that should succeed ----\n");
	do_test("md5", PROTO_IPSEC_AH);
	do_test("sha", PROTO_IPSEC_AH);
	do_test("sha1", PROTO_IPSEC_AH);
	do_test("sha2", PROTO_IPSEC_AH);
	do_test("sha256", PROTO_IPSEC_AH);
	do_test("sha384", PROTO_IPSEC_AH);
	do_test("sha512", PROTO_IPSEC_AH);
	do_test("sha2_256", PROTO_IPSEC_AH);
	do_test("sha2_384", PROTO_IPSEC_AH);
	do_test("sha2_512", PROTO_IPSEC_AH);
	do_test("aes_xcbc", PROTO_IPSEC_AH);
	do_test("ripemd", PROTO_IPSEC_AH);

	fprintf(stdout, "\n---- AH tests that should fail ----\n");
	do_test("aes-sha1", PROTO_IPSEC_AH);
	do_test("vanityhash1", PROTO_IPSEC_AH);
	do_test("aes_gcm_c-256", PROTO_IPSEC_AH);
	do_test("id3", PROTO_IPSEC_AH);
	do_test("3des", PROTO_IPSEC_AH);
	do_test("null", PROTO_IPSEC_AH);
	do_test("aes_gcm", PROTO_IPSEC_AH);
	do_test("aes_ccm", PROTO_IPSEC_AH);

#ifdef WORK_IN_PROGRESS
	/* ike= */
	fprintf(stdout, "\n---- IKE tests ----\n");
	do_test("3des-sha1", PROTO_ISAKMP);
#endif
	fflush(NULL);
	report_leaks();
	tool_close_log();
	exit(0);
}
