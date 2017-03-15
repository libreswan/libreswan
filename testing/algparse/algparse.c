#include <stddef.h>
#include <stdlib.h>

#include "lswlog.h"
#include "lswalloc.h"
#include "lswnss.h"

#include "ike_alg.h"
#include "alg_info.h"

static void do_test(const char *algstr, int ttype)
{
	char err_buf[256];	/* ??? big enough? */
	char algbuf[256];

	printf("[%*s] ", 20, algstr);
	algbuf[0] = '\0';

	switch (ttype) {
#define CHECK(TYPE,PARSE) {						\
			struct alg_info_##TYPE *e =			\
				alg_info_##PARSE##_create_from_str(0, algstr, \
								  err_buf, \
								  sizeof(err_buf)); \
			if (err_buf[0] != '\0') {			\
				printf("ERROR: alg=%s  error=%s\n",	\
				       algbuf, err_buf);		\
			} else {					\
				passert(e);				\
				alg_info_##TYPE##_snprint(algbuf, sizeof(algbuf), e); \
				printf("   OK: alg=%s\n", algbuf);	\
			}						\
			if (e != NULL) {				\
				alg_info_free(&e->ai);			\
			}						\
		}
	case PROTO_IPSEC_ESP:
		CHECK(esp,esp);
		break;
	case PROTO_IPSEC_AH:
		CHECK(esp,ah);
		break;
	case PROTO_ISAKMP:
		CHECK(ike,ike);
		break;
	}
}

int main(int argc UNUSED, char *argv[])
{
	tool_init_log(argv[0]);

	/*
	 * Need to ensure that NSS is initialized before calling
	 * ike_alg_init().  Some sanity checks require a working NSS.
	 */
	lsw_nss_buf_t err;
	if (!lsw_nss_setup(NULL, 0, NULL, err)) {
		fprintf(stderr, "unexpected %s\n", err);
		exit(1);
	}

	ike_alg_init();

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

	/* ike= */
	fprintf(stdout, "\n---- IKE tests ----\n");
	do_test("3des-sha1", PROTO_ISAKMP);

	fflush(NULL);
	report_leaks();

	lsw_nss_shutdown();
	tool_close_log();
	exit(0);
}
