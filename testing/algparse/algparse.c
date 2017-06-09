#include <stddef.h>
#include <stdlib.h>

#include "lswlog.h"
#include "lswalloc.h"
#include "lswnss.h"
#include "lswfips.h"

#include "ike_alg.h"
#include "alg_info.h"


#define CHECK(TYPE,PARSE) {						\
		printf("[%*s] ", 20, algstr);				\
		fflush(NULL);						\
		char err_buf[512] = "";	/* ??? big enough? */		\
		struct alg_info_##TYPE *e =				\
			alg_info_##PARSE##_create_from_str(0, algstr,	\
							   err_buf,	\
							   sizeof(err_buf)); \
		if (e != NULL) {					\
			passert(err_buf[0] == '\0');			\
			char algbuf[512] = "";				\
			alg_info_##TYPE##_snprint(algbuf, sizeof(algbuf), e); \
			printf("   OK: %s\n", algbuf);			\
			alg_info_free(&e->ai);				\
		} else {						\
			passert(err_buf[0]);				\
			printf("ERROR: %s\n", err_buf);			\
		}							\
		fflush(NULL);						\
	}

static void esp(const char *algstr)
{
	CHECK(esp, esp);
}

static void ah(const char *algstr)
{
	CHECK(esp, ah);
}

static void ike(const char *algstr)
{
	CHECK(ike, ike);
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

	/*
	 * esp=
	 */

	printf("\n---- ESP tests that should succeed ----\n");

	esp("");
	esp("aes_gcm_a-128-null");
	esp("3des-sha1;modp1024");
	esp("3des-sha1;modp1536");
	esp("3des-sha1;modp2048");
	esp("3des-sha1;dh23");
	esp("3des-sha1;dh24");
	esp("3des-sha1");
	esp("null-sha1");
	esp("aes");
	esp("aes_cbc");
	esp("aes-sha");
	esp("aes-sha1");
	esp("aes-sha2");
	esp("aes-sha256");
	esp("aes-sha384");
	esp("aes-sha512");
	esp("aes128-sha1");
	esp("aes128-aes_xcbc");
	esp("aes192-sha1");
	esp("aes256-sha1");
	esp("aes256-sha");
	esp("aes256-sha2");
	esp("aes256-sha2_256");
	esp("aes256-sha2_384");
	esp("aes256-sha2_512");
	esp("camellia");
	esp("camellia128");
	esp("camellia192");
	esp("camellia256");
	esp("aes_ccm_a-128-null");
	esp("aes_ccm_a-192-null");
	esp("aes_ccm_a-256-null");
	esp("aes_ccm_b-128-null");
	esp("aes_ccm_b-192-null");
	esp("aes_ccm_b-256-null");
	esp("aes_ccm_c-128-null");
	esp("aes_ccm_c-192-null");
	esp("aes_ccm_c-256-null");
	esp("aes_gcm_a-128-null");
	esp("aes_gcm_a-192-null");
	esp("aes_gcm_a-256-null");
	esp("aes_gcm_b-128-null");
	esp("aes_gcm_b-192-null");
	esp("aes_gcm_b-256-null");
	esp("aes_gcm_c-128-null");
	esp("aes_gcm_c-192-null");
	esp("aes_gcm_c-256-null");
	esp("aes_ccm-null");
	esp("aes_gcm-null");
	esp("aes_ccm-256-null");
	esp("aes_gcm-192-null");
#if 0
	/* these are caught using "aliasing" and rewritten to the above syntax */
	esp("aes_ccm_8-128-null");
	esp("aes_ccm_8-192-null");
	esp("aes_ccm_8-256-null");
	esp("aes_ccm_12-128-null");
	esp("aes_ccm_12-192-null");
	esp("aes_ccm_12-256-null");
	esp("aes_ccm_16-128-null");
	esp("aes_ccm_16-192-null");
	esp("aes_ccm_16-256-null");
	esp("aes_gcm_8-128-null");
	esp("aes_gcm_8-192-null");
	esp("aes_gcm_8-256-null");
	esp("aes_gcm_12-128-null");
	esp("aes_gcm_12-192-null");
	esp("aes_gcm_12-256-null");
	esp("aes_gcm_16-128-null");
	esp("aes_gcm_16-192-null");
	esp("aes_gcm_16-256-null");
#endif
	/* other */
	esp("aes_ctr");
	esp("aesctr");
	esp("aes_ctr128");
	esp("aes_ctr192");
	esp("aes_ctr256");
	esp("serpent");
	esp("twofish");
	/*
	 * should this be supported - for now man page says not
	 * esp("modp1536");
	 */

	printf("\n---- ESP tests that should fail----\n");

	esp("3des168-sha1"); /* should get rejected */
	esp("3des-null"); /* should get rejected */
	esp("aes128-null"); /* should get rejected */
	esp("aes224-sha1"); /* should get rejected */
	esp("aes512-sha1"); /* should get rejected */
	esp("aes-sha1555"); /* should get rejected */
	esp("camellia666-sha1"); /* should get rejected */
	esp("blowfish"); /* obsoleted */
	esp("des-sha1"); /* obsoleted */
	esp("aes_ctr666"); /* bad key size */
	esp("aes128-sha2_128"); /* _128 does not exist */
	esp("aes256-sha2_256-4096"); /* double keysize */
	esp("aes256-sha2_256-128"); /* now what?? */
	esp("vanitycipher");
	esp("ase-sah"); /* should get rejected */
	esp("aes-sah1"); /* should get rejected */
	esp("id3"); /* should be rejected; idXXX removed */
	esp("aes-id3"); /* should be rejected; idXXX removed */
	esp("aes_gcm-md5"); /* AEAD must have auth null */
	esp("mars"); /* support removed */
	esp("3des-sha1;dh22"); /* support for dh22 removed */
	esp("3des-sha1-dh21"); /* ';' vs '-' */
	esp("3des-sha1;dh21,3des-sha2"); /* DH must be last */

	/*
	 * ah=
	 */

	printf("\n---- AH tests that should succeed ----\n");

	ah("");
	ah("md5");
	ah("sha");
	ah("sha1");
	ah("sha2");
	ah("sha256");
	ah("sha384");
	ah("sha512");
	ah("sha2_256");
	ah("sha2_384");
	ah("sha2_512");
	ah("aes_xcbc");

	printf("\n---- AH tests that should fail ----\n");

	ah("aes-sha1");
	ah("vanityhash1");
	ah("aes_gcm_c-256");
	ah("id3"); /* should be rejected; idXXX removed */
	ah("3des");
	ah("null");
	ah("aes_gcm");
	ah("aes_ccm");
	ah("ripemd"); /* support removed */

	/*
	 * ike=
	 */

	printf("\n---- IKE tests that should succeed ----\n");

	ike("");
	ike("3des-sha1");
	ike("3des-sha1");
	ike("3des-sha1;modp1536");
	ike("aes_gcm");

	printf("\n---- IKE tests that should fail ----\n");

	ike("id2"); /* should be rejected; idXXX removed */
	ike("3des-id2"); /* should be rejected; idXXX removed */

	/*
	 * FIPS
	 */

	printf("\n---- FIPS defaults ----\n");

	lsw_set_fips_mode(LSW_FIPS_ON);
	ike("");
	esp("");
	ah("");

	report_leaks();

	lsw_nss_shutdown();
	tool_close_log();
	exit(0);
}
