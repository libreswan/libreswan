#include "alg_info.h"

struct alg_info_ike *alg_info_ike_create_from_str(const char *alg_str,
						  char *err_buf, size_t err_buf_len)
{
	struct alg_info_ike *alg_info_ike;

	err_buf[0] = '\0';
	/*
	 *      alg_info storage should be sized dynamically
	 *      but this may require two passes to know
	 *      transform count in advance.
	 */
	alg_info_ike = alloc_thing(struct alg_info_ike, "alg_info_ike");
	alg_info_ike->alg_info_cnt = 1;

	return alg_info_ike;
}
