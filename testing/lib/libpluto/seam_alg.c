#include "alg_info.h"

struct alg_info_ike *alg_info_ike_create_from_str(const char *alg_str,
						  const char **err_p)
{
	struct alg_info_ike *alg_info_ike;

	/*
	 *      alg_info storage should be sized dynamically
	 *      but this may require 2passes to know
	 *      transform count in advance.
	 */
	alg_info_ike = alloc_thing(struct alg_info_ike, "alg_info_ike");
	alg_info_ike->alg_info_cnt = 1;

	return alg_info_ike;
}
