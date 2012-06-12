struct connection;

/* status info */
extern void kernel_alg_show_status(void);
void kernel_alg_show_connection(struct connection *c, const char *instance);

struct ike_info;
#define IKEALGBUF_LEN strlen("00000_000-00000_000-00000")
extern char *alg_info_snprint_ike1(struct ike_info *ike_info
				   , int eklen, int aklen
				   , char *buf, int buflen);

extern struct alg_info_ike *
alg_info_ike_create_from_str (const char *alg_str, const char **err_p);

extern void alg_info_snprint_phase2(char *buf, size_t buflen
				   , struct alg_info_esp *alg_info);

