struct connection;
struct esp_info;

/* status info */
extern void show_kernel_alg_status(struct show *s);
extern void show_kernel_alg_connection(struct show *s,
				       const struct connection *c);

struct ike_info;
#define IKEALGBUF_LEN strlen("00000_000-00000_000-00000")

void jam_ipsec_proto_info(struct jambuf *buf, const struct ipsec_proto_info *info);
