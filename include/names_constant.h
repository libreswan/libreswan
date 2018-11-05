/*
 * names_constant.h
 */
#include <sys/types.h>
#include <libreswan.h>

extern enum_names kern_interface_names;
extern enum_names timer_event_names;

extern enum_names dpd_action_names;
#ifdef NETKEY_SUPPORT
extern enum_names netkey_sa_dir_names;
#endif
extern enum_names sd_action_names;
extern enum_names stf_status_names;
extern enum_names ikev2_asym_auth_name;

extern const enum_names debug_names;
extern const enum_names debug_help;
extern const struct lmod_info debug_lmod_info;

extern const enum_names impair_names;
extern const enum_names impair_help;
extern const struct lmod_info impair_lmod_info;

extern enum_names state_names;
extern enum_names state_stories;
extern enum_names connection_kind_names;
extern enum_names routing_story;
extern enum_names certpolicy_type_names;
extern const char *const sa_policy_bit_names[];
extern enum_names oakley_attr_names;
extern const char *const oakley_attr_bit_names[];
extern enum_names *const oakley_attr_val_descs[];
extern const unsigned int oakley_attr_val_descs_roof;
extern enum_names ipsec_attr_names;
extern enum_names *const ipsec_attr_val_descs[];
extern const unsigned int ipsec_attr_val_descs_roof;
extern enum_names sa_lifetime_names;
extern enum_names enc_mode_names;
extern enum_names auth_alg_names;
extern enum_names oakley_lifetime_names;

extern enum_names version_names;
extern enum_names doi_names;
extern enum_names ikev1_payload_names;
extern enum_names ikev2_payload_names;
extern enum_names ikev2_last_proposal_desc;
extern enum_names ikev2_last_transform_desc;
extern enum_names payload_names_ikev1orv2;
extern const char *const payload_name_ikev1[];	/* suitable for bitnamesof() */
extern enum_names attr_msg_type_names;
extern enum_names modecfg_attr_names;
extern enum_names xauth_type_names;
extern enum_names xauth_attr_names;
extern enum_names ikev1_exchange_names;
extern enum_names ikev2_exchange_names;
extern enum_names exchange_names_ikev1orv2;
extern enum_names ikev1_protocol_names;
extern enum_names ikev2_protocol_names;
extern enum_names ikev2_del_protocol_names;	/* subset of protocol names accepted by IKEv2 Delete */
extern enum_names isakmp_transformid_names;
extern enum_names ah_transformid_names;
extern enum_names esp_transformid_names;
extern enum_names ipcomp_transformid_names;
extern enum_names ike_idtype_names_extended0;
extern enum_names ike_idtype_names_extended;
extern enum_names ike_idtype_names;
extern enum_names ike_cert_type_names;
extern enum_names oakley_enc_names;
extern enum_names oakley_hash_names;
extern enum_names oakley_auth_names;
extern enum_names oakley_group_names;
extern enum_names ikev1_notify_names;

/* IKEv2 */
extern enum_names ikev2_auth_names;
extern enum_names ikev2_sec_proto_id_names;
extern enum_names ikev2_trans_type_names;
extern enum_names ikev2_trans_type_encr_names;
extern enum_names ikev2_trans_type_prf_names;
extern enum_names ikev2_trans_type_integ_names;
extern enum_names ikev2_trans_type_esn_names;
extern enum_names ikev2_trans_attr_descs;
extern enum_enum_names v2_transform_ID_enums;
extern enum_names ikev2_idtype_names;
extern enum_names ikev2_cert_type_names;
extern enum_names ikev2_notify_names;
extern enum_names ikev2_ts_type_names;
extern enum_names ikev2_cp_type_names;
extern enum_names ikev2_cp_attribute_type_names;

extern enum_names dns_auth_level_names;

#ifdef HAVE_LABELED_IPSEC
/*
 * Attribute Type "constant" for Security Context
 *
 * ??? NOT A CONSTANT!
 * Originally, we assigned the value 10, but that properly belongs to ECN_TUNNEL.
 * We then assigned 32001 which is in the private range RFC 2407.
 * Unfortunately, we feel we have to support 10 as an option for backward
 * compatibility.
 * This variable specifies (globally!!) which we support: 10 or 32001.
 * ??? surely that makes migration to 32001 all or nothing.
 */
extern uint16_t secctx_attr_type;
#endif

extern const char *const natt_bit_names[];
extern enum_names natt_method_names;

extern enum_names pkk_names;
extern enum_names ikev2_ppk_id_type_names;

extern enum_names spi_names;

/* natt traversal types */
extern const char *const natt_type_bitnames[];
