#ifndef NAMES_CONSTANT_H
#define NAMES_CONSTANT_H

/*
 * names_constant.h
 */
#include <sys/types.h>

#include "names.h"

extern enum_names ip_protocol_id_names;	/* aka ipproto_*; in ip_protocol.c */

#ifdef KERNEL_XFRM
extern enum_names xfrm_policy_names;	/* #ifdef KERNEL_XFRM */
#endif
extern enum_names sd_action_names;
extern enum_names stf_status_names;

extern const enum_names debug_names;
extern const enum_names debug_help;
extern const struct lmod_info debug_lmod_info;

extern enum_names ike_version_names;

/* IKEv2 */

extern enum_names dns_auth_level_names;

extern enum_names natt_method_names;

extern enum_names secret_kind_names;

/* natt traversal types */
extern const char *const natt_type_bitnames[];

#endif
