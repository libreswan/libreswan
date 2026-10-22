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

extern enum_names secret_kind_names;

/* natt traversal types */
extern const char *const natt_type_bitnames[];

#endif
