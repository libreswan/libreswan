#ifndef NAMES_CONSTANT_H
#define NAMES_CONSTANT_H

/*
 * names_constant.h
 */
#include <sys/types.h>

#include "names.h"

#ifdef KERNEL_XFRM
extern enum_names xfrm_policy_names;	/* #ifdef KERNEL_XFRM */
#endif

/* natt traversal types */
extern const char *const natt_type_bitnames[];

#endif
