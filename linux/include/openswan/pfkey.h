/*
 * FreeS/WAN specific PF_KEY headers
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs.
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * RCSID $Id: pfkey.h,v 1.52 2005/11/09 00:30:37 mcr Exp $
 */

#ifndef __NET_IPSEC_PF_KEY_H
#define __NET_IPSEC_PF_KEY_H
#ifdef __KERNEL__
extern struct proto_ops pfkey_proto_ops;
typedef struct sock pfkey_sock;
extern int debug_pfkey;

extern /* void */ int pfkey_init(void);
extern /* void */ int pfkey_cleanup(void);

struct socket_list
{
	struct socket *socketp;
	struct socket_list *next;
};
extern int pfkey_list_insert_socket(struct socket*, struct socket_list**);
extern int pfkey_list_remove_socket(struct socket*, struct socket_list**);
extern struct socket_list *pfkey_open_sockets;
extern struct socket_list *pfkey_registered_sockets[];

struct ipsec_alg_supported
{
	uint16_t ias_exttype;
	uint8_t  ias_id;
	uint8_t  ias_ivlen;
	uint16_t ias_keyminbits;
	uint16_t ias_keymaxbits;
        char    *ias_name;
};

extern struct supported_list *pfkey_supported_list[];
struct supported_list
{
	struct ipsec_alg_supported *supportedp;
	struct supported_list *next;
};
extern int pfkey_list_insert_supported(struct ipsec_alg_supported*, struct supported_list**);
extern int pfkey_list_remove_supported(struct ipsec_alg_supported*, struct supported_list**);

struct sockaddr_key
{
	uint16_t	key_family;	/* PF_KEY */
	uint16_t	key_pad;	/* not used */
	uint32_t	key_pid;	/* process ID */
};

struct pfkey_extracted_data
{
	struct ipsec_sa* ips;
	struct ipsec_sa* ips2;
	struct eroute *eroute;
};

/* forward reference */
struct sadb_ext;
struct sadb_msg;
struct sockaddr;
struct sadb_comb;
struct sadb_sadb;
struct sadb_alg;

extern int
pfkey_alloc_eroute(struct eroute** eroute);

extern int
pfkey_sa_process(struct sadb_ext *pfkey_ext,
		 struct pfkey_extracted_data* extr);

extern int
pfkey_lifetime_process(struct sadb_ext *pfkey_ext,
		       struct pfkey_extracted_data* extr);

extern int
pfkey_address_process(struct sadb_ext *pfkey_ext,
		      struct pfkey_extracted_data* extr);

extern int
pfkey_key_process(struct sadb_ext *pfkey_ext,
		  struct pfkey_extracted_data* extr);

extern int
pfkey_ident_process(struct sadb_ext *pfkey_ext,
		    struct pfkey_extracted_data* extr);

extern int
pfkey_sens_process(struct sadb_ext *pfkey_ext,
		   struct pfkey_extracted_data* extr);

extern int
pfkey_prop_process(struct sadb_ext *pfkey_ext,
		   struct pfkey_extracted_data* extr);

extern int
pfkey_supported_process(struct sadb_ext *pfkey_ext,
			struct pfkey_extracted_data* extr);

extern int
pfkey_spirange_process(struct sadb_ext *pfkey_ext,
		       struct pfkey_extracted_data* extr);

extern int
pfkey_x_kmprivate_process(struct sadb_ext *pfkey_ext,
			  struct pfkey_extracted_data* extr);

extern int
pfkey_x_satype_process(struct sadb_ext *pfkey_ext,
		       struct pfkey_extracted_data* extr);

extern int
pfkey_x_debug_process(struct sadb_ext *pfkey_ext,
		      struct pfkey_extracted_data* extr);

extern int pfkey_upmsg(struct socket *, struct sadb_msg *);
extern int pfkey_expire(struct ipsec_sa *, int);
extern int pfkey_acquire(struct ipsec_sa *);
#else /* ! __KERNEL__ */

extern openswan_keying_debug_func_t pfkey_debug_func;
extern openswan_keying_debug_func_t pfkey_error_func;
extern void pfkey_print(struct sadb_msg *msg, FILE *out);


#endif /* __KERNEL__ */

extern uint8_t satype2proto(uint8_t satype);
extern uint8_t proto2satype(uint8_t proto);
extern char* satype2name(uint8_t satype);
extern char* proto2name(uint8_t proto);

struct key_opt
{
	uint32_t	key_pid;	/* process ID */
	struct sock	*sk;
};

#define key_pid(sk) ((struct key_opt*)&((sk)->sk_protinfo))->key_pid

/* XXX-mcr this is not an alignment, this is because the count is in 64-bit
 * words.
 */
#define IPSEC_PFKEYv2_ALIGN (sizeof(uint64_t)/sizeof(uint8_t))
#define BITS_PER_OCTET 8
#define OCTETBITS 8
#define PFKEYBITS 64
#define DIVUP(x,y) ((x + y -1) / y) /* divide, rounding upwards */
#define ALIGN_N(x,y) (DIVUP(x,y) * y) /* align on y boundary */

#define IPSEC_PFKEYv2_LEN(x)   ((x) * IPSEC_PFKEYv2_ALIGN)
#define IPSEC_PFKEYv2_WORDS(x) ((x) / IPSEC_PFKEYv2_ALIGN)


#define PFKEYv2_MAX_MSGSIZE 4096

/*
 * PF_KEYv2 permitted and required extensions in and out bitmaps
 */
struct pf_key_ext_parsers_def {
	int  (*parser)(struct sadb_ext*);
	char  *parser_name;
};


#define SADB_EXTENSIONS_MAX 31
extern unsigned int extensions_bitmaps[2/*in/out*/][2/*perm/req*/][SADB_EXTENSIONS_MAX];
#define EXT_BITS_IN 0
#define EXT_BITS_OUT 1
#define EXT_BITS_PERM 0
#define EXT_BITS_REQ 1

extern void pfkey_extensions_init(struct sadb_ext *extensions[]);
extern void pfkey_extensions_free(struct sadb_ext *extensions[]);
extern void pfkey_msg_free(struct sadb_msg **pfkey_msg);

extern int pfkey_msg_parse(struct sadb_msg *pfkey_msg,
			   struct pf_key_ext_parsers_def *ext_parsers[],
			   struct sadb_ext **extensions,
			   int dir);

extern int pfkey_register_reply(int satype, struct sadb_msg *sadb_msg);

/*
 * PF_KEYv2 build function prototypes
 */

int
pfkey_msg_hdr_build(struct sadb_ext**	pfkey_ext,
		    uint8_t		msg_type,
		    uint8_t		satype,
		    uint8_t		msg_errno,
		    uint32_t		seq,
		    uint32_t		pid);

int
pfkey_sa_ref_build(struct sadb_ext **	pfkey_ext,
	       uint16_t			exttype,
	       uint32_t			spi, /* in network order */
	       uint8_t			replay_window,
	       uint8_t			sa_state,
	       uint8_t			auth,
	       uint8_t			encrypt,
	       uint32_t			flags,
	       uint32_t/*IPsecSAref_t*/	ref);

int
pfkey_sa_build(struct sadb_ext **	pfkey_ext,
	       uint16_t			exttype,
	       uint32_t			spi, /* in network order */
	       uint8_t			replay_window,
	       uint8_t			sa_state,
	       uint8_t			auth,
	       uint8_t			encrypt,
	       uint32_t			flags);

int
pfkey_lifetime_build(struct sadb_ext **	pfkey_ext,
		     uint16_t		exttype,
		     uint32_t		allocations,
		     uint64_t		bytes,
		     uint64_t		addtime,
		     uint64_t		usetime,
		     uint32_t		packets);

int
pfkey_address_build(struct sadb_ext**	pfkey_ext,
		    uint16_t		exttype,
		    uint8_t		proto,
		    uint8_t		prefixlen,
		    struct sockaddr*	address);

int
pfkey_key_build(struct sadb_ext**	pfkey_ext,
		uint16_t		exttype,
		uint16_t		key_bits,
		unsigned char          *key);

int
pfkey_ident_build(struct sadb_ext**	pfkey_ext,
		  uint16_t		exttype,
		  uint16_t		ident_type,
		  uint64_t		ident_id,
		  uint8_t               ident_len,
		  char*			ident_string);

#ifdef __KERNEL__
extern int pfkey_nat_t_new_mapping(struct ipsec_sa *, struct sockaddr *, __u16);
extern int pfkey_x_nat_t_type_process(struct sadb_ext *pfkey_ext, struct pfkey_extracted_data* extr);
extern int pfkey_x_nat_t_port_process(struct sadb_ext *pfkey_ext, struct pfkey_extracted_data* extr);
#endif /* __KERNEL__ */
int
pfkey_x_nat_t_type_build(struct sadb_ext**  pfkey_ext,
            uint8_t         type);
int
pfkey_x_nat_t_port_build(struct sadb_ext**  pfkey_ext,
            uint16_t         exttype,
            uint16_t         port);

int
pfkey_sens_build(struct sadb_ext**	pfkey_ext,
		 uint32_t		dpd,
		 uint8_t		sens_level,
		 uint8_t		sens_len,
		 uint64_t*		sens_bitmap,
		 uint8_t		integ_level,
		 uint8_t		integ_len,
		 uint64_t*		integ_bitmap);

int pfkey_x_protocol_build(struct sadb_ext **, uint8_t);


int
pfkey_prop_build(struct sadb_ext**	pfkey_ext,
		 uint8_t		replay,
		 unsigned int		comb_num,
		 struct sadb_comb*	comb);

int
pfkey_supported_build(struct sadb_ext**	pfkey_ext,
		      uint16_t		exttype,
		      unsigned int	alg_num,
		      struct sadb_alg*	alg);

int
pfkey_spirange_build(struct sadb_ext**	pfkey_ext,
		     uint16_t		exttype,
		     uint32_t		min,
		     uint32_t		max);

int
pfkey_x_kmprivate_build(struct sadb_ext**	pfkey_ext);

int
pfkey_x_satype_build(struct sadb_ext**	pfkey_ext,
		     uint8_t		satype);

int
pfkey_x_debug_build(struct sadb_ext**	pfkey_ext,
		    uint32_t            tunnel,
		    uint32_t		netlink,
		    uint32_t		xform,
		    uint32_t		eroute,
		    uint32_t		spi,
		    uint32_t		radij,
		    uint32_t		esp,
		    uint32_t		ah,
		    uint32_t		rcv,
		    uint32_t            pfkey,
		    uint32_t            ipcomp,
		    uint32_t            verbose);

int
pfkey_msg_build(struct sadb_msg**	pfkey_msg,
		struct sadb_ext*	extensions[],
		int			dir);

/* in pfkey_v2_debug.c - routines to decode numbers -> strings */
const char *
pfkey_v2_sadb_ext_string(int extnum);

const char *
pfkey_v2_sadb_type_string(int sadb_type);


#endif /* __NET_IPSEC_PF_KEY_H */

/*
 * $Log: pfkey.h,v $
 * Revision 1.52  2005/11/09 00:30:37  mcr
 * 	adjusted signed-ness and look.in
 *
 * Revision 1.51  2005/08/14 21:43:15  mcr
 * 	elide very old comments/logs.
 *
 * Revision 1.50  2005/08/05 08:53:29  mcr
 * 	use a typedef for the pfkey debug function.
 *
 * Revision 1.49  2005/05/11 00:57:29  mcr
 * 	rename struct supported -> struct ipsec_alg_supported.
 * 	make pfkey.h more standalone.
 *
 * Revision 1.48  2005/05/01 03:12:50  mcr
 * 	include name of algorithm in datastructure.
 *
 * Revision 1.47  2004/08/21 00:44:14  mcr
 * 	simplify definition of nat_t related prototypes.
 *
 * Revision 1.46  2004/08/04 16:27:22  mcr
 * 	2.6 sk_ options.
 *
 * Revision 1.45  2004/04/06 02:49:00  mcr
 * 	pullup of algo code from alg-branch.
 *
 * Revision 1.44  2003/12/10 01:20:01  mcr
 * 	NAT-traversal patches to KLIPS.
 *
 * ...elided.
 *
 */
