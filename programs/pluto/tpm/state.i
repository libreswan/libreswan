/* state and event objects
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
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
 */

%module state
%{
#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "lswalloc.h"
#include "id.h"
#include "defs.h"
#include "packet.h"
#include "demux.h"
#include "connections.h"
#include "state.h"
#include "tpm_int.h"

#define true TRUE
#define false FALSE

Tcl_Obj *tpm_StateToInstanceObj(struct state *st)
{
	char result[512];
	SWIG_MakePtr(result, st, SWIGTYPE_p_state, 0);
	return Tcl_NewStringObj(result, -1);
}

Tcl_Obj *tpm_ConnectionToInstanceObj(struct connection *st)
{
	char result[512];

	SWIG_MakePtr(result, st, SWIGTYPE_p_connection, 0);
	return Tcl_NewStringObj(result, -1);
}

Tcl_Obj *tpm_BufToCharPointer(u_int8_t *ptr)
{
	char result[512];

	SWIG_MakePtr(result, ptr, SWIGTYPE_p_unsigned_char, 0);
	return Tcl_NewStringObj(result, -1);
}

Tcl_Obj *tpm_MessageDigestToInstanceObj(struct msg_digest *st)
{
	char result[512];
	SWIG_MakePtr(result, st, SWIGTYPE_p_msg_digest, 0);
	return Tcl_NewStringObj(result,-1);
}

Tcl_Obj *tpm_PbStreamToInstanceObj(pb_stream *pbs)
{
	char result[512];
	SWIG_MakePtr(result, pbs, SWIGTYPE_p_packet_byte_stream, 0);
	return Tcl_NewStringObj(result,-1);
}

Tcl_Obj *tpm_IsakmpHdrToInstanceObj(struct isakmp_hdr *hdr)
{
	char result[512];
	SWIG_MakePtr(result, hdr, SWIGTYPE_p_isakmp_hdr, 0);
	return Tcl_NewStringObj(result,-1);
}

Tcl_Obj *tpm_IntPToInstanceObj(int *ip)
{
	char result[512];
	SWIG_MakePtr(result, ip, SWIGTYPE_p_int, 0);
	return Tcl_NewStringObj(result,-1);
}

%}

%include "systypes.i"
%include "cstring.i"
%include "mycdata.i"
%include "cpointer.i"
%include "libreswantypes.i"
%include "ietf_constants.h"
%include "pluto_constants.h"
%typedef u_int32_t msgid_t;	
%typedef u_int32_t time_t;

/* Create some functions for working with "int *" */
%pointer_functions(int, int);

%cstring_output_maxsize(char *addrbuf, size_t buflen);
size_t addrtot(const ip_address *src, int format, char *addrbuf, size_t buflen);

%apply (char *STRING, int LENGTH) { (char *data, size_t datalen) };
void libreswan_DBG_dump(char *label, char *data, size_t datalen);


struct chunk {
    u_char *ptr;
    size_t len;
};
typedef struct chunk chunk_t;

typedef struct packet_byte_stream pb_stream;
struct pb_stream;

int pbs_peek(pb_stream *pbs, int offset);
void pbs_poke(pb_stream *pbs, int offset, int value);
int pbs_append(pb_stream *dest, int destoffset, pb_stream *src, int offset, int length);
pb_stream *pbs_create(int size);
void pbs_delete(pb_stream *pbs);          /* opposite of pbs_create */
void pbs_free(pb_stream *pbs);            /* use when a pbs_free    */
int pbs_offset_get(pb_stream *pbs);
int pbs_room_get(pb_stream *pbs);
int pbs_left_get(pb_stream *pbs);

%cstring_output_withsize(void *outbytes, int *bytecount);
void pbs_bytes(pb_stream *pbs, void *outbytes, int *bytecount);

struct oakley_trans_attrs {
    u_int16_t encrypt;		/* Encryption algorithm */
    u_int16_t enckeylen;	/* encryption key len (bits) */
    const struct encrypt_desc *encrypter;	/* package of encryption routines */
    oakley_hash_t hash;		/* Hash algorithm */
    const struct hash_desc *hasher;	/* package of hashing routines */
    oakley_auth_t auth;		/* Authentication method */
    u_int16_t xauth;            /* did we negotiate Extended Authentication? */
    const struct oakley_group_desc *group;	/* Oakley group */
    time_t life_seconds;	/* When this SA expires (seconds) */
    u_int32_t life_kilobytes;	/* When this SA is exhausted (kilobytes) */
};

/* IPsec (Phase 2 / Quick Mode) transform and attributes
 * This is a flattened/decoded version of what is represented
 * by a Transaction Payload.  There may be one for AH, one
 * for ESP, and a funny one for IPCOMP.
 */
struct ipsec_trans_attrs {
    u_int8_t transid;	/* transform id */
    ipsec_spi_t spi;	/* his SPI */
    time_t life_seconds;		/* When this SA expires */
    u_int32_t life_kilobytes;	/* When this SA expires */
    u_int16_t encapsulation;
    ipsec_auth_t auth;            
    u_int16_t key_len;
    u_int16_t key_rounds;
};

/* IPsec per protocol state information */
struct ipsec_proto_info {
    bool present;	/* was this transform specified? */
    struct ipsec_trans_attrs attrs;
    ipsec_spi_t our_spi;
    u_int16_t keymat_len;	/* same for both */
    u_char *our_keymat;
    u_char *peer_keymat;
};

/* state object: record the state of a (possibly nascent) SA
 *
 * Invariants (violated only during short transitions):
 * - each state object will be in statetable exactly once.
 * - each state object will always have a pending event.
 *   This prevents leaks.
 */
struct state
{
    so_serial_t        st_serialno;          /*serial number (for seniority) */
    so_serial_t        st_clonedfrom;        /* serial number of parent */
    int                st_usage;

    struct connection *st_connection;          /* connection for this SA */
    int                st_whack_sock;          /* fd for our Whack TCP socket.
                                                * Single copy: close when
						* freeing struct.
                                                */

    struct msg_digest *st_suspended_md;        /* suspended state-transition */

    struct oakley_trans_attrs st_oakley;

    struct ipsec_proto_info st_ah;
    struct ipsec_proto_info st_esp;
    struct ipsec_proto_info st_ipcomp;

    ipsec_spi_t        st_tunnel_in_spi;          /* KLUDGE */
    ipsec_spi_t        st_tunnel_out_spi;         /* KLUDGE */

    const struct oakley_group_desc *st_pfs_group; /*group for Phase 2 PFS */

    u_int32_t          st_doi;                 /* Domain of Interpretation */
    u_int32_t          st_situation;

    lset_t             st_policy;              /* policy for IPsec SA */

    ip_address         st_remoteaddr;          /* where to send packets to */
    u_int16_t          st_remoteport;          /* host byte order */
    
    const struct iface_port *st_interface;     /* where to send from */
    ip_address         st_localaddr;           /* where to send them from */
    u_int16_t          st_localport;           

    msgid_t            st_msgid;               /* MSG-ID from header.  Network Order! */

    msgid_t            st_msgid_phase15;       /* msgid for phase 1.5 */
    msgid_t            st_msgid_phase15b;      /* msgid for phase 1.5 */

    /* only for a state representing an ISAKMP SA */
    struct msgid_list  *st_used_msgids;        /* used-up msgids */

/* symmetric stuff */

  /* initiator stuff */
    chunk_t            st_gi;                  /* Initiator public value */
    u_int8_t           st_icookie[COOKIE_SIZE];/* Initiator Cookie */
    chunk_t            st_ni;                  /* Ni nonce */

  /* responder stuff */
    chunk_t            st_gr;                  /* Responder public value */
    u_int8_t           st_rcookie[COOKIE_SIZE];/* Responder Cookie */
    chunk_t            st_nr;                  /* Nr nonce */


  /* my stuff */

    chunk_t            st_tpacket;             /* Transmitted packet */

    /* Phase 2 ID payload info about my user */
    u_int8_t           st_myuserprotoid;       /* IDcx.protoid */
    u_int16_t          st_myuserport;

  /* his stuff */

    chunk_t            st_rpacket;             /* Received packet */

    /* Phase 2 ID payload info about peer's user */
    u_int8_t           st_peeruserprotoid;     /* IDcx.protoid */
    u_int16_t          st_peeruserport;

/* end of symmetric stuff */

    u_int8_t           st_sec_in_use;      /* bool: does st_sec hold a value */
    MP_INT             st_sec;             /* Our local secret value */
    chunk_t            st_sec_chunk;       /* copy of above */

    chunk_t            st_shared;              /* Derived shared secret
                                                * Note: during Quick Mode,
                                                * presence indicates PFS
                                                * selected.
                                                */
    enum crypto_importance st_import;          /* relative priority of crypto
						* operations
						*/

    /* In a Phase 1 state, preserve peer's public key after authentication */
    struct pubkey     *st_peer_pubkey;

    enum state_kind    st_state;               /* State of exchange */
    u_int8_t           st_retransmit;          /* Number of retransmits */
    unsigned long      st_try;                 /* number of times rekeying attempted */
                                               /* 0 means the only time */
    time_t             st_margin;              /* life after EVENT_SA_REPLACE */
    unsigned long      st_outbound_count;      /* traffic through eroute */
    time_t             st_outbound_time;       /* time of last change to st_outbound_count */

    bool               st_calculating;         /* set to TRUE, if we are performing cryptographic
						* operations on this state at this time
						*/

    chunk_t            st_p1isa;               /* Phase 1 initiator SA (Payload) for HASH */
    chunk_t            st_skeyid;              /* Key material */
    chunk_t            st_skeyid_d;            /* KM for non-ISAKMP key derivation */
    chunk_t            st_skeyid_a;            /* KM for ISAKMP authentication */
    chunk_t            st_skeyid_e;            /* KM for ISAKMP encryption */
    u_char             st_iv[MAX_DIGEST_LEN];  /* IV for encryption */
    u_char             st_old_iv[MAX_DIGEST_LEN];  /* IV for encryption */
    u_char             st_new_iv[MAX_DIGEST_LEN];
    u_char             st_ph1_iv[MAX_DIGEST_LEN]; /* IV at end if phase 1 */
    unsigned int       st_iv_len;
    unsigned int       st_old_iv_len;
    unsigned int       st_new_iv_len;
    unsigned int       st_ph1_iv_len;

    chunk_t            st_enc_key;             /* Oakley Encryption key */

    struct event      *st_event;               /* backpointer for certain events */
    struct state      *st_hashchain_next;      /* Next in list */
    struct state      *st_hashchain_prev;      /* Previous in list */

    struct {
        unsigned int   st_malformed_received;
        unsigned int   st_malformed_sent;
	bool           st_xauth_client_done;
	int            st_xauth_client_attempt;
        bool           st_modecfg_server_done;
        bool           st_modecfg_vars_set;
	bool           st_got_certrequest;
        bool           st_modecfg_started;
	bool           st_skeyid_calculated;
	bool           st_dpd;                 /* Peer supports DPD */
	bool           st_dpd_local;	       /* If we want DPD on this conn */
	bool           st_logged_p1algos;      /* if we have logged algos */
	u_int32_t      st_nat_traversal;       /* bit field of permitted
						* methods. If non-zero, then
						* NAT-T has been detected, and
						* should be used. */
	ip_address     st_nat_oa;
	ip_address     st_natd;
    } hidden_variables;                        /* internal state that
						* should get copied by god
						* Eistein would be proud
						*/


    unsigned char *st_xauth_username;

    /* RFC 3706 Dead Peer Detection */
    time_t              st_last_dpd;            /* Time of last DPD transmit */
    u_int32_t           st_dpd_seqno;           /* Next R_U_THERE to send */
    u_int32_t           st_dpd_expectseqno;     /* Next R_U_THERE_ACK to receive */
    u_int32_t           st_dpd_peerseqno;       /* global variables */
    struct event        *st_dpd_event;          /* backpointer for DPD events */


    u_int32_t	      st_seen_vendorid;	  /* Bit field about recognized Vendor ID */
    struct isakmp_quirks quirks;          /* work arounds for faults in other
 					   * products */
    
};

struct payload_digest {
    pb_stream pbs;
    union payload payload;
    struct payload_digest *next;   /* of same kind */
};

/* message digest
 * Note: raw_packet and packet_pbs are "owners" of space on heap.
 */

struct iface_dev {
    int   id_count;
    char *id_vname;	/* virtual (ipsec) device name */
    char *id_rname;	/* real device name */
};

struct iface_port {
    struct iface_dev   *ip_dev;
    u_int16_t           port;    /* host byte order */
    ip_address          ip_addr;   /* interface IP address */
    bool ike_float;
};

struct isakmp_hdr
{
    u_int8_t    isa_icookie[8];
    u_int8_t    isa_rcookie[8];
    u_int8_t    isa_np;                 /* Next payload */
    u_int8_t	isa_version;	/* high-order 4 bits: Major; low order 4: Minor */
    u_int8_t    isa_xchg;		/* Exchange type */
    u_int8_t    isa_flags;
    u_int32_t   isa_msgid;		/* Message ID (RAW) */
    u_int32_t   isa_length;		/* Length of message */
};

struct msg_digest {
    struct msg_digest *next;	/* for free list */
    chunk_t raw_packet;		/* if encrypted, received packet before decryption */
    const struct iface_port *iface;	/* interface on which message arrived */
    ip_address sender;	        /* where message came from (network order) */
    u_int16_t sender_port;	/* host order */
    pb_stream packet_pbs;	/* whole packet */
    pb_stream message_pbs;	/* message to be processed */
    struct isakmp_hdr hdr;	/* message's header */
    bool encrypted;	/* was it encrypted? */
    enum state_kind from_state;	/* state we started in */
    const struct state_microcode *smc;	/* microcode for initial state */
    struct state *st;	/* current state object */
    pb_stream reply;	/* room for reply */
    pb_stream rbody;	/* room for reply body (after header) */
    notification_t note;	/* reason for failure */
    bool dpd;           /* Peer supports RFC 3706 DPD */
    int  result;

#   define PAYLIMIT 20
    struct payload_digest
	digest[PAYLIMIT],
	*digest_roof,
	*chain[ISAKMP_NEXT_ROOF];
};
