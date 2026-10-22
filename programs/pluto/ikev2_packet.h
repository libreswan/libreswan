/* parsing IKEv2 packets: formats and tools, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2005-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2011-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Wolfgang Nothdurft <wolfgang@linogate.de>
 * Copyright (C) 2018-2019 Andrew Cagney
 * Copyright (C) 2020 Nupur Agrawal <nupur202000@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#ifndef IKEv2_PACKET_H
#define IKEv2_PACKET_H

#include "packet.h"

/* descriptor for V2 payload type. */

extern struct_desc *ikev2_payload_desc(unsigned p);


/*
 * IKEv2 structures
 */

/*
 * 3.2.  Generic Payload Header
 */

struct ikev2_generic {
	uint8_t isag_np;
	uint8_t isag_critical;
	uint16_t isag_length;
};
extern struct_desc ikev2_generic_desc;
extern struct_desc ikev2_unknown_payload_desc;

struct ikev2_sa {
	uint8_t isasa_np;		/* Next payload */
	uint8_t isasa_critical;
	uint16_t isasa_length;		/* Payload length */
};

extern struct_desc ikev2_sa_desc;

/*
 * IKEv2 Proposal Substructure
 *
 * Layout taken from RFC 7296 3.3.1.  Proposal Substructure
 *
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Last Substruc |   RESERVED    |         Proposal Length       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Proposal Num  |  Protocol ID  |    SPI Size   |Num  Transforms|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ~                        SPI (variable)                         ~
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * ~                        <Transforms>                           ~
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct ikev2_prop {
	uint8_t isap_lp;		/* Last proposal or not */
					/* Matches IKEv1 ISAKMP_NEXT_P by design */
	uint8_t isap_critical;
	uint16_t isap_length;		/* Payload length */
	uint8_t isap_propnum;
	uint8_t isap_protoid;
	uint8_t isap_spisize;
	uint8_t isap_numtrans;
};

extern struct_desc ikev2_prop_desc;

/* RFC 8784 */

struct ikev2_ppk_id {
	uint8_t isappkid_type;
};

extern struct_desc ikev2_ppk_id_desc;

/* rfc4306, section 3.3.2 */

struct ikev2_trans {
	uint8_t isat_lt;		/* Last transform or not */
					/* Matches IKEv1 ISAKMP_NEXT_T by design */
	uint8_t isat_critical;
	uint16_t isat_length;		/* Payload length */
	uint8_t isat_type;		/* transform type */
	uint8_t isat_res2;
	uint16_t isat_transid;		/* ID */
};

extern struct_desc ikev2_trans_desc;

/* rfc4306, section 3.3.5 */

struct ikev2_trans_attr {
	uint16_t isatr_type;		/* Attribute Type */
	uint16_t isatr_lv;		/* Length (AF=0) or Value (AF=1) */
	/* u_intXX_t isatr_value;	Value if AF=0, absent if AF=1 */
};

extern struct_desc ikev2_trans_attr_desc;

/* rfc4306, section 3.4 */

struct ikev2_ke_payload {
	uint8_t isak_np;		/* Next payload */
	uint8_t isak_critical;
	uint16_t isak_length;		/* Payload length */
	uint16_t isak_ke;		/* transform type */
	uint16_t isak_res2;
};

extern struct_desc ikev2_ke_payload_desc;

/* rfc4306, section 3.5 */

struct ikev2_id {
	uint8_t isai_np;		/* Next payload */
	uint8_t isai_critical;
	uint16_t isai_length;		/* Payload length */
	uint8_t isai_type;		/* ID type */
	uint8_t isai_res1;
	uint8_t isai_res2;
	uint8_t isai_res3;
};

extern struct_desc ikev2_id_i_desc;
extern struct_desc ikev2_id_r_desc;

/* rfc4306, section 3.8 */

struct ikev2_auth {
	uint8_t isaa_np;		/* Next payload */
	uint8_t isaa_critical;
	uint16_t isaa_length;		/* Payload length */
	uint8_t isaa_auth_method;
	uint8_t isaa_res1;
	uint16_t isaa_res2;
};

extern struct_desc ikev2_auth_desc;

/* rfc4306 section 3.6 CERT Payload */

struct ikev2_cert {
	uint8_t isac_np;	/* Next payload */
	uint8_t isac_critical;
	uint16_t isac_length;	/* Payload length */
	uint8_t isac_enc;	/* encoding type */
};

/* NOTE: this packet type has a fixed portion that is not a
 * multiple of 4 octets.  This means that sizeof(struct isakmp_cr)
 * yields the wrong value for the length.
 */

#define IKEV2_CERT_SIZE		5
extern struct_desc ikev2_certificate_desc;

/* RFC-7296 section 3.10 CERTREQ Payload */

struct ikev2_certreq {
	uint8_t isacertreq_np;		/* Next payload */
	uint8_t isacertreq_critical;
	uint16_t isacertreq_length;	/* Payload length */
	uint8_t isacertreq_enc;	/* encoding type */
};

/* NOTE: this packet type has a fixed portion that is not a
 * multiple of 4 octets.  This means that sizeof(struct isakmp_cr)
 * yields the wrong value for the length.
 */

#define IKEV2_CERTREQ_SIZE	5
extern struct_desc ikev2_certificate_req_desc;

/* rfc4306, section 3.9, nonce, uses generic header */

extern struct_desc ikev2_nonce_desc;

/*
 * IKEv2 Notify Payload
 *
 * Layout from RFC 7296 3.10.  Notify Payload
 *
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Next Payload  |C|  RESERVED   |         Payload Length        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Protocol ID  |   SPI Size    |      Notify Message Type      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * ~                Security Parameter Index (SPI)                 ~
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * ~                       Notification Data                       ~
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct ikev2_notify {
	uint8_t isan_np;	/* Next payload */
	uint8_t isan_critical;
	uint16_t isan_length;	/* Payload length */
	uint8_t isan_protoid;	/* Protocol ID: noSA=0,IKE=1,AH=2,ESP=3 */
	uint8_t isan_spisize;	/* SPI size: 0 for IKE_SA */
	uint16_t isan_type;	/* Notification type, see v2_notification_t */
};

extern struct_desc ikev2_notify_desc;

/* IKEv2 Delete Payload
 * layout from RFC 5996 Section 3.11
 * This is followed by a variable length SPI.
 *
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !C| RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !  Protocol ID  !   SPI Size    !           Num of SPIs         !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~               Security Parameter Index(es) (SPI)              ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct ikev2_delete {
	uint8_t isad_np;
	uint8_t isad_reserved;
	uint16_t isad_length;
	uint8_t isad_protoid;
	uint8_t isad_spisize;
	uint16_t isad_nrspi;
};

extern struct_desc ikev2_delete_desc;

/* rfc4306, section 3.13 */

struct ikev2_ts {
	uint8_t isat_np;	/* Next Payload */
	uint8_t isat_critical;
	uint16_t isat_length;	/* Payload length */
	uint8_t isat_num;	/* number of TSs */
	uint8_t isat_res1;
	uint16_t isat_res2;
};

struct ikev2_ts_header {
	uint8_t isath_type;
	uint8_t isath_ipprotoid;
	uint16_t isath_length;
};

struct ikev2_ts_portrange {
	uint16_t isatpr_startport;
	uint16_t isatpr_endport;
};

extern struct_desc ikev2_ts_i_desc;
extern struct_desc ikev2_ts_r_desc;
extern struct_desc ikev2_ts_header_desc;
extern struct_desc ikev2_ts_portrange_desc;

/* rfc4306, section 3.14, encrypted payload, uses generic header */

extern struct_desc ikev2_sk_desc;

/*
 * Configuration Payload . RFC 5996 section 3.15
 */

struct ikev2_cp {
	uint8_t isacp_np;
	uint8_t isacp_critical;
	uint16_t isacp_length;
	uint8_t isacp_type;
	uint8_t isacp_res1; /* 3 octets */
	uint16_t isat_res2;
};

extern struct_desc ikev2_cp_desc;

struct ikev2_cp_attribute {
	uint16_t type;
	uint16_t len;
};

extern struct_desc ikev2_cp_attribute_desc;

/* RFC 4306, section 3.16 */

extern struct_desc ikev2_eap_desc;

/* RFC 3748, section 4 */

struct eap_termination {
	uint8_t eap_code;
	uint8_t eap_identifier;
	uint16_t eap_length;
};

extern struct_desc eap_termination_desc;

/* RFC 5216, section 3.1 */

struct eap_tls {
	uint8_t eap_code;
	uint8_t eap_identifier;
	uint16_t eap_length;
	uint8_t eap_type;
	uint8_t eaptls_flags;
};

extern struct_desc eap_tls_desc;

/*
 * Fragment Message. RFC 7383 section 2.5
 */

#define NSIZEOF_ikev2_skf	8	/* on-the-wire sizeof struct ikev2_skf */
struct ikev2_skf {
	uint8_t isaskf_np;
	uint8_t isaskf_critical;
	uint16_t isaskf_length;
	uint16_t isaskf_number;
	uint16_t isaskf_total;
};

extern struct_desc ikev2_skf_desc;

/*
 * 3.12.  Vendor ID Payload
 *
 *  The Vendor ID Payload fields are defined as follows:
 *
 *                         1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    ! Next Payload  !C!  RESERVED   !         Payload Length        !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    !                                                               !
 *    ~                        Vendor ID (VID)                        ~
 *    !                                                               !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

extern struct_desc ikev2_vendor_id_desc;

struct ikev2_suggested_kem {
	uint16_t /*oakley_group_t*/ sk_kem;
};

extern struct_desc ikev2_suggested_kem_desc;

struct ikev2_redirect_part {
	u_int8_t gw_identity_type;
	u_int8_t gw_identity_len;
};

extern struct_desc ikev2_redirect_desc;

struct ikev2_notify_ipcomp_data {
	u_int16_t ikev2_cpi;
	u_int8_t ikev2_notify_ipcomp_trans;
};

extern struct_desc ikev2notify_ipcomp_data_desc;

struct ikev2_ticket_lifetime {
    uint32_t sr_lifetime;
};

extern struct_desc ikev2_ticket_lifetime_desc;

extern struct_desc sec_ctx_desc;

#endif
