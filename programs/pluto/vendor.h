/* FreeS/WAN ISAKMP VendorID
 * Copyright (C) 2002-2003 Mathieu Lafon - Arkoon Network Security
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
 * RCSID $Id: vendor.h,v 1.13.2.1 2005/07/26 02:05:10 ken Exp $
 */

#ifndef _VENDOR_H_
#define _VENDOR_H_

enum known_vendorid {
  /* 1 - 100 : Implementation names */
  VID_OPENPGP                 =1,
  VID_KAME_RACOON             =2,
  VID_MS_NT5                  =3,
  VID_SSH_SENTINEL            =4,
  VID_SSH_SENTINEL_1_1        =5,
  VID_SSH_SENTINEL_1_2        =6,
  VID_SSH_SENTINEL_1_3        =7,
  VID_SSH_IPSEC_1_1_0         =8,
  VID_SSH_IPSEC_1_1_1         =9,
  VID_SSH_IPSEC_1_1_2         =10,
  VID_SSH_IPSEC_1_2_1         =11,
  VID_SSH_IPSEC_1_2_2         =12,
  VID_SSH_IPSEC_2_0_0         =13,
  VID_SSH_IPSEC_2_1_0         =14,
  VID_SSH_IPSEC_2_1_1         =15,
  VID_SSH_IPSEC_2_1_2         =16,
  VID_SSH_IPSEC_3_0_0         =17,
  VID_SSH_IPSEC_3_0_1         =18,
  VID_SSH_IPSEC_4_0_0         =19,
  VID_SSH_IPSEC_4_0_1         =20,
  VID_SSH_IPSEC_4_1_0         =21,
  VID_SSH_IPSEC_4_2_0         =22,
  VID_CISCO_UNITY             =23,
  VID_SSH_SENTINEL_1_4        =24,
  VID_SSH_SENTINEL_1_4_1      =25,
  VID_TIMESTEP                =26,
  VID_FSWAN_2_00_VID          =27,
  VID_FSWAN_2_00_X509_1_3_1_VID =28,
  VID_FSWAN_2_00_X509_1_3_1_LDAP_VID =29,
  VID_SAFENET		    =30,
  VID_NORTEL		    =31,
  VID_OPENSWAN1		    =32,
  VID_OPENSWAN2		    =33,
  VID_MACOSX                =34,
  VID_CISCO3K               =35,
  VID_OPENSWANSELF	    =36,
  VID_NCP                   =37,
  VID_CISCO_IOS             =38,


  /* 101 - 200 : NAT-Traversal */
  VID_NATT_STENBERG_01       =101,
  VID_NATT_STENBERG_02       =102,
  VID_NATT_HUTTUNEN          =103,
  VID_NATT_HUTTUNEN_ESPINUDP =104,
  VID_NATT_IETF_00           =105,
  VID_NATT_IETF_02_N         =106,
  VID_NATT_IETF_02           =107,
  VID_NATT_IETF_03           =108,
  VID_NATT_RFC               =109,
  VID_NATT_DRAFT_IETF_IPSEC_NAT_T_IKE	=110,

/* 
  While searching (strings) in /usr/sbin/racoon on Max OS X 10.3.3, I found it :
  # echo -n "draft-ietf-ipsec-nat-t-ike" | md5sum
  4df37928e9fc4fd1b3262170d515c662
  But this VID has not been seen in any IETF drafts. (mlafon)

*/

  /* 201 - 300 : Misc */
  VID_MISC_XAUTH             =201,
  VID_MISC_DPD               =202,
  VID_MISC_HEARTBEAT_NOTIFY  =203,
  VID_MISC_FRAGMENTATION     =204,
  VID_INITIAL_CONTACT        =205

};

void init_vendorid(void);

struct msg_digest;
void handle_vendorid (struct msg_digest *md, const char *vid, size_t len, struct state *st);

bool out_vendorid (u_int8_t np, pb_stream *outs, enum known_vendorid vid);

extern const char compile_time_interop_options[];

extern char pgp_vendorid[];
extern const int pgp_vendorid_len;

extern char dpd_vendorid[];
extern const int dpd_vendorid_len;


#endif /* _VENDOR_H_ */

