/* ip_protocol, for libreswan
 *
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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

#include <netdb.h>		/* for getprotobyname() */
#include <stdlib.h>		/* for strtol() */
#include <netinet/in.h>		/* for IPPROTO_* */

#include "lswcdefs.h"		/* for elemsof() */
#include "constants.h"		/* for strncaseeq() */
#include "enum_names.h"

#include "passert.h"
#include "ip_protocol.h"
#include "ip_encap.h"
#include "jambuf.h"

const struct ip_protocol ip_protocols[] = {
	/*
	 * Hand generated from:
	 * https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
	 *
	 * Decimal,Keyword,Protocol,IPv6 Extension Header,Reference
	 */

#if 0
	/*
	 * IPv6 defines protocol 0 (it loosely translates to look in
	 * next header) but pluto assumes 0 is wild-card.
	 */
	[0] = {
		.description = "IPv6 Hop-by-Hop Option",
		.name = "HOPOPT",
		.ipproto = 0,
		.ipv6_extension_header = true,
		.reference = "[RFC8200]",
	},
#else
	[0] = {
		.description = "unknown",
		.name = "UNKNOWN",
		.prefix = "unk",
		.ipproto = 0,
	},
#endif
	[1] = {
		.description = "Internet Control Message",
		.name = "ICMP",
		.ipproto = IPPROTO_ICMP,
		.reference = "[RFC792]",
		/* libreswan */
		.prefix = "tun",
	},
	[2] = {
		.description = "Internet Group Management",
		.name = "IGMP",
		.ipproto = 2,
		.reference = "[RFC1112]",
	},
	[3] = {
		.description = "Gateway-to-Gateway",
		.name = "GGP",
		.ipproto = 3,
		.reference = "[RFC823]",
	},
	[4] = {
		.description = "IPv4 encapsulation",
		.name = "IPv4",
		.ipproto = IPPROTO_IPIP,
		.reference = "[RFC2003]",
		/* libreswan */
		.prefix = "tun",
	},
	[5] = {
		.description = "Stream",
		.name = "ST",
		.ipproto = 5,
		.reference = "[RFC1190][RFC1819]",
	},
	[6] = {
		.description = "Transmission Control",
		.name = "TCP",
		.ipproto = IPPROTO_TCP,
		.reference = "[RFC793]",
		/* libreswan */
		.prefix = "tcp",
		.encap_esp = &ip_encap_esp_in_tcp,
		.endpoint_requires_non_zero_port = true,
	},
	[7] = {
		.description = "CBT",
		.name = "CBT",
		.ipproto = 7,
		.reference = "[Tony_Ballardie]",
	},
	[8] = {
		.description = "Exterior Gateway Protocol",
		.name = "EGP",
		.ipproto = 8,
		.reference = "[RFC888][David_Mills]",
	},
	[9] = {
		.description = "any private interior gateway (used by Cisco for their IGRP)",
		.name = "IGP",
		.ipproto = 9,
		.reference = "[Internet_Assigned_Numbers_Authority]",
	},
	[10] = {
		.description = "BBN RCC Monitoring",
		.name = "BBN-RCC-MON",
		.ipproto = 10,
		.reference = "[Steve_Chipman]",
	},
	[11] = {
		.description = "Network Voice Protocol",
		.name = "NVP-II",
		.ipproto = 11,
		.reference = "[RFC741][Steve_Casner]",
	},
	[12] = {
		.description = "PUP",
		.name = "PUP",
		.ipproto = 12,
		.reference = "[Boggs, D., J. Shoch, E. Taft, and R. Metcalfe, \"PUP: An Internetwork Architecture\", XEROX Palo Alto Research Center, CSL-79-10, July 1979; also in IEEE Transactions on Communication, Volume COM-28, Number 4, April 1980.][[XEROX]]",
	},
	[13] = {
		.description = "ARGUS",
		.name = "ARGUS (deprecated)",
		.ipproto = 13,
		.reference = "[Robert_W_Scheifler]",
	},
	[14] = {
		.description = "EMCON",
		.name = "EMCON",
		.ipproto = 14,
		.reference = "[<mystery contact>]",
	},
	[15] = {
		.description = "Cross Net Debugger",
		.name = "XNET",
		.ipproto = 15,
		.reference = "[Haverty, J., \"XNET Formats for Internet Protocol Version 4\", IEN 158, October 1980.][Jack_Haverty]",
	},
	[16] = {
		.description = "Chaos",
		.name = "CHAOS",
		.ipproto = 16,
		.reference = "[J_Noel_Chiappa]",
	},
	[17] = {
		.description = "User Datagram",
		.name = "UDP",
		.ipproto = IPPROTO_UDP,
		.reference = "[RFC768][Jon_Postel]",
		/* libreswan */
		.prefix = "udp",
		.encap_esp = &ip_encap_esp_in_udp,
		.endpoint_requires_non_zero_port = true,
	},
	[18] = {
		.description = "Multiplexing",
		.name = "MUX",
		.ipproto = 18,
		.reference = "[Cohen, D. and J. Postel, \"Multiplexing Protocol\", IEN 90, USC/Information Sciences Institute, May 1979.][Jon_Postel]",
	},
	[19] = {
		.description = "DCN Measurement Subsystems",
		.name = "DCN-MEAS",
		.ipproto = 19,
		.reference = "[David_Mills]",
	},
	[20] = {
		.description = "Host Monitoring",
		.name = "HMP",
		.ipproto = 20,
		.reference = "[RFC869][Bob_Hinden]",
	},
	[21] = {
		.description = "Packet Radio Measurement",
		.name = "PRM",
		.ipproto = 21,
		.reference = "[Zaw_Sing_Su]",
	},
	[22] = {
		.description = "XEROX NS IDP",
		.name = "XNS-IDP",
		.ipproto = 22,
		.reference = "[\"The Ethernet, A Local Area Network: Data Link Layer and Physical Layer Specification\", AA-K759B-TK, Digital Equipment Corporation, Maynard, MA.  Also as: \"The Ethernet - A Local Area Network\", Version 1.0, Digital Equipment Corporation, Intel Corporation, Xerox Corporation, September 1980.  And: \"The Ethernet, A Local Area Network: Data Link Layer and Physical Layer Specifications\", Digital, Intel and Xerox, November 1982. And: XEROX, \"The Ethernet, A Local Area Network: Data Link Layer and Physical Layer Specification\", X3T51/80-50, Xerox Corporation, Stamford, CT., October 1980.][[XEROX]]",
	},
	[23] = {
		.description = "Trunk-1",
		.name = "TRUNK-1",
		.ipproto = 23,
		.reference = "[Barry_Boehm]",
	},
	[24] = {
		.description = "Trunk-2",
		.name = "TRUNK-2",
		.ipproto = 24,
		.reference = "[Barry_Boehm]",
	},
	[25] = {
		.description = "Leaf-1",
		.name = "LEAF-1",
		.ipproto = 25,
		.reference = "[Barry_Boehm]",
	},
	[26] = {
		.description = "Leaf-2",
		.name = "LEAF-2",
		.ipproto = 26,
		.reference = "[Barry_Boehm]",
	},
	[27] = {
		.description = "Reliable Data Protocol",
		.name = "RDP",
		.ipproto = 27,
		.reference = "[RFC908][Bob_Hinden]",
	},
	[28] = {
		.description = "Internet Reliable Transaction",
		.name = "IRTP",
		.ipproto = 28,
		.reference = "[RFC938][Trudy_Miller]",
	},
	[29] = {
		.description = "ISO Transport Protocol Class 4",
		.name = "ISO-TP4",
		.ipproto = 29,
		.reference = "[RFC905][<mystery contact>]",
	},
	[30] = {
		.description = "Bulk Data Transfer Protocol",
		.name = "NETBLT",
		.ipproto = 30,
		.reference = "[RFC969][David_Clark]",
	},
	[31] = {
		.description = "MFE Network Services Protocol",
		.name = "MFE-NSP",
		.ipproto = 31,
		.reference = "[Shuttleworth, B., ""A Documentary of MFENet, a National Computer Network"", UCRL-52317, Lawrence Livermore Labs, Livermore, California, June 1977.][Barry_Howard]",
	},
	[32] = {
		.description = "MERIT Internodal Protocol",
		.name = "MERIT-INP",
		.ipproto = 32,
		.reference = "[Hans_Werner_Braun]",
	},
	[33] = {
		.description = "Datagram Congestion Control Protocol",
		.name = "DCCP",
		.ipproto = 33,
		.reference = "[RFC4340]",
	},
	[34] = {
		.description = "Third Party Connect Protocol",
		.name = "3PC",
		.ipproto = 34,
		.reference = "[Stuart_A_Friedberg]",
	},
	[35] = {
		.description = "Inter-Domain Policy Routing Protocol",
		.name = "IDPR",
		.ipproto = 35,
		.reference = "[Martha_Steenstrup]",
	},
	[36] = {
		.description = "XTP",
		.name = "XTP",
		.ipproto = 36,
		.reference = "[Greg_Chesson]",
	},
	[37] = {
		.description = "Datagram Delivery Protocol",
		.name = "DDP",
		.ipproto = 37,
		.reference = "[Wesley_Craig]",
	},
	[38] = {
		.description = "IDPR Control Message Transport Proto",
		.name = "IDPR-CMTP",
		.ipproto = 38,
		.reference = "[Martha_Steenstrup]",
	},
	[39] = {
		.description = "TP++ Transport Protocol",
		.name = "TP++",
		.ipproto = 39,
		.reference = "[Dirk_Fromhein]",
	},
	[40] = {
		.description = "IL Transport Protocol",
		.name = "IL",
		.ipproto = 40,
		.reference = "[Dave_Presotto]",
	},
	[41] = {
		.description = "IPv6 encapsulation",
		.name = "IPv6",
		.ipproto = 41,
		.reference = "[RFC2473]",
	},
	[42] = {
		.description = "Source Demand Routing Protocol",
		.name = "SDRP",
		.ipproto = 42,
		.reference = "[Deborah_Estrin]",
	},
	[43] = {
		.description = "Routing Header for IPv6",
		.name = "IPv6-Route",
		.ipproto = 43,
		.ipv6_extension_header = true,
		.reference = "[Steve_Deering]",
	},
	[44] = {
		.description = "Fragment Header for IPv6",
		.name = "IPv6-Frag",
		.ipproto = 44,
		.ipv6_extension_header = true,
		.reference = "[Steve_Deering]",
	},
	[45] = {
		.description = "Inter-Domain Routing Protocol",
		.name = "IDRP",
		.ipproto = 45,
		.reference = "[Sue_Hares]",
	},
	[46] = {
		.description = "Reservation Protocol",
		.name = "RSVP",
		.ipproto = 46,
		.reference = "[RFC2205][RFC3209][Bob_Braden]",
	},
	[47] = {
		.description = "Generic Routing Encapsulation",
		.name = "GRE",
		.ipproto = 47,
		.reference = "[RFC2784][Tony_Li]",
	},
	[48] = {
		.description = "Dynamic Source Routing Protocol",
		.name = "DSR",
		.ipproto = 48,
		.reference = "[RFC4728]",
	},
	[49] = {
		.description = "BNA",
		.name = "BNA",
		.ipproto = 49,
		.reference = "[Gary Salamon]",
	},
	[50] = {
		.description = "Encap Security Payload",
		.name = "ESP",
		.ipproto = IPPROTO_ESP,
		.ipv6_extension_header = true,
		.reference = "[RFC4303]",
		/* libreswan */
		.prefix = "esp",
		.ikev1_protocol_id = PROTO_IPSEC_ESP,
	},
	[51] = {
		.description = "Authentication Header",
		.name = "AH",
		.ipproto = IPPROTO_AH,
		.ipv6_extension_header = true,
		.reference = "[RFC4302]",
		/* libreswan */
		.prefix = "ah",
		.ikev1_protocol_id = PROTO_IPSEC_AH,
	},
	[52] = {
		.description = "Integrated Net Layer Security  TUBA",
		.name = "I-NLSP",
		.ipproto = 52,
		.reference = "[K_Robert_Glenn]",
	},
	[53] = {
		.description = "IP with Encryption",
		.name = "SWIPE (deprecated)",
		.ipproto = 53,
		.reference = "[John_Ioannidis]",
	},
	[54] = {
		.description = "NBMA Address Resolution Protocol",
		.name = "NARP",
		.ipproto = 54,
		.reference = "[RFC1735]",
	},
	[55] = {
		.description = "IP Mobility",
		.name = "MOBILE",
		.ipproto = 55,
		.reference = "[Charlie_Perkins]",
	},
	[56] = {
		.description = "Transport Layer Security Protocol using Kryptonet key management",
		.name = "TLSP",
		.ipproto = 56,
		.reference = "[Christer_Oberg]",
	},
	[57] = {
		.description = "SKIP",
		.name = "SKIP",
		.ipproto = 57,
		.reference = "[Tom_Markson]",
	},
	[58] = {
		.description = "ICMP for IPv6",
		.name = "IPv6-ICMP",
		.ipproto = 58,
		.reference = "[RFC8200]",
	},
	[59] = {
		.description = "No Next Header for IPv6",
		.name = "IPv6-NoNxt",
		.ipproto = 59,
		.reference = "[RFC8200]",
	},
	[60] = {
		.description = "Destination Options for IPv6",
		.name = "IPv6-Opts",
		.ipproto = 60,
		.ipv6_extension_header = true,
		.reference = "[RFC8200]",
	},
	[61] = {
		.description = "any host internal protocol",
		.name = "",
		.ipproto = INTERNAL_IPPROTO,
		.reference = "[Internet_Assigned_Numbers_Authority]",
		/* libreswan */
		.prefix = "int",
	},
	[62] = {
		.description = "CFTP",
		.name = "CFTP",
		.ipproto = 62,
		.reference = "[Forsdick, H., ""CFTP"", Network Message, Bolt Beranek and Newman, January 1982.][Harry_Forsdick]",
	},
	[63] = {
		.description = "any local network",
		.name = "",
		.ipproto = 63,
		.reference = "[Internet_Assigned_Numbers_Authority]",
	},
	[64] = {
		.description = "SATNET and Backroom EXPAK",
		.name = "SAT-EXPAK",
		.ipproto = 64,
		.reference = "[Steven_Blumenthal]",
	},
	[65] = {
		.description = "Kryptolan",
		.name = "KRYPTOLAN",
		.ipproto = 65,
		.reference = "[Paul Liu]",
	},
	[66] = {
		.description = "MIT Remote Virtual Disk Protocol",
		.name = "RVD",
		.ipproto = 66,
		.reference = "[Michael_Greenwald]",
	},
	[67] = {
		.description = "Internet Pluribus Packet Core",
		.name = "IPPC",
		.ipproto = 67,
		.reference = "[Steven_Blumenthal]",
	},
	[68] = {
		.description = "any distributed file system",
		.name = "",
		.ipproto = 68,
		.reference = "[Internet_Assigned_Numbers_Authority]",
	},
	[69] = {
		.description = "SATNET Monitoring",
		.name = "SAT-MON",
		.ipproto = 69,
		.reference = "[Steven_Blumenthal]",
	},
	[70] = {
		.description = "VISA Protocol",
		.name = "VISA",
		.ipproto = 70,
		.reference = "[Gene_Tsudik]",
	},
	[71] = {
		.description = "Internet Packet Core Utility",
		.name = "IPCV",
		.ipproto = 71,
		.reference = "[Steven_Blumenthal]",
	},
	[72] = {
		.description = "Computer Protocol Network Executive",
		.name = "CPNX",
		.ipproto = 72,
		.reference = "[David Mittnacht]",
	},
	[73] = {
		.description = "Computer Protocol Heart Beat",
		.name = "CPHB",
		.ipproto = 73,
		.reference = "[David Mittnacht]",
	},
	[74] = {
		.description = "Wang Span Network",
		.name = "WSN",
		.ipproto = 74,
		.reference = "[Victor Dafoulas]",
	},
	[75] = {
		.description = "Packet Video Protocol",
		.name = "PVP",
		.ipproto = 75,
		.reference = "[Steve_Casner]",
	},
	[76] = {
		.description = "Backroom SATNET Monitoring",
		.name = "BR-SAT-MON",
		.ipproto = 76,
		.reference = "[Steven_Blumenthal]",
	},
	[77] = {
		.description = "SUN ND PROTOCOL-Temporary",
		.name = "SUN-ND",
		.ipproto = 77,
		.reference = "[William_Melohn]",
	},
	[78] = {
		.description = "WIDEBAND Monitoring",
		.name = "WB-MON",
		.ipproto = 78,
		.reference = "[Steven_Blumenthal]",
	},
	[79] = {
		.description = "WIDEBAND EXPAK",
		.name = "WB-EXPAK",
		.ipproto = 79,
		.reference = "[Steven_Blumenthal]",
	},
	[80] = {
		.description = "ISO Internet Protocol",
		.name = "ISO-IP",
		.ipproto = 80,
		.reference = "[Marshall_T_Rose]",
	},
	[81] = {
		.description = "VMTP",
		.name = "VMTP",
		.ipproto = 81,
		.reference = "[Dave_Cheriton]",
	},
	[82] = {
		.description = "SECURE-VMTP",
		.name = "SECURE-VMTP",
		.ipproto = 82,
		.reference = "[Dave_Cheriton]",
	},
	[83] = {
		.description = "VINES",
		.name = "VINES",
		.ipproto = 83,
		.reference = "[Brian Horn]",
	},
#if 0 /* duplicate! */
	[84] = {
		.description = "Transaction Transport Protocol",
		.name = "TTP",
		.ipproto = 84,
		.reference = "[Jim_Stevens]",
	},
	[84] = {
		.description = "Internet Protocol Traffic Manager",
		.name = "IPTM",
		.ipproto = 84,
		.reference = "[Jim_Stevens]",
	},
#else
	[84] = {
		.description = "Transaction Transport Protocol|Internet Protocol Traffic Manager",
		.name = "TTP|IPTM",
		.ipproto = 84,
		.reference = "[Jim_Stevens]",
	},
#endif
	[85] = {
		.description = "NSFNET-IGP",
		.name = "NSFNET-IGP",
		.ipproto = 85,
		.reference = "[Hans_Werner_Braun]",
	},
	[86] = {
		.description = "Dissimilar Gateway Protocol",
		.name = "DGP",
		.ipproto = 86,
		.reference = "[M/A-COM Government Systems, ""Dissimilar Gateway Protocol Specification, Draft Version"", Contract no. CS901145, November 16, 1987.][Mike_Little]",
	},
	[87] = {
		.description = "TCF",
		.name = "TCF",
		.ipproto = 87,
		.reference = "[Guillermo_A_Loyola]",
	},
	[88] = {
		.description = "EIGRP",
		.name = "EIGRP",
		.ipproto = 88,
		.reference = "[RFC7868]",
	},
	[89] = {
		.description = "OSPFIGP",
		.name = "OSPFIGP",
		.ipproto = 89,
		.reference = "[RFC1583][RFC2328][RFC5340][John_Moy]",
	},
	[90] = {
		.description = "Sprite RPC Protocol",
		.name = "Sprite-RPC",
		.ipproto = 90,
		.reference = "[Welch, B., ""The Sprite Remote Procedure Call System"", Technical Report, UCB/Computer Science Dept., 86/302, University of California at Berkeley, June 1986.][Bruce Willins]",
	},
	[91] = {
		.description = "Locus Address Resolution Protocol",
		.name = "LARP",
		.ipproto = 91,
		.reference = "[Brian Horn]",
	},
	[92] = {
		.description = "Multicast Transport Protocol",
		.name = "MTP",
		.ipproto = 92,
		.reference = "[Susie_Armstrong]",
	},
	[93] = {
		.description = "AX.25 Frames",
		.name = "AX.25",
		.ipproto = 93,
		.reference = "[Brian_Kantor]",
	},
	[94] = {
		.description = "IP-within-IP Encapsulation Protocol",
		.name = "IPIP",
		.ipproto = 94,
		.reference = "[John_Ioannidis]",
	},
	[95] = {
		.description = "Mobile Internetworking Control Pro.",
		.name = "MICP (deprecated)",
		.ipproto = 95,
		.reference = "[John_Ioannidis]",
	},
	[96] = {
		.description = "Semaphore Communications Sec. Pro.",
		.name = "SCC-SP",
		.ipproto = 96,
		.reference = "[Howard_Hart]",
	},
	[97] = {
		.description = "Ethernet-within-IP Encapsulation",
		.name = "ETHERIP",
		.ipproto = 97,
		.reference = "[RFC3378]",
	},
	[98] = {
		.description = "Encapsulation Header",
		.name = "ENCAP",
		.ipproto = 98,
		.reference = "[RFC1241][Robert_Woodburn]",
	},
	[99] = {
		.description = "any private encryption scheme",
		.name = "",
		.ipproto = 99,
		.reference = "[Internet_Assigned_Numbers_Authority]",
	},
	[100] = {
		.description = "GMTP",
		.name = "GMTP",
		.ipproto = 100,
		.reference = "[[RXB5]]",
	},
	[101] = {
		.description = "Ipsilon Flow Management Protocol",
		.name = "IFMP",
		.ipproto = 101,
		.reference = "[Bob_Hinden][November 1995, 1997.]",
	},
	[102] = {
		.description = "PNNI over IP",
		.name = "PNNI",
		.ipproto = 102,
		.reference = "[Ross_Callon]",
	},
	[103] = {
		.description = "Protocol Independent Multicast",
		.name = "PIM",
		.ipproto = 103,
		.reference = "[RFC7761][Dino_Farinacci]",
	},
	[104] = {
		.description = "ARIS",
		.name = "ARIS",
		.ipproto = 104,
		.reference = "[Nancy_Feldman]",
	},
	[105] = {
		.description = "SCPS",
		.name = "SCPS",
		.ipproto = 105,
		.reference = "[Robert_Durst]",
	},
	[106] = {
		.description = "QNX",
		.name = "QNX",
		.ipproto = 106,
		.reference = "[Michael_Hunter]",
	},
	[107] = {
		.description = "Active Networks",
		.name = "A/N",
		.ipproto = 107,
		.reference = "[Bob_Braden]",
	},
	[COMP_IPPROTO] = {
		.description = "IP Payload Compression Protocol",
		.name = "IPComp",
		.ipproto = 108,
		.reference = "[RFC2393]",
		/* libreswan */
		.prefix = "comp",
	},
	[109] = {
		.description = "Sitara Networks Protocol",
		.name = "SNP",
		.ipproto = 109,
		.reference = "[Manickam_R_Sridhar]",
	},
	[110] = {
		.description = "Compaq Peer Protocol",
		.name = "Compaq-Peer",
		.ipproto = 110,
		.reference = "[Victor_Volpe]",
	},
	[111] = {
		.description = "IPX in IP",
		.name = "IPX-in-IP",
		.ipproto = 111,
		.reference = "[CJ_Lee]",
	},
	[112] = {
		.description = "Virtual Router Redundancy Protocol",
		.name = "VRRP",
		.ipproto = 112,
		.reference = "[RFC5798]",
	},
	[113] = {
		.description = "PGM Reliable Transport Protocol",
		.name = "PGM",
		.ipproto = 113,
		.reference = "[Tony_Speakman]",
	},
	[114] = {
		.description = "any 0-hop protocol",
		.name = "",
		.ipproto = 114,
		.reference = "[Internet_Assigned_Numbers_Authority]",
	},
	[115] = {
		.description = "Layer Two Tunneling Protocol",
		.name = "L2TP",
		.ipproto = 115,
		.reference = "[RFC3931][Bernard_Aboba]",
	},
	[116] = {
		.description = "D-II Data Exchange (DDX)",
		.name = "DDX",
		.ipproto = 116,
		.reference = "[John_Worley]",
	},
	[117] = {
		.description = "Interactive Agent Transfer Protocol",
		.name = "IATP",
		.ipproto = 117,
		.reference = "[John_Murphy]",
	},
	[118] = {
		.description = "Schedule Transfer Protocol",
		.name = "STP",
		.ipproto = 118,
		.reference = "[Jean_Michel_Pittet]",
	},
	[119] = {
		.description = "SpectraLink Radio Protocol",
		.name = "SRP",
		.ipproto = 119,
		.reference = "[Mark_Hamilton]",
	},
	[120] = {
		.description = "UTI",
		.name = "UTI",
		.ipproto = 120,
		.reference = "[Peter_Lothberg]",
	},
	[121] = {
		.description = "Simple Message Protocol",
		.name = "SMP",
		.ipproto = 121,
		.reference = "[Leif_Ekblad]",
	},
	[122] = {
		.description = "Simple Multicast Protocol",
		.name = "SM (deprecated)",
		.ipproto = 122,
		.reference = "[Jon_Crowcroft][draft-perlman-simple-multicast]",
	},
	[123] = {
		.description = "Performance Transparency Protocol",
		.name = "PTP",
		.ipproto = 123,
		.reference = "[Michael_Welzl]",
	},
	[124] = {
		.description = "",
		.name = "ISIS over IPv4",
		.ipproto = 124,
		.reference = "[Tony_Przygienda]",
	},
	[125] = {
		.description = "",
		.name = "FIRE",
		.ipproto = 125,
		.reference = "[Criag_Partridge]",
	},
	[126] = {
		.description = "Combat Radio Transport Protocol",
		.name = "CRTP",
		.ipproto = 126,
		.reference = "[Robert_Sautter]",
	},
	[127] = {
		.description = "Combat Radio User Datagram",
		.name = "CRUDP",
		.ipproto = 127,
		.reference = "[Robert_Sautter]",
	},
	[128] = {
		.description = "",
		.name = "SSCOPMCE",
		.ipproto = 128,
		.reference = "[Kurt_Waber]",
	},
	[129] = {
		.description = "",
		.name = "IPLT",
		.ipproto = 129,
		.reference = "[[Hollbach]]",
	},
	[130] = {
		.description = "Secure Packet Shield",
		.name = "SPS",
		.ipproto = 130,
		.reference = "[Bill_McIntosh]",
	},
	[131] = {
		.description = "Private IP Encapsulation within IP",
		.name = "PIPE",
		.ipproto = 131,
		.reference = "[Bernhard_Petri]",
	},
	[132] = {
		.description = "Stream Control Transmission Protocol",
		.name = "SCTP",
		.ipproto = 132,
		.reference = "[Randall_R_Stewart]",
	},
	[133] = {
		.description = "Fibre Channel",
		.name = "FC",
		.ipproto = 133,
		.reference = "[Murali_Rajagopal][RFC6172]",
	},
	[134] = {
		.description = "",
		.name = "RSVP-E2E-IGNORE",
		.ipproto = 134,
		.reference = "[RFC3175]",
	},
	[135] = {
		.description = "",
		.name = "Mobility Header",
		.ipproto = 135,
		.ipv6_extension_header = true,
		.reference = "[RFC6275]",
	},
	[136] = {
		.description = "",
		.name = "UDPLite",
		.ipproto = 136,
		.reference = "[RFC3828]",
	},
	[137] = {
		.description = "",
		.name = "MPLS-in-IP",
		.ipproto = 137,
		.reference = "[RFC4023]",
	},
	[138] = {
		.description = "MANET Protocols",
		.name = "manet",
		.ipproto = 138,
		.reference = "[RFC5498]",
	},
	[139] = {
		.description = "Host Identity Protocol",
		.name = "HIP",
		.ipproto = 139,
		.ipv6_extension_header = true,
		.reference = "[RFC7401]",
	},
	[140] = {
		.description = "Shim6 Protocol",
		.name = "Shim6",
		.ipproto = 140,
		.ipv6_extension_header = true,
		.reference = "[RFC5533]",
	},
	[141] = {
		.description = "Wrapped Encapsulating Security Payload",
		.name = "WESP",
		.ipproto = 141,
		.reference = "[RFC5840]",
	},
	[142] = {
		.description = "Robust Header Compression",
		.name = "ROHC",
		.ipproto = 142,
		.reference = "[RFC5858]",
	},
	[143] = {
		.description = "Ethernet",
		.name = "Ethernet",
		.ipproto = 143,
		.reference = "[RFC-ietf-spring-srv6-network-programming-28]",
	},

	[144] = { .description = "144", .name = "144", .ipproto = 144, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[145] = { .description = "145", .name = "145", .ipproto = 145, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[146] = { .description = "146", .name = "146", .ipproto = 146, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[147] = { .description = "147", .name = "147", .ipproto = 147, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[148] = { .description = "148", .name = "148", .ipproto = 148, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[149] = { .description = "149", .name = "149", .ipproto = 149, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[150] = { .description = "150", .name = "150", .ipproto = 150, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[151] = { .description = "151", .name = "151", .ipproto = 151, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[152] = { .description = "152", .name = "152", .ipproto = 152, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[153] = { .description = "153", .name = "153", .ipproto = 153, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[154] = { .description = "154", .name = "154", .ipproto = 154, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[155] = { .description = "155", .name = "155", .ipproto = 155, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[156] = { .description = "156", .name = "156", .ipproto = 156, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[157] = { .description = "157", .name = "157", .ipproto = 157, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[158] = { .description = "158", .name = "158", .ipproto = 158, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[159] = { .description = "159", .name = "159", .ipproto = 159, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[160] = { .description = "160", .name = "160", .ipproto = 160, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[161] = { .description = "161", .name = "161", .ipproto = 161, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[162] = { .description = "162", .name = "162", .ipproto = 162, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[163] = { .description = "163", .name = "163", .ipproto = 163, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[164] = { .description = "164", .name = "164", .ipproto = 164, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[165] = { .description = "165", .name = "165", .ipproto = 165, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[166] = { .description = "166", .name = "166", .ipproto = 166, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[167] = { .description = "167", .name = "167", .ipproto = 167, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[168] = { .description = "168", .name = "168", .ipproto = 168, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[169] = { .description = "169", .name = "169", .ipproto = 169, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[170] = { .description = "170", .name = "170", .ipproto = 170, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[171] = { .description = "171", .name = "171", .ipproto = 171, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[172] = { .description = "172", .name = "172", .ipproto = 172, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[173] = { .description = "173", .name = "173", .ipproto = 173, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[174] = { .description = "174", .name = "174", .ipproto = 174, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[175] = { .description = "175", .name = "175", .ipproto = 175, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[176] = { .description = "176", .name = "176", .ipproto = 176, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[177] = { .description = "177", .name = "177", .ipproto = 177, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[178] = { .description = "178", .name = "178", .ipproto = 178, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[179] = { .description = "179", .name = "179", .ipproto = 179, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[180] = { .description = "180", .name = "180", .ipproto = 180, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[181] = { .description = "181", .name = "181", .ipproto = 181, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[182] = { .description = "182", .name = "182", .ipproto = 182, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[183] = { .description = "183", .name = "183", .ipproto = 183, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[184] = { .description = "184", .name = "184", .ipproto = 184, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[185] = { .description = "185", .name = "185", .ipproto = 185, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[186] = { .description = "186", .name = "186", .ipproto = 186, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[187] = { .description = "187", .name = "187", .ipproto = 187, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[188] = { .description = "188", .name = "188", .ipproto = 188, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[189] = { .description = "189", .name = "189", .ipproto = 189, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[190] = { .description = "190", .name = "190", .ipproto = 190, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[191] = { .description = "191", .name = "191", .ipproto = 191, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[192] = { .description = "192", .name = "192", .ipproto = 192, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[193] = { .description = "193", .name = "193", .ipproto = 193, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[194] = { .description = "194", .name = "194", .ipproto = 194, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[195] = { .description = "195", .name = "195", .ipproto = 195, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[196] = { .description = "196", .name = "196", .ipproto = 196, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[197] = { .description = "197", .name = "197", .ipproto = 197, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[198] = { .description = "198", .name = "198", .ipproto = 198, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[199] = { .description = "199", .name = "199", .ipproto = 199, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[200] = { .description = "200", .name = "200", .ipproto = 200, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[201] = { .description = "201", .name = "201", .ipproto = 201, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[202] = { .description = "202", .name = "202", .ipproto = 202, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[203] = { .description = "203", .name = "203", .ipproto = 203, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[204] = { .description = "204", .name = "204", .ipproto = 204, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[205] = { .description = "205", .name = "205", .ipproto = 205, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[206] = { .description = "206", .name = "206", .ipproto = 206, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[207] = { .description = "207", .name = "207", .ipproto = 207, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[208] = { .description = "208", .name = "208", .ipproto = 208, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[209] = { .description = "209", .name = "209", .ipproto = 209, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[210] = { .description = "210", .name = "210", .ipproto = 210, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[211] = { .description = "211", .name = "211", .ipproto = 211, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[212] = { .description = "212", .name = "212", .ipproto = 212, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[213] = { .description = "213", .name = "213", .ipproto = 213, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[214] = { .description = "214", .name = "214", .ipproto = 214, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[215] = { .description = "215", .name = "215", .ipproto = 215, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[216] = { .description = "216", .name = "216", .ipproto = 216, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[217] = { .description = "217", .name = "217", .ipproto = 217, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[218] = { .description = "218", .name = "218", .ipproto = 218, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[219] = { .description = "219", .name = "219", .ipproto = 219, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[220] = { .description = "220", .name = "220", .ipproto = 220, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[221] = { .description = "221", .name = "221", .ipproto = 221, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[222] = { .description = "222", .name = "222", .ipproto = 222, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[223] = { .description = "223", .name = "223", .ipproto = 223, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[224] = { .description = "224", .name = "224", .ipproto = 224, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[225] = { .description = "225", .name = "225", .ipproto = 225, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[226] = { .description = "226", .name = "226", .ipproto = 226, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[227] = { .description = "227", .name = "227", .ipproto = 227, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[228] = { .description = "228", .name = "228", .ipproto = 228, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[229] = { .description = "229", .name = "229", .ipproto = 229, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[230] = { .description = "230", .name = "230", .ipproto = 230, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[231] = { .description = "231", .name = "231", .ipproto = 231, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[232] = { .description = "232", .name = "232", .ipproto = 232, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[233] = { .description = "233", .name = "233", .ipproto = 233, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[234] = { .description = "234", .name = "234", .ipproto = 234, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[235] = { .description = "235", .name = "235", .ipproto = 235, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[236] = { .description = "236", .name = "236", .ipproto = 236, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[237] = { .description = "237", .name = "237", .ipproto = 237, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[238] = { .description = "238", .name = "238", .ipproto = 238, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[239] = { .description = "239", .name = "239", .ipproto = 239, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[240] = { .description = "240", .name = "240", .ipproto = 240, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[241] = { .description = "241", .name = "241", .ipproto = 241, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[242] = { .description = "242", .name = "242", .ipproto = 242, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[243] = { .description = "243", .name = "243", .ipproto = 243, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[244] = { .description = "244", .name = "244", .ipproto = 244, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[245] = { .description = "245", .name = "245", .ipproto = 245, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[246] = { .description = "246", .name = "246", .ipproto = 246, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[247] = { .description = "247", .name = "247", .ipproto = 247, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[248] = { .description = "248", .name = "248", .ipproto = 248, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[249] = { .description = "249", .name = "249", .ipproto = 249, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[250] = { .description = "250", .name = "250", .ipproto = 250, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[251] = { .description = "251", .name = "251", .ipproto = 251, .reference = "[Internet_Assigned_Numbers_Authority]", },
	[252] = { .description = "252", .name = "252", .ipproto = 252, .reference = "[Internet_Assigned_Numbers_Authority]", },

	[253] = {
		.description = "Use for experimentation and testing",
		.name = "",
		.ipproto = 253,
		.ipv6_extension_header = true,
		.reference = "[RFC3692]",
	},
	[254] = {
		.description = "Use for experimentation and testing",
		.name = "",
		.ipproto = 254,
		.ipv6_extension_header = true,
		.reference = "[RFC3692]",
	},
	[255] = {
		.description = "",
		.name = "Reserved",
		.ipproto = 255,
		.reference = "[Internet_Assigned_Numbers_Authority]",
	},
};

const struct ip_protocol *protocol_by_prefix(const char *prefix)
{
	for (unsigned ipproto = 0; ipproto < elemsof(ip_protocols); ipproto++) {
		const struct ip_protocol *p = &ip_protocols[ipproto];
		passert(p->ipproto == ipproto);
		if (p->prefix != NULL &&
		    strncaseeq(prefix, p->prefix, strlen(p->prefix))) {
			return p;
		}
	}
	return NULL;
}

const struct ip_protocol *protocol_by_shunk(shunk_t token)
{
	/* try the name */
	for (unsigned ipproto = 0; ipproto < elemsof(ip_protocols); ipproto++) {
		const struct ip_protocol *p = &ip_protocols[ipproto];
		passert(p->ipproto == ipproto);
		if (hunk_strcaseeq(token, p->name) || hunk_strcaseeq(token, p->prefix)) {
			return p;
		}
	}
	/* try the number */
	uintmax_t ipproto;
	if (shunk_to_uintmax(token, NULL, 10, &ipproto, 255) == NULL) {
		return protocol_by_ipproto(ipproto);
	}
	return NULL;
}

const struct ip_protocol *protocol_by_ipproto(unsigned ipproto)
{
	if (ipproto >= elemsof(ip_protocols)) {
		return NULL;
	}
	const struct ip_protocol *p = &ip_protocols[ipproto];
	return p;
}

err_t ttoipproto(const char *proto_name, unsigned *proto)
{
       /* extract protocol by trying to resolve it by name */
       const struct protoent *protocol = getprotobyname(proto_name);
       if (protocol != NULL) {
               *proto = protocol->p_proto;
               return NULL;
       }

       /* failed, now try it by number */
       char *end;
       long l = strtol(proto_name, &end, 0);
       if (*proto_name && *end) {
               *proto = 0;
               return "<protocol> is neither a number nor a valid name";
       }

       if (l < 0 || l > 0xff) {
               *proto = 0;
               return "<protocol> must be between 0 and 255";
       }

       *proto = (uint8_t)l;
       return NULL;
}

/*
 * Abstract ENUM names to work with above table?
 */

static const char *const ip_protocol_id_name[] = {
	[0] = "ALL",
#define A(P) [IPPROTO_##P] = #P
	A(UDP),
	A(TCP),
	A(ICMP),
#undef A
};

enum_names ip_protocol_id_names = {
	0, elemsof(ip_protocol_id_name) - 1,
	ARRAY_REF(ip_protocol_id_name),
	NULL, /* prefix */
	NULL, /* next */
};

size_t jam_protocols(struct jambuf *buf, const ip_protocol *src, char sep, const ip_protocol *dst)
{
	size_t s = 0;
	/* caller adds ' ' */
	s += jam_char(buf, sep);
	s += jam_string(buf, (src == NULL ? "<null>" :
			      src->ipproto == 0 ? "<all>" :
			      src->name));
	if (src != dst) {
		s += jam_char(buf, sep);
		s += jam_string(buf, (dst == NULL ? "<null>" :
				      dst->ipproto == 0 ? "<all>" :
				      dst->name));
	}
	s += jam_char(buf, sep);
	s += jam_char(buf, '>');
	/* caller adds ' ' */
	return s;
}
