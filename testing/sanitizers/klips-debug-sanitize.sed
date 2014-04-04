s/pid=\([0-9]*\)\./pid=987./
s/(pid=\([0-9]*\))/(pid=987)/
s/0p[A-Fa-f0-9]\{8\}/0pDEADF00D/g
s/0p0x[A-Fa-f0-9]\{8\}/0pDEADF00D/g
s/data:[0-9A-Fa-f ][0-9A-Fa-f]:.*$/data:/
/klips_debug:pfkey_destroy_socket: pfkey_skb contents:.*/d
/2: .*destructor:0p/d
/klips_debug:ipsec_sadb_cleanup: removing all SArefFreeList entries from circulation./d
/klips_debug:ipsec_sadb_init: initialising main table./d
/^012345$/d
/klips_info:ipsec_init: KLIPS startup, Libreswan IPsec version: .*/d
/klips_info:pfkey_cleanup: shutting down PF_KEY domain sockets./d
/klips_info:cleanup_module: ipsec module unloaded./d
/klips_info:ipsec_alg_init: KLIPS alg v=0.8.1-0.*/d
/klips_info:ipsec_alg_init: calling ipsec_alg_static_init.*/d
/ipsec_aes_init(alg_type=15 alg_id=12 name=aes): ret=0/d
/ipsec_aes_init(alg_type=14 alg_id=9 name=aes_mac): ret=0/d
s/ixt_e=......../ixt_e=ABCDABCD/
s/key_e=......../key_e=ABCDABCD/
s/ekp=......../ekp=ABCDABCD/
/ipsec_alg_sa_init/d
/experimental ipsec_alg_AES_MAC not registered/d
s/^\[\s\+[0-9]\+.[0-9]\+\] /\[ 00.00] /g
/ipsec: module verification failed.*$/d
