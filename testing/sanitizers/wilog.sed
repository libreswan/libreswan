/^033 Can.t Opportunistically initiate for/s/RR of type TXT for \(.*\) was not found$/no host \1 for TXT record/
/^\(002 .*received Vendor ID Payload; ASCII hash: \).*/s//\1XXXXXXXXXXXX/
s/ [({]using isakmp#.*[})]//
/^\=\=\= /d
/eer ID is ID_IPV4_ADDR/d
s/ {isakmp=#.*\/ipsec=#.*}//
/Changing to directory /d
/  Warning: empty directory/d
/transition from state /d
/stats db_ops.c/d
/started helper pid=/d
/calc_dh_shared()/d
/^!/d
s/\(Vendor ID payload \[Libreswan (this version) \).*/\1 VERSION/
s/\(Vendor ID payload \[Openswan (this version) \).*/\1 VERSION/
/@(#) built on/d
s,7.2/ifn0,7.2/lo:e,
s,7.1/ifn0,7.1/lo:w,

