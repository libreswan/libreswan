/^033 Can.t Opportunistically initiate for/s/RR of type TXT for \(.*\) was not found$/no host \1 for TXT record/
/^\(002 .*received Vendor ID Payload; ASCII hash: \).*/s//\1XXXXXXXXXXXX/
s/ [({]using isakmp#.*[})]//
s/IPsec SA established {.*}/IPsec SA established/
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
