#secret sauce whack vs packet triggred.
ipsec whack --oppohere 192.1.3.209 --oppothere 192.1.2.23 --keyid 192.1.2.23 --pubkeyrsa 0sAQO9bJbr33iJs+13DaF/e+UWwsnkfZIKkJ1VQ7RiEwOFeuAme1QfygmTz/8lyQJMeMqU5T6s0fmo5bt/zCCE4CHJ8A3FRLrzSGRhWPYPYw3SZx5Zi+zzUDlx+znaEWS2Ys1f040uwVDtnG4iDDmnzmK1r4qADy5MBVyCx40pAi67I1/b8p61feIgcBpj845drEfwXCZOsdBCYFJKsHclzuCYK0P0x1kaZAGD6k7jGiqSuFWrY91LcEcp3Om0YL9DTViPZHOVcKw1ibLCnNRiwF9WX60b5d1Jk2r1I4Lt1OfV8VXyLaImpjZTL5T7mSJcR8xtgDCIljgM9fLtN9AJ1QePae+pmc5NGneeOcQ488VRUUjv
# wait on OE retransmits
sleep 2
# should show established tunnel and no bare shunts
ipsec whack --trafficstatus
ipsec whack --shuntstatus
# ping should succeed through tunnel
ping -n -c 2 -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
echo done
