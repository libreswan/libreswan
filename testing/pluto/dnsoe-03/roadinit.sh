/testing/guestbin/swan-prep
cp road-ikev2-oe.conf /etc/ipsec.d/ikev2-oe.conf
cp policies/* /etc/ipsec.d/policies/
echo "192.1.2.0/24"  >> /etc/ipsec.d/policies/private-or-clear
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 6,' -- ipsec auto --status
ipsec whack --listpubkeys
# preload east's key
ipsec whack --keyid "192.1.2.23" --addkey --pubkeyrsa "0sAQO9bJbr33iJs+13DaF/e+UWwsnkfZIKkJ1VQ7RiEwOFeuAme1QfygmTz/8lyQJMeMqU5T6s0fmo5bt/zCCE4CHJ8A3FRLrzSGRhWPYPYw3SZx5Zi+zzUDlx+znaEWS2Ys1f040uwVDtnG4iDDmnzmK1r4qADy5MBVyCx40pAi67I1/b8p61feIgcBpj845drEfwXCZOsdBCYFJKsHclzuCYK0P0x1kaZAGD6k7jGiqSuFWrY91LcEcp3Om0YL9DTViPZHOVcKw1ibLCnNRiwF9WX60b5d1Jk2r1I4Lt1OfV8VXyLaImpjZTL5T7mSJcR8xtgDCIljgM9fLtN9AJ1QePae+pmc5NGneeOcQ488VRUUjv"
ipsec whack --listpubkeys
echo "initdone"
