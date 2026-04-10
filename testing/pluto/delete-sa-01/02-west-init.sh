/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
# left as example/test for manually calling whack
ipsec whack --label 'SAwest-east leftrsasigkey'  --keyid "@west" --pubkeyrsa "0sAQOm9dY/449sAWr8e3xtV4tJOQ1396zihfGYHkttpT6zlprRmVq8EPKX3vIo+V+SCfDI1BLkYG6cYJgQAX0mt4+VYi2H3c3e9tOPNbBQ0Bj1mfgE8f9hW7x/H8AE2OSMrDStesHaPC2MMK7WPFmxOpTT1Spzkb1ZXz5yv0obncWyK03nDSQ+d/l/LdadKe9wfXptorhhDEsJSgZxhHCFmo9SoYAG/cb8Pif6Fvoyg6nKgNsPSr/36VWOvSlNI6bcKrNdYqkhHr6D2Gk8AwpIjtM6EfKGWtEwZb3I9IOH/wSHMwVP4NiM/rMZTN2FQPNNbuhJFAYsH1lZBY8gsMpGP8kgfgQwfZqAbD8KiffTr9gVBDf5"
ipsec whack --label 'SAwest-east rightrsasigkey'  --keyid "@east" --pubkeyrsa "0sAQO9bJbr33iJs+13DaF/e+UWwsnkfZIKkJ1VQ7RiEwOFeuAme1QfygmTz/8lyQJMeMqU5T6s0fmo5bt/zCCE4CHJ8A3FRLrzSGRhWPYPYw3SZx5Zi+zzUDlx+znaEWS2Ys1f040uwVDtnG4iDDmnzmK1r4qADy5MBVyCx40pAi67I1/b8p61feIgcBpj845drEfwXCZOsdBCYFJKsHclzuCYK0P0x1kaZAGD6k7jGiqSuFWrY91LcEcp3Om0YL9DTViPZHOVcKw1ibLCnNRiwF9WX60b5d1Jk2r1I4Lt1OfV8VXyLaImpjZTL5T7mSJcR8xtgDCIljgM9fLtN9AJ1QePae+pmc5NGneeOcQ488VRUUjv"
ipsec whack --name SAwest-east --ikev1 --encrypt --tunnel --pfs --rsasig --host "192.1.2.45"  --nexthop "192.1.2.23" --updown "ipsec _updown" --id "@west" --to --host "192.1.2.23"  --nexthop "192.1.2.45" --updown "ipsec _updown" --id "@east" --ipseclifetime "28800" --no-esn
