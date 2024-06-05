rm -f /etc/ipsec.conf

ipsec --config $PWD/ipsec.conf add west
ipsec --config $PWD/ipsec.conf up west
ipsec --config $PWD/ipsec.conf down west
ipsec --config $PWD/ipsec.conf delete west

ipsec add --config $PWD/ipsec.conf west
ipsec up --config $PWD/ipsec.conf west
ipsec down --config $PWD/ipsec.conf west
ipsec delete --config $PWD/ipsec.conf west
