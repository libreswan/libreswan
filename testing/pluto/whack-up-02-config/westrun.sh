rm -f /etc/ipsec.conf

ipsec --config $PWD/ipsec.conf add west
ipsec --config $PWD/ipsec.conf up west # sanitize-retransmits
ipsec --config $PWD/ipsec.conf down west
ipsec --config $PWD/ipsec.conf delete west

ipsec add --config $PWD/ipsec.conf west
ipsec up --config $PWD/ipsec.conf west # sanitize-retransmits
ipsec down --config $PWD/ipsec.conf west
ipsec delete --config $PWD/ipsec.conf west
