# note swan-prep does not yet support BSD
rm -rf /usr/local/etc/ipsec.*
mkdir -p /usr/local/etc/ipsec.d/
cp ipsec.* /usr/local/etc/
ipsec start
ipsec auto --add eastnet-westnet-ikev2
echo "initdone"
