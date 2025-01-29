# Import WEST's cert and extract its CKAID
/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/west.end.p12
westckaid=$(ipsec showhostkey --list | sed -e 's/.*ckaid: //')

# Import EAST's cert and extract its CKAID
/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/east.all.p12
eastckaid=$(ipsec showhostkey --list | sed -e 's/.*ckaid: //')

/testing/x509/import.sh real/mainca/west.end.cert

echo west ckaid: $westckaid east ckaid: $eastckaid
sed -i -e "s/WESTCKAID/$westckaid/" -e "s/EASTCKAID/$eastckaid/" /etc/ipsec.conf

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec auto --status | grep westnet-eastnet-ikev2
echo "initdone"
