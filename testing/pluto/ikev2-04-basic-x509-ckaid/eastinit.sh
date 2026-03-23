# Import WEST's private key and extract its CKAID

/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/west.end.p12
WEST_CKAID=$(ipsec showhostkey --list | sed -e 's/.*ckaid: //')

# Import EAST's private key and extract its CKAID

/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/east.p12
EAST_CKAID=$(ipsec showhostkey --list | sed -e 's/.*ckaid: //')

# edit CKAIDS into ipsec.conf
echo west ckaid: $westckaid east ckaid: $eastckaid
sed -e "s/@@WEST_CKAID@@/${WEST_CKAID}/" -e "s/@@EAST_CKAID@@/${EAST_CKAID}/" ipsec.conf > OUTPUT/ipsec.conf

# configure for real

/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/east.p12
/testing/x509/import.sh real/mainca/west.end.cert
cp -v OUTPUT/ipsec.conf /etc/ipsec.conf

ipsec start
../../guestbin/wait-until-pluto-started
ipsec add westnet-eastnet-ikev2
ipsec connectionstatus westnet-eastnet-ikev2
echo "initdone"
