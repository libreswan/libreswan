/testing/guestbin/swan-prep --x509 --x509name west
westckaid=$(ipsec showhostkey --list | sed -e 's/.*ckaid: //')
/testing/guestbin/swan-prep --x509
eastckaid=$(ipsec showhostkey --list | sed -e 's/.*ckaid: //')
echo west ckaid: $westckaid east ckaid: $eastckaid
sed -i -e "s/WESTCKAID/$westckaid/" -e "s/EASTCKAID/$eastckaid/" /etc/ipsec.conf
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec auto --status | grep westnet-eastnet-ikev2
echo "initdone"
