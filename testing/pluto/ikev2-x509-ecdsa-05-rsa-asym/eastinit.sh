/testing/guestbin/swan-prep --x509
/testing/x509/import.sh real/mainec/`hostname`.p12
# Tuomo: why doesn't ipsec checknss --settrust work here?
ipsec certutil -M -n "strongSwan CA - strongSwan" -t CT,,
#ipsec start
ipsec pluto --config /etc/ipsec.conf --leak-detective
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec status | grep "our auth:"
ipsec whack --impair suppress_retransmits
echo "initdone"
