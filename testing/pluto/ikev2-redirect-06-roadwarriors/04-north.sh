/testing/guestbin/swan-prep --x509
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add north-east
ipsec whack --impair revival
echo initdone
ipsec auto --up north-east | sed -e "s/192.0.2.10./192.0.2.10X/" # sanitize-retransmits
sleep 3
