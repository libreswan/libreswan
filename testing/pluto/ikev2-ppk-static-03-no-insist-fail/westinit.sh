/testing/guestbin/swan-prep --nokeys
# confirm that newtwork is alive
../../guestbin/wait-until-alive -I 192.0.1.254 192.0.2.254
ipsec pluto --config /etc/ipsec.conf --leak-detective
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ipv4-psk-ppk
ipsec auto --status | grep westnet-eastnet-ipv4-psk-ppk
ipsec whack --impair suppress_retransmits
ipsec whack --impair revival
echo "initdone"
