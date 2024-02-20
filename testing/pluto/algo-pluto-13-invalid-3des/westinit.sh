/testing/guestbin/swan-prep
# confirm that the network is alive
../../guestbin/wait-until-alive -I 192.0.1.254 192.0.2.254
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair send_key_size_check
ipsec whack --impair suppress_retransmits
ipsec auto --add westnet-eastnet-aes256
ipsec auto --status | grep westnet-eastnet-aes256
echo "initdone"
ipsec whack --impair revival
