/testing/guestbin/swan-prep --nokeys
echo "xnorth:xOzlFlqtwJIu2:east-any:192.0.2.101" > /etc/ipsec.d/passwd
echo "xroad:xOzlFlqtwJIu2:east-any:192.0.2.101-192.0.2.200" >> /etc/ipsec.d/passwd
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair timeout_on_retransmit
ipsec auto --add east-any
echo initdone
