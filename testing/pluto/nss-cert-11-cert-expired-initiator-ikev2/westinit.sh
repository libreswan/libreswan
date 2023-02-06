/testing/guestbin/swan-prep --x509
/testing/guestbin/swan-prep --x509 --x509name notvalidanymore
# Set a time in the past so notvalidanymore is valid here (but not
# on the other side with normal time
# Invoke pluto directly so that it is the root of the shared
# faketime tree.
LD_PRELOAD=/usr/lib64/faketime/libfaketime.so.1 FAKETIME=-3d ipsec pluto  --config /etc/ipsec.conf
../../guestbin/wait-until-pluto-started
# if faketime works, adding conn should not give a warning about cert
ipsec auto --add ikev2-westnet-eastnet-x509-cr
ipsec whack --impair suppress-retransmits
echo "initdone"
