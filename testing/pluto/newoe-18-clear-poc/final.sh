ipsec whack --shuntstatus
../../guestbin/ipsec-look.sh
# should not show any hits
grep "negotiated connection" /tmp/pluto.log
