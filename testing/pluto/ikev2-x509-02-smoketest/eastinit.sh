/testing/guestbin/swan-prep --x509
ipsec certutil -D -n west
ipsec start
../../guestbin/wait-until-pluto-started
# down'ed conn must remain down
ipsec whack --impair revival
ipsec auto --add san
echo "initdone"
