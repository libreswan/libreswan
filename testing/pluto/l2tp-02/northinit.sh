/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add north-east-l2tp
ipsec auto --add north-east-pass
ipsec auto --route north-east-pass
(cd /tmp && xl2tpd -D 2>/tmp/xl2tpd.log 1>&2) &
ipsec auto --route north-east-l2tp
echo done
