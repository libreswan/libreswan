/testing/guestbin/swan-prep --nokeys
ipsec pk12util -i /testing/x509/strongswan/strongEast.p12 -w /testing/x509/nss-pw
# Because we cannot run ipsec import, fixup trust bits manually
ipsec certutil -M -n "strongSwan CA - strongSwan" -t CT,,
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
echo "initdone"
