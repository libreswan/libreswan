/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add xauth_0-client_sn-sn_192.168.11.0/24-0.0.0.0/0
echo initdone
