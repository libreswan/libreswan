/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2a
ipsec auto --add westnet-eastnet-ikev2b
# do not answer CREATE_CHILD_SA requests
###ipsec whack --impair send-no-ikev2-cc-resp

echo "initdone"
