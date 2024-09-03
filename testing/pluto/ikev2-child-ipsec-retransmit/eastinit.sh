/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2a
ipsec auto --add westnet-eastnet-ikev2b
# do not answer CREATE_CHILD_SA requests
###ipsec whack --impair send_no_ikev2_cc_resp

echo "initdone"
