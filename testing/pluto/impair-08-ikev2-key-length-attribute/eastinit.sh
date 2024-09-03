/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
# ipsec whack --impair key_length_attribute:0
ipsec auto --add east
echo "initdone"
