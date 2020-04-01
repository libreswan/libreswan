/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
# ipsec whack --impair key-length-attribute:0
ipsec auto --add east
echo "initdone"
