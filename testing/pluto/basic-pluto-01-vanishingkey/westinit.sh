/testing/guestbin/swan-prep
# This test assumes we know how to delete the key from NSS properly
# We know this fails right now, going to ask upstream because doing a
# rm might cause the pluto daemon to keep the loaded nss db in place
certutil -F -name b49f1aac9e456e7929c881973a0c6ad37f0f0350 -d sql:/etc/ipsec.d
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet
echo "initdone"
