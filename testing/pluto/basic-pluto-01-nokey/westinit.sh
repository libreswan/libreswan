/testing/guestbin/swan-prep
# we must delete key due to bug shown in basic-pluto-01-wrongkey
# NSS certutil bug? this does not work
#certutil -F -name b49f1aac9e456e7929c881973a0c6ad37f0f0350 -d sql:/etc/ipsec.d
# use sledgehammer approach
rm /etc/ipsec.d/*db
ipsec initnss
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet
echo "initdone"
