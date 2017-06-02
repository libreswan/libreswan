/testing/guestbin/swan-prep
certutil -F -n 61559973d3acef7d3a370e3e82ad92c18a8225f1 -d sql:/etc/ipsec.d
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-2
echo "initdone"
