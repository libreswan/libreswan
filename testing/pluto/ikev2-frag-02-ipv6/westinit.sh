/testing/guestbin/swan-prep --46 --x509 --x509name key4096
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add v6-tunnel
echo "initdone"
