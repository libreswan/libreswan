/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
echo 192.1.2.23 east-from-hosts-file.example.com east-from-hosts-file >> /etc/hosts
ipsec auto --add westnet-eastnet
ipsec auto --status
echo "initdone"
