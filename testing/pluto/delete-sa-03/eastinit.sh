/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
../../guestbin/ipsec-add.sh west-east-c west-east-b west-east
ipsec status | sed -n -e '/west-/ { s/conn serial: [^;]*;/conn serial: .../; p; }'
echo "initdone"
