../../guestbin/prep.sh

../../guestbin/ifconfig.sh vioif1 add 192.0.20.254/24

../../guestbin/start-racoon.sh
echo "initdone"
