rm -f /etc/racoon/*
# no tabs?!?
cp netbsde.racoon.conf /etc/racoon/racoon.conf
cp netbsde.psk.txt     /etc/racoon/psk.txt
chmod u=r,go=          /etc/racoon/psk.txt
racoon -l /tmp/racoon.log
echo "initdone"
