/testing/guestbin/swan-prep
gcc -fPIC -fno-stack-protector -c mypam.c
ld -x --shared -o /lib64/security/mypam.so mypam.o
test -f /etc/pam.d/pluto && mv /etc/pam.d/pluto /etc/pam.d/pluto.stock
cp pluto.pam /etc/pam.d/pluto
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add xauth-road-eastnet
echo "initdone"
