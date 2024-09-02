/testing/guestbin/swan-prep --hostkeys
gcc -fPIC -fno-stack-protector  -o OUTPUT/mypam.o -c mypam.c
ld -x --shared -o /lib64/security/mypam.so OUTPUT/mypam.o
test -f /etc/pam.d/pluto && mv /etc/pam.d/pluto /etc/pam.d/pluto.stock
cp pluto.pam /etc/pam.d/pluto
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add xauth-road-eastnet
echo "initdone"
