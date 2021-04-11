/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add west-east-ikev2
ipsec auto --status | grep west

ncat -n -v -v --keep-open --sh-exec 'echo 222; cat' --listen 222 &
sleep 1
echo 222 | ncat localhost 222

ncat -n -v -v --keep-open --sh-exec 'echo 333; cat' --listen 333 &
sleep 1
echo 333 | ncat localhost 333

echo "initdone"
