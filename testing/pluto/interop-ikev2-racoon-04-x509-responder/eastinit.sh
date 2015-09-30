/testing/guestbin/swan-prep --userland racoon
/usr/sbin/racoon2-spmd
/usr/sbin/racoon2-iked -d -d -d -l /tmp/racoon.log
sleep 3
pidof racoon2-spmd
pidof racoon2-iked
echo "initdone"
