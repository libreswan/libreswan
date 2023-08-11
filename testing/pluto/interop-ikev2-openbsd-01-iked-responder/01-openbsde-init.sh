# note swan-prep does not yet support iked
cp openbsde.conf /etc/iked.conf
chmod 600 /etc/iked.conf
/sbin/iked -dvvv > /tmp/iked.log 2>&1 & sleep 1
echo "initdone"
