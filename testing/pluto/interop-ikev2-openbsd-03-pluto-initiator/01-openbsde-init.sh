# note swan-prep does not yet support iked
cp openbsde.conf /etc/iked.conf
chmod 600 /etc/iked.conf
rm -f /tmp/iked.log
ln -s $PWD/OUTPUT/openbsde.iked.log /tmp/iked.log
/sbin/iked -dvvv > /tmp/iked.log 2>&1 & sleep 1
echo "initdone"
