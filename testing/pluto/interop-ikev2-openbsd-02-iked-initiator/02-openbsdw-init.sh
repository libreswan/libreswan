# note swan-prep does not yet support iked
cp openbsdw.conf /etc/iked.conf
chmod 600 /etc/iked.conf
/sbin/iked -dvvv > OUTPUT/iked.log 2>&1 & sleep 1
echo "initdone"
