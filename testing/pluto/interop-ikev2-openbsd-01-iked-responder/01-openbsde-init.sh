set +o emacs
set +o vi
set +o gmacs
# note swan-prep does not yet support iked 
#/testing/guestbin/swan-prep
cp openbsde.conf /etc/iked.conf
chmod 600 /etc/iked.conf
/sbin/iked -dvvv > /tmp/iked.log 2>&1 &
echo "initdone"
