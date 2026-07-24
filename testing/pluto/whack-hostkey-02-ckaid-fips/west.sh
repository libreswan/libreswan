/testing/guestbin/swan-prep --nokeys
/testing/guestbin/fips.sh on
ipsec newhostkey
ipsec showhostkey --list
ckaid=$(ipsec showhostkey --list | sed -e 's/.*ckaid: //')
ipsec showhostkey --left --ckaid "$ckaid"

