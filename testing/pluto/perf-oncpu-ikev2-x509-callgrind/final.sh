ipsec _kernel state
ipsec _kernel policy
# callgrind only dumps results after pluto is shutdown
ipsec whack --shutdown
cp -v /tmp/$(hostname).*.call* OUTPUT/
