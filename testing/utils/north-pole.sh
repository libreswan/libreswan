o4net=192[.]0[.]3[.]
n4net=198.18.66.

o4north="${o4net}254"
n4north="${n4net}254"

o6net="2001:db8:0:3::"
n6net="2001:db8:66::"

o6north="${o6net}254"
n6north="${n6net}254"

files=$(echo \
	    testing/pluto/*/*.{txt,sh,conf} \
	    testing/kvm/systemd/network/*.network \
	    testing/kvm/transmogrify/*.sh \
	    testing/kvm/bin/*.sh \
	    testing/kvm/rc.d/* \
	    testing/ns/host.sh \
	    testing/utils/nsrun \
	    testing/guestbin/*.nft)

# addresses

sed -i \
    -e "s;${o4net}\([0-2][0-9]*\);${n4net}\1;g" \
    -e "s;${o6net}\([0-2][0-9]*\);${n6net}\1;g" \
    -e "s;${o6net}/;${n6net}/;g" \
    -e "s;${o4net}\$;${n4net};g" \
    -e "s;${o6net}\$;${n6net};g" \
    ${files}

exit 0
