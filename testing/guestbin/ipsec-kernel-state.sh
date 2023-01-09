#!/bin/sh

# Join/Split related lines using <> as the separator so that they can
# be fed to things like sort.
#
# Note: OpenBSD SED doesn't support \t or \s
#
# Note: kernel-{state,policy}.sh have identical code

join_lines()
{
    sed -n -e '
1 { h; n; }
/^[^ 	]/ { x; s,\n,<>,g; p; n; }
H
$ { x; s,\n,<>,g; p; }'
}

split_lines()
{
    sed -e 's,<>,\
,g'
}

# deal with the different systems

xfrm_state()
{
    ip xfrm state
}

ipsecctl_state()
{
    ipsecctl -k -v -v -s sa | \
	join_lines | \
	sort | \
	split_lines
}

setkey_state()
{
    setkey -D
}

case $(uname) in
    Linux)
	xfrm_state
	;;
    NetBSD|FreeBSD)
	setkey_state
	;;
    OpenBSD)
	ipsecctl_state
	;;
    *)
	echo unknown
	exit 1
	;;
esac
