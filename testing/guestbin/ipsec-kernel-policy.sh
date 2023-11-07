#!/bin/sh

# Join/Split related lines using <> as the separator so that they can
# be fed to things like sort.  While at it strip out any trailing
# spaces.
#
# Note: OpenBSD's SED doesn't support \t or \s
#
# Note: kernel-{state,policy}.sh have identical code

join_lines()
{
    sed -n -e '
s/[ 	]*$//
1 { h; n; }
/^[^ 	]/ { x; s,\n,<>,g; p; n; }
s/[ 	]*$//
H
$ { x; s,\n,<>,g; p; }'
}

split_lines()
{
    sed -e 's,<>,\
,g'
}

# deal with the different systems

xfrm_policy()
{
    # Force the order by feeding sort with lines prefixed by '[46]
    # TYPE PRIORITY |'.
    #
    # XXX: should this also sort the direction?
    {
	ip xfrm policy
    } | {
	join_lines
    } | {
	# Eliminate socket lines vis:
	#
	#     src 0.0.0.0/0 dst 0.0.0.0/0
	#            socket out priority 0 ptype main
	sed -e '/socket/d'
    } | {
	# Prefix each line with:
	#
	#   <[46]> <priority> |
	#
	# so it is easy to sort.
	#
	# With each field, start with the assumption that the value is
	# unknown (setting it to the default), and then adjust it as
	# necessary.  For instance, for the protocol, start out
	# assuming it is '4' (IPv4) and then if the line contains a
	# ':' switch the prefix to '6' (IPv6).
	sed -e 's/^/| /' \
	    \
	    -e 's/^/0 /' \
	    -e 's/^0 \(.* priority \([0-9][0-9]*\)\)/\2 \1/' \
	    \
	    -e 's/^/4 /' \
	    -e 's/^4 \(.* | src [0-9a-f:/]* \)/6 \1/'
    } | {
	# sort by each of the prefixes individually, and then by the
	# rest of the line.  Shorter forms like -n and -k1,3n don't do
	# what is wanted.
	sort -b -k1,1n -k2,2n -k4V
    } | {
	# strip the sort prefixes
	sed -e 's/^.* | //'
    } | {
	if test "$#" -gt 0 ; then
	    grep "$@"
	else
	    cat
	fi
    } | {
	split_lines
    }
}

setkey_policy()
{
    setkey -DP
}

ipsecctl_policy()
{
    ipsecctl -k -v -v -s flow
}

case $(uname) in
    Linux)
	xfrm_policy "$@"
	;;
    NetBSD|FreeBSD)
	setkey_policy "$@"
	;;
    OpenBSD)
	ipsecctl_policy "$@"
	;;
    *)
	echo unknown
	exit 1
	;;
esac
