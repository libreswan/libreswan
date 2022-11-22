#!/bin/sh

# Dump the raw output from <<ip xfrm state|policy>> on stderr (putting
# it on stderr, makes it easier for calling scripts to discard it vis:
# <<ipsec-look.sh 2>/devnull|grep foo>>.  Internally, "ipsec look"
# uses that same output to produce its dump.

case $(uname) in
    Linux)
	ip xfrm state
	;;
    NetBSD|FreeBSD)
	setkey -D
	;;
    OpenBSD)
	{
	    ipsecctl -k -v -v -s sa
	} | {
	    # join related output using <>; OpenBSD SED doesn't
	    # support \t or \s
	    sed -n -e '
1 { h; n; }
/^[^ 	]/ { x; s,\n,<>,g; p; n; }
H
$ { x; s,\n,<>,g; p; }'
	} | {
	    sort
	} | {
	    # split lines on <>; OpenBSD SED doesn't allow \n in
	    # replacement
	    sed -e 's,<>,\
,g'
	}
	;;
    *) echo unknown ; exit 1 ;;
esac
