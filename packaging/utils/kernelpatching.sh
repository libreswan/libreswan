#!/bin/sh
# routines to help build patch files.

fakeallpatch() {
    # $1 true/false as to whether to continue
    # $2 file contents
    # $3 target name

    doit=$1
    content=$2
    target=$3

    if $doit
    then
	:
    else
	return
    fi

    set -- `wc -l $content `
    lines=$1

    echo "diff -ruN a/${target#*/} b/${target#*/}"
    echo '--- /dev/null   Tue Mar 11 13:02:56 2003'
    echo "+++ $target     Mon Feb  9 13:51:03 2004"
    echo "@@ -0,0 +1,$lines @@"
    sed -e 's/^/+/' $content
}

doversion() {
    content=$1

    target=`echo $content | sed -e 's/.in.c/.c/'`

    set -- `wc -l $content `
    lines=$1

    # get IPSECVERSION
    eval $(cd ${LIBRESWANSRCDIR} && make env | grep IPSECVERSION)

    echo "diff -ruN a/${target#*/} b/${target#*/}"
    echo '--- /dev/null   Tue Mar 11 13:02:56 2003'
    echo "+++ $target     Mon Feb  9 13:51:03 2004"
    echo "@@ -0,0 +1,$lines @@"
    sed -e 's/^/+/' -e '/"/s/@IPSECVERSION@/'${IPSECVERSION}'/' $content
}

