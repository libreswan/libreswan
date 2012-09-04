#!/bin/bash

# this script goes into $POOLSPACE/{plain,swan}{,26} and looks for the .config
# file that is there. It canonicalizes the file using "sort", and adds any
# missing items to uml{plain,swan}{,26}.config.
#
# Actually, it just cats the new file and the old file, turning all comments
# like '# FOO is not set' into "FOO=n" and uses sort -u on the result.
#

canonicalize_kernel_config() {
    old=$1
    new=$2
    out=`basename $old`

    rm -f $out.new
    ./canonicalize_kernel_config.pl $old $new >$out.new
}

source ../../umlsetup.sh
for type in plain swan
do
    for ver in "" 26
    do
	if [ -f $POOLSPACE/${type}${ver}/.config ]
	then
	    canonicalize_kernel_config uml${type}${ver}.config $POOLSPACE/${type}${ver}/.config 
	    mv uml${type}${ver}.config     uml${type}${ver}.config.old
	    mv uml${type}${ver}.config.new uml${type}${ver}.config
	fi
    done
done

