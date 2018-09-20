#!/bin/sh -eux

# A script to put various build sequences through their paces.

j=-j$(grep ^processor /proc/cpuinfo | wc -l)
echo make $j
sleep 1

while read target
do
    case "$target" in
	"#"* ) ;;
	* )
	    log=$(echo mk/make $target | tr '[ ]' '[_]')
	    if test ! -r $log.log
	    then
		rm -rf OBJ.*
		make $j $target | tee $log.tmp
		mv $log.tmp $log.log
	    fi
	    ;;
    esac
done <<EOF
#
# GNU's "Standard 'Makefile' Targets"
#

all
install
# install-strip
uninstall
clean
distclean
#check
#installcheck
#dist
#
# Standard combinations
#
all install clean
all install distclean
#
# Local variants
#
programs
clean-manpages manpages install-manpages clean-manpages
clean-base base install-base clean-base
install_file_list
EOF

exit 0
